//! Re-fetch a user's Discord guild list and replace the cached
//! `user_guilds` rows.
//!
//! Two entry points share one core ([`replace_user_guilds`]):
//!
//! - The background [`guild_refresh_worker`](crate::tasks::guild_refresh_worker)
//!   sweeps every user once their cache is ~7 days stale.
//! - [`refresh_on_demand`] is called from a request handler when a user
//!   arrives from a per-guild verify link (`?guild=<id>`) for a server we
//!   don't have on file yet. Without it, a user who *just joined* the
//!   server keeps seeing "you're not in that server" — the cache would
//!   otherwise only update on their next login or after the 7-day sweep.
//!
//! On-demand refreshes are cooldown-gated. The gate is an atomic claim on
//! `guilds_refreshed_at`, which also closes a correctness hole: Discord
//! rotates the refresh token on every use, so two concurrent refreshes
//! would invalidate each other's rotated token. The claim guarantees only
//! one refresh runs per cooldown window.

use crate::error::AppError;
use crate::services::discord_oauth::DiscordOAuth;
use crate::AppState;

/// Outcome of an on-demand refresh attempt.
pub enum OnDemand {
    /// A live Discord refresh ran; payload is the new guild count.
    Refreshed(usize),
    /// No refresh ran — either we refreshed within the cooldown window or
    /// the user has no stored Discord refresh token.
    Skipped,
}

/// Refresh the caller's guild list right now, subject to `cooldown_secs`.
///
/// The cooldown is enforced by atomically bumping `guilds_refreshed_at`
/// and grabbing the refresh token in a single `UPDATE ... RETURNING`. If
/// no row comes back, the previous refresh was too recent (or there's no
/// token on file) and we skip — so rapid page reloads can't hammer
/// Discord, and concurrent requests can't race on the rotating token.
pub async fn refresh_on_demand(
    state: &AppState,
    discord_id: &str,
    cooldown_secs: f64,
) -> Result<OnDemand, AppError> {
    let claimed: Option<(String,)> = sqlx::query_as(
        "UPDATE discord_tokens \
         SET guilds_refreshed_at = now() \
         WHERE discord_id = $1 \
           AND guilds_refreshed_at < now() - make_interval(secs => $2) \
         RETURNING refresh_token",
    )
    .bind(discord_id)
    .bind(cooldown_secs)
    .fetch_optional(&state.pool)
    .await?;

    let refresh_token = match claimed {
        Some((rt,)) => rt,
        None => return Ok(OnDemand::Skipped),
    };

    let count = replace_user_guilds(state, discord_id, &refresh_token).await?;
    Ok(OnDemand::Refreshed(count))
}

/// Refresh a single user's guild list using their stored refresh token,
/// then atomically replace their `user_guilds` rows. Shared by the
/// background worker and the on-demand path.
///
/// On an invalid refresh token the row is removed from `discord_tokens`
/// (Discord won't let us refresh it again) and the error is propagated.
pub async fn replace_user_guilds(
    state: &AppState,
    discord_id: &str,
    refresh_token: &str,
) -> Result<usize, AppError> {
    let oauth = DiscordOAuth::with_client(state.http.clone());

    // Get new access token (Discord invalidates old refresh token, returns new one)
    let (access_token, new_refresh_token) = match oauth
        .refresh_access_token(&state.config, refresh_token)
        .await
    {
        Ok(tokens) => tokens,
        Err(e) => {
            tracing::warn!(discord_id, "Refresh token invalid, removing: {e}");
            let _ = sqlx::query("DELETE FROM discord_tokens WHERE discord_id = $1")
                .bind(discord_id)
                .execute(&state.pool)
                .await;
            return Err(e);
        }
    };

    // Store the new refresh token immediately (old one is now invalid)
    sqlx::query("UPDATE discord_tokens SET refresh_token = $1 WHERE discord_id = $2")
        .bind(&new_refresh_token)
        .bind(discord_id)
        .execute(&state.pool)
        .await?;

    // Fetch guild list and current display name
    let guilds = oauth.get_user_guilds(&access_token).await?;
    let (_id, display_name) = oauth.get_user(&access_token).await?;

    // Replace guild memberships atomically
    let mut tx = state.pool.begin().await?;

    // Snapshot the previous guild set so the optout helper can detect
    // brand-new guilds and honor the user's "auto-enable new servers"
    // preference. Done inside the same tx as the wipe/insert.
    let old_guild_ids = crate::services::optout::snapshot_guild_ids(&mut tx, discord_id).await?;

    sqlx::query("DELETE FROM user_guilds WHERE discord_id = $1")
        .bind(discord_id)
        .execute(&mut *tx)
        .await?;

    if !guilds.is_empty() {
        let guild_ids: Vec<&str> = guilds.iter().map(|(id, _, _, _)| id.as_str()).collect();
        let guild_names: Vec<&str> = guilds.iter().map(|(_, name, _, _)| name.as_str()).collect();
        let manage_flags: Vec<bool> = guilds.iter().map(|(_, _, m, _)| *m).collect();
        let icon_hashes: Vec<Option<String>> =
            guilds.iter().map(|(_, _, _, icon)| icon.clone()).collect();
        sqlx::query(
            "INSERT INTO user_guilds (discord_id, discord_username, guild_id, guild_name, manage_guild, icon_hash, updated_at) \
             SELECT $1, $2, UNNEST($3::text[]), UNNEST($4::text[]), UNNEST($5::bool[]), UNNEST($6::text[]), now()",
        )
        .bind(discord_id)
        .bind(&display_name)
        .bind(&guild_ids)
        .bind(&guild_names)
        .bind(&manage_flags)
        .bind(&icon_hashes)
        .execute(&mut *tx)
        .await?;

        crate::services::optout::apply_optouts_for_new_guilds(
            &mut tx,
            discord_id,
            &old_guild_ids,
            &guild_ids,
        )
        .await?;
    }

    sqlx::query("UPDATE discord_tokens SET guilds_refreshed_at = now() WHERE discord_id = $1")
        .bind(discord_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    tracing::debug!(discord_id, guilds = guilds.len(), "Guild list refreshed");
    Ok(guilds.len())
}
