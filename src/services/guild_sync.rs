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
//! Both paths claim the user before refreshing: an atomic bump of
//! `guilds_refreshed_at`. Discord rotates the refresh token on every use,
//! so two concurrent refreshes would invalidate each other's rotated token,
//! and the loser would read `invalid_grant` — which now means "revoked".
//!
//! ## Membership we can no longer verify
//!
//! `user_guilds` is only as true as the last time Discord confirmed it. A
//! user whose refresh token is gone (they de-authorized the app, or signed
//! in without one) can't be re-checked, so their rows are kept for
//! [`UNVERIFIED_GRACE_DAYS`] after that last confirmation and then removed
//! by [`expire_unverifiable`]. Signing in again restores them at once.
//! Before this, those rows stayed forever: a banned member kept counting as
//! a member, and an ex-manager kept `manage_guild`.

use crate::error::AppError;
use crate::services::discord_oauth::{DiscordOAuth, RefreshError};
use crate::AppState;

/// How long a user's guild list outlives the last moment Discord confirmed
/// it, once the gateway can no longer refresh it. Two refresh cycles: long
/// enough that losing a token is not losing every role overnight, short
/// enough that nobody stays a "member" of a server they left.
pub const UNVERIFIED_GRACE_DAYS: i32 = 14;

/// Outcome of an on-demand refresh attempt.
pub enum OnDemand {
    /// A live Discord refresh ran; payload is the new guild count.
    Refreshed(usize),
    /// No refresh ran — either we refreshed within the cooldown window or
    /// the user has no stored Discord refresh token.
    Skipped,
}

/// Why a refresh did not complete.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// Discord will never refresh this user's token again. It has been
    /// forgotten; their guild list now ages out (see the module docs).
    #[error("Discord refresh token revoked")]
    Revoked,
    /// Discord did not answer usefully this time (network, rate limit,
    /// outage). The token is kept and the refresh should be retried later.
    #[error("{0}")]
    Retry(String),
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl From<AppError> for SyncError {
    fn from(e: AppError) -> Self {
        match e {
            AppError::Database(db) => SyncError::Database(db),
            other => SyncError::Retry(other.to_string()),
        }
    }
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
) -> Result<OnDemand, SyncError> {
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
/// background worker and the on-demand path; the caller has already
/// claimed the user.
///
/// - `invalid_grant` → [`SyncError::Revoked`]: the token row is deleted
///   (only if it still holds the token we used — a sign-in that raced us
///   stored a fresh one, which must survive). `user_guilds` is left as last
///   confirmed and ages out.
/// - Anything else Discord does wrong → [`SyncError::Retry`]: the token is
///   kept. Nothing is written, so a failed fetch can never empty a list.
pub async fn replace_user_guilds(
    state: &AppState,
    discord_id: &str,
    refresh_token: &str,
) -> Result<usize, SyncError> {
    let oauth = DiscordOAuth::with_client(state.http.clone());

    // Get new access token (Discord invalidates old refresh token, returns new one)
    let (access_token, new_refresh_token) = match oauth
        .refresh_access_token(&state.config, refresh_token)
        .await
    {
        Ok(tokens) => tokens,
        Err(RefreshError::Revoked(detail)) => {
            return Err(forget_token(state, discord_id, refresh_token, &detail).await?);
        }
        Err(RefreshError::Other(detail)) => return Err(SyncError::Retry(detail)),
    };

    // Store the new refresh token immediately (old one is now invalid)
    sqlx::query("UPDATE discord_tokens SET refresh_token = $1 WHERE discord_id = $2")
        .bind(&new_refresh_token)
        .bind(discord_id)
        .execute(&state.pool)
        .await?;

    // Fetch guild list and current display name
    let guilds = match oauth.get_user_guilds(&access_token).await {
        Ok(guilds) => guilds,
        // The token refreshes but Discord won't show it the user's servers:
        // it was granted without the `guilds` scope (refresh tokens were
        // consolidated from older plugin logins). Refreshing it again can
        // never work, and a user who still has a token is never expired, so
        // keeping it would freeze their list for good. Signing in again asks
        // for the scope.
        Err(AppError::Unauthorized) => {
            return Err(forget_token(
                state,
                discord_id,
                &new_refresh_token,
                "the token cannot read the user's servers (no guilds scope)",
            )
            .await?);
        }
        Err(e) => return Err(e.into()),
    };
    let (_id, display_name) = oauth.get_user(&access_token).await?;

    store_user_guilds(state, discord_id, &display_name, &guilds).await?;

    tracing::debug!(discord_id, guilds = guilds.len(), "Guild list refreshed");
    Ok(guilds.len())
}

/// Forget a refresh token that can never refresh this user's guild list,
/// but only if it is still the stored one — a sign-in that raced us stored
/// a fresh token, which must survive. The guild list stays as last
/// confirmed and ages out (see [`expire_unverifiable`]). Always answers
/// [`SyncError::Revoked`] for the caller to return.
async fn forget_token(
    state: &AppState,
    discord_id: &str,
    token: &str,
    reason: &str,
) -> Result<SyncError, sqlx::Error> {
    let forgotten =
        sqlx::query("DELETE FROM discord_tokens WHERE discord_id = $1 AND refresh_token = $2")
            .bind(discord_id)
            .bind(token)
            .execute(&state.pool)
            .await?
            .rows_affected();
    tracing::warn!(
        discord_id,
        forgotten = forgotten > 0,
        "Discord token unusable; guild list now expires in {UNVERIFIED_GRACE_DAYS} days unless they sign in again: {reason}"
    );
    Ok(SyncError::Revoked)
}

/// Replace a user's `user_guilds` rows with what Discord just confirmed —
/// including with nothing, when they are in no server — and record the
/// refresh. One transaction. Shared with the sign-in callback.
pub async fn store_user_guilds(
    state: &AppState,
    discord_id: &str,
    display_name: &str,
    guilds: &[(String, String, bool, Option<String>)],
) -> Result<(), AppError> {
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
        .bind(display_name)
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
    Ok(())
}

/// Remove guild lists the gateway can no longer verify: users with no
/// refresh token on file whose rows Discord last confirmed more than
/// [`UNVERIFIED_GRACE_DAYS`] ago. Users who still have a token are never
/// touched here, however long their refreshes keep failing — a bug or an
/// outage on our side must not empty everyone's list. Returns rows removed.
pub async fn expire_unverifiable(state: &AppState) -> Result<u64, sqlx::Error> {
    let removed = sqlx::query(
        "DELETE FROM user_guilds ug \
         WHERE ug.updated_at < now() - make_interval(days => $1) \
           AND NOT EXISTS ( \
             SELECT 1 FROM discord_tokens dt WHERE dt.discord_id = ug.discord_id \
           )",
    )
    .bind(UNVERIFIED_GRACE_DAYS)
    .execute(&state.pool)
    .await?
    .rows_affected();
    Ok(removed)
}
