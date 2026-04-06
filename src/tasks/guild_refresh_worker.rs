use std::sync::Arc;

use crate::services::discord_oauth::DiscordOAuth;
use crate::AppState;

/// Configurable via DISCORD_GUILD_REFRESH_PER_HOUR env var.
/// Default 600 users/hour (1200 API calls/hour to Discord).
fn max_users_per_hour() -> u64 {
    std::env::var("DISCORD_GUILD_REFRESH_PER_HOUR")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(600)
}

/// All users get guild refresh after this many hours.
const STALE_HOURS: i32 = 168; // 7 days

pub async fn run(state: Arc<AppState>) {
    let rate = max_users_per_hour();
    let sleep_secs = if rate > 0 { 3600 / rate } else { 60 };
    tracing::info!(rate, sleep_secs, "Guild refresh worker started");

    // Initial delay to let startup settle
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    loop {
        match pick_next_user(&state).await {
            Ok(Some((discord_id, refresh_token))) => {
                if let Err(e) = refresh_user_guilds(&state, &discord_id, &refresh_token).await {
                    tracing::warn!(discord_id, "Guild refresh failed: {e}");
                }
            }
            Ok(None) => {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                continue;
            }
            Err(e) => {
                tracing::error!("Guild refresh worker DB error: {e}");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(sleep_secs)).await;
    }
}

/// Pick the next user whose guild list is stale.
async fn pick_next_user(state: &AppState) -> Result<Option<(String, String)>, sqlx::Error> {
    sqlx::query_as::<_, (String, String)>(
        "SELECT dt.discord_id, dt.refresh_token \
         FROM discord_tokens dt \
         WHERE dt.guilds_refreshed_at < now() - make_interval(hours => $1) \
         ORDER BY dt.guilds_refreshed_at ASC \
         LIMIT 1",
    )
    .bind(STALE_HOURS)
    .fetch_optional(&state.pool)
    .await
}

/// Refresh a single user's guild list using their stored refresh token.
async fn refresh_user_guilds(
    state: &AppState,
    discord_id: &str,
    refresh_token: &str,
) -> Result<(), crate::error::AppError> {
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

    // Fetch guild list
    let guilds = oauth.get_user_guilds(&access_token).await?;

    // Replace guild memberships atomically
    let mut tx = state.pool.begin().await?;
    sqlx::query("DELETE FROM user_guilds WHERE discord_id = $1")
        .bind(discord_id)
        .execute(&mut *tx)
        .await?;

    if !guilds.is_empty() {
        let guild_ids: Vec<&str> = guilds.iter().map(|(id, _)| id.as_str()).collect();
        let guild_names: Vec<&str> = guilds.iter().map(|(_, name)| name.as_str()).collect();
        sqlx::query(
            "INSERT INTO user_guilds (discord_id, guild_id, guild_name, updated_at) \
             SELECT $1, UNNEST($2::text[]), UNNEST($3::text[]), now()",
        )
        .bind(discord_id)
        .bind(&guild_ids)
        .bind(&guild_names)
        .execute(&mut *tx)
        .await?;
    }

    sqlx::query("UPDATE discord_tokens SET guilds_refreshed_at = now() WHERE discord_id = $1")
        .bind(discord_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    tracing::debug!(discord_id, guilds = guilds.len(), "Guild list refreshed");
    Ok(())
}
