use std::sync::Arc;

use crate::services::guild_sync;
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
                if let Err(e) =
                    guild_sync::replace_user_guilds(&state, &discord_id, &refresh_token).await
                {
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
