use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::services::guild_sync::{self, SyncError};
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

/// A refresh Discord didn't answer usefully is tried again this much later.
/// Before, the user stayed the stalest row and was retried every few
/// seconds, holding up everyone behind them for as long as it kept failing.
const RETRY_AFTER_HOURS: i32 = 1;

/// How often guild lists the gateway can no longer verify are expired.
const EXPIRE_EVERY: Duration = Duration::from_secs(3600);

pub async fn run(state: Arc<AppState>) {
    let rate = max_users_per_hour();
    let sleep_secs = if rate > 0 { 3600 / rate } else { 60 };
    tracing::info!(rate, sleep_secs, "Guild refresh worker started");

    // Initial delay to let startup settle
    tokio::time::sleep(Duration::from_secs(10)).await;

    let mut last_expiry: Option<Instant> = None;

    loop {
        if last_expiry.is_none_or(|at| at.elapsed() >= EXPIRE_EVERY) {
            match guild_sync::expire_unverifiable(&state).await {
                Ok(0) => {}
                Ok(removed) => tracing::info!(
                    removed,
                    grace_days = guild_sync::UNVERIFIED_GRACE_DAYS,
                    "Expired guild memberships the gateway can no longer verify"
                ),
                Err(e) => tracing::error!("Failed to expire unverifiable guild memberships: {e}"),
            }
            last_expiry = Some(Instant::now());
        }

        match claim_next_user(&state).await {
            Ok(Some((discord_id, refresh_token))) => {
                match guild_sync::replace_user_guilds(&state, &discord_id, &refresh_token).await {
                    Ok(_) | Err(SyncError::Revoked) => {}
                    Err(e) => {
                        tracing::warn!(
                            discord_id,
                            "Guild refresh failed, retrying in {RETRY_AFTER_HOURS}h: {e}"
                        );
                        if let Err(db) = retry_later(&state, &discord_id).await {
                            tracing::error!(
                                discord_id,
                                "Failed to schedule guild refresh retry: {db}"
                            );
                        }
                    }
                }
            }
            Ok(None) => {
                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
            }
            Err(e) => {
                tracing::error!("Guild refresh worker DB error: {e}");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        }

        tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
    }
}

/// Claim the next user whose guild list is stale: bump their
/// `guilds_refreshed_at` and take their refresh token in one statement, the
/// same claim the on-demand path makes. Without it the worker could refresh
/// a user at the same moment as their own page load did; Discord rotates the
/// token on every use, so one of the two would read `invalid_grant` and the
/// user would be treated as having revoked access.
async fn claim_next_user(state: &AppState) -> Result<Option<(String, String)>, sqlx::Error> {
    sqlx::query_as::<_, (String, String)>(
        "UPDATE discord_tokens dt \
         SET guilds_refreshed_at = now() \
         WHERE dt.discord_id = ( \
             SELECT discord_id FROM discord_tokens \
             WHERE guilds_refreshed_at < now() - make_interval(hours => $1) \
             ORDER BY guilds_refreshed_at ASC \
             LIMIT 1 \
             FOR UPDATE SKIP LOCKED \
         ) \
         RETURNING dt.discord_id, dt.refresh_token",
    )
    .bind(STALE_HOURS)
    .fetch_optional(&state.pool)
    .await
}

/// Make a user due again in [`RETRY_AFTER_HOURS`] rather than in a week.
async fn retry_later(state: &AppState, discord_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE discord_tokens \
         SET guilds_refreshed_at = now() - make_interval(hours => $2) \
         WHERE discord_id = $1",
    )
    .bind(discord_id)
    .bind(STALE_HOURS - RETRY_AFTER_HOURS)
    .execute(&state.pool)
    .await?;
    Ok(())
}
