//! Helpers around the `user_settings` and `user_guild_optouts` tables.
//!
//! The "auto-enable new servers" preference lives in `user_settings`.
//! When a user has it set to `FALSE` and they join a brand-new guild,
//! the OAuth callback and the guild_refresh_worker both call
//! [`apply_optouts_for_new_guilds`] to immediately insert a guild-wide
//! master opt-out for those guilds — so no plugin assigns them roles
//! there until they explicitly opt in via `/auth/my_servers`.
//!
//! Both call sites are in the middle of replacing the user's
//! `user_guilds` rows wholesale (DELETE-then-INSERT under a transaction),
//! so the helper takes the snapshot of pre-existing guild IDs as input
//! and operates inside the same transaction.

use std::collections::HashSet;

use sqlx::{PgPool, Postgres, Transaction};

use crate::error::AppError;

/// Returns the user's `auto_enable_new_guilds` preference. Defaults to
/// `false` for users with no row — the conservative privacy stance:
/// don't hand out roles in a server until the user explicitly opts in.
pub async fn auto_enable_new_guilds(
    pool: &PgPool,
    discord_id: &str,
) -> Result<bool, sqlx::Error> {
    let row: Option<(bool,)> = sqlx::query_as(
        "SELECT auto_enable_new_guilds FROM user_settings WHERE discord_id = $1",
    )
    .bind(discord_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(b,)| b).unwrap_or(false))
}

/// Upsert the user's `auto_enable_new_guilds` setting.
pub async fn set_auto_enable_new_guilds(
    pool: &PgPool,
    discord_id: &str,
    enabled: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO user_settings (discord_id, auto_enable_new_guilds) \
         VALUES ($1, $2) \
         ON CONFLICT (discord_id) DO UPDATE SET \
           auto_enable_new_guilds = EXCLUDED.auto_enable_new_guilds, \
           updated_at = now()",
    )
    .bind(discord_id)
    .bind(enabled)
    .execute(pool)
    .await?;
    Ok(())
}

/// Snapshot the guild IDs currently recorded for a user. Call this
/// before the worker / OAuth callback wipes and re-inserts `user_guilds`
/// so [`apply_optouts_for_new_guilds`] can tell what's brand new.
pub async fn snapshot_guild_ids(
    tx: &mut Transaction<'_, Postgres>,
    discord_id: &str,
) -> Result<HashSet<String>, AppError> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT guild_id FROM user_guilds WHERE discord_id = $1")
            .bind(discord_id)
            .fetch_all(&mut **tx)
            .await?;
    Ok(rows.into_iter().map(|(g,)| g).collect())
}

/// For each guild in `new_guild_ids` that wasn't in `old_guild_ids`,
/// insert a guild-wide master opt-out IF the user has the
/// `auto_enable_new_guilds` setting set to `FALSE`. No-op when the
/// setting is `TRUE`. The default is `FALSE` — users who never visit
/// `/auth/my_servers` opt out of new servers automatically.
///
/// Runs inside the same transaction that re-inserts `user_guilds`, so
/// either both writes commit or both roll back — no risk of half-state.
pub async fn apply_optouts_for_new_guilds(
    tx: &mut Transaction<'_, Postgres>,
    discord_id: &str,
    old_guild_ids: &HashSet<String>,
    new_guild_ids: &[&str],
) -> Result<(), AppError> {
    let truly_new: Vec<&str> = new_guild_ids
        .iter()
        .copied()
        .filter(|g| !old_guild_ids.contains(*g))
        .collect();
    if truly_new.is_empty() {
        return Ok(());
    }

    let setting: Option<(bool,)> = sqlx::query_as(
        "SELECT auto_enable_new_guilds FROM user_settings WHERE discord_id = $1",
    )
    .bind(discord_id)
    .fetch_optional(&mut **tx)
    .await?;

    // Default FALSE: no row, or row says FALSE → insert opt-outs.
    // Only a row that explicitly says TRUE skips the opt-out step.
    if setting.map(|(b,)| b).unwrap_or(false) {
        return Ok(());
    }

    // Empty `plugin` slug is the guild-wide master toggle that overrides
    // every plugin in that guild — exactly what we want for the implicit
    // opt-out applied to newly-joined guilds.
    sqlx::query(
        "INSERT INTO user_guild_optouts (discord_id, guild_id, plugin) \
         SELECT $1, UNNEST($2::text[]), '' \
         ON CONFLICT (discord_id, guild_id, plugin) DO NOTHING",
    )
    .bind(discord_id)
    .bind(&truly_new)
    .execute(&mut **tx)
    .await?;

    tracing::info!(
        discord_id,
        new_guilds = truly_new.len(),
        "Auto-opted out of newly-joined guilds (auto_enable_new_guilds = false)",
    );

    Ok(())
}
