//! Server-to-server endpoints for plugins.
//!
//! These bypass the user-cookie auth used by `/auth/guild_permission` and
//! `/auth/guild_members` because background sync workers in plugins don't
//! have a logged-in user. Instead they authenticate via a shared secret
//! sent in the `X-Internal-Key` header (`INTERNAL_API_KEY` env var on both
//! sides).
//!
//! Mounted under `/auth/internal/*` — server-to-server only, never exposed
//! to browsers.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::HeaderMap;

use crate::error::AppError;
use crate::AppState;

const INTERNAL_KEY_HEADER: &str = "x-internal-key";

fn verify_internal_key(headers: &HeaderMap, expected: &str) -> Result<(), AppError> {
    let provided = headers
        .get(INTERNAL_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    // Constant-time-ish compare. The keys are fixed-length random strings,
    // not user-controlled, so a length-leaking compare is acceptable; we
    // still iterate over both bytes to avoid trivial early-out.
    if provided.len() != expected.len() {
        tracing::warn!("internal API call with wrong key length");
        return Err(AppError::Unauthorized);
    }
    let mut diff: u8 = 0;
    for (a, b) in provided.bytes().zip(expected.bytes()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        tracing::warn!("internal API call with bad key");
        return Err(AppError::Unauthorized);
    }
    Ok(())
}

#[derive(serde::Deserialize)]
pub struct UserGuildIdsQuery {
    pub discord_id: String,
    /// Plugin slug requesting the data. When present, guilds the user has
    /// explicitly opted out of (either for this plugin or guild-wide) are
    /// filtered out. Absent for legacy callers — they get the unfiltered
    /// list (master opt-out still applies for consistency).
    pub plugin: Option<String>,
}

/// GET /auth/internal/user_guild_ids?discord_id=...[&plugin=<slug>]
///
/// Returns the list of guild IDs the given user is a member of, according
/// to the gateway's `user_guilds` table (which is the source of truth,
/// kept fresh by the OAuth callback and the guild_refresh_worker).
///
/// When `plugin` is provided, any guild the user has opted out of — either
/// for that specific plugin or via the guild-wide master toggle — is
/// excluded. Absence of an opt-out row means opted-in, which preserves
/// the pre-existing behavior for users who have never touched their
/// preferences.
pub async fn user_guild_ids(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<UserGuildIdsQuery>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    verify_internal_key(&headers, &state.config.internal_api_key)?;

    // Anti-join against the opt-out table: the empty plugin slug stands
    // for the guild-wide master toggle, and a row keyed on the caller's
    // plugin slug is the per-plugin override. Either disables the guild.
    let plugin = query.plugin.unwrap_or_default();
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT ug.guild_id FROM user_guilds ug \
         WHERE ug.discord_id = $1 \
           AND NOT EXISTS ( \
             SELECT 1 FROM user_guild_optouts o \
             WHERE o.discord_id = ug.discord_id \
               AND o.guild_id   = ug.guild_id \
               AND o.plugin IN ('', $2) \
           )",
    )
    .bind(&query.discord_id)
    .bind(&plugin)
    .fetch_all(&state.pool)
    .await?;

    let guild_ids: Vec<String> = rows.into_iter().map(|(g,)| g).collect();

    Ok(axum::Json(serde_json::json!({
        "guild_ids": guild_ids,
    })))
}

#[derive(serde::Deserialize)]
pub struct GuildMemberIdsQuery {
    pub guild_id: String,
    /// Plugin slug requesting the data. When present, members who have
    /// opted out of this guild (either plugin-specific or guild-wide)
    /// are filtered out.
    pub plugin: Option<String>,
}

/// GET /auth/internal/guild_member_ids?guild_id=...[&plugin=<slug>]
///
/// Returns every Discord ID the gateway knows to be a member of the given
/// guild, plus the cached guild name. Used by plugin sync workers to filter
/// their local `linked_accounts` query down to "users in this guild".
///
/// When `plugin` is provided, members who have opted out of this guild
/// for the calling plugin (or guild-wide) are excluded from the returned
/// list so the plugin's atomic role replacement strips their role on the
/// next sync.
pub async fn guild_member_ids(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<GuildMemberIdsQuery>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    verify_internal_key(&headers, &state.config.internal_api_key)?;

    let plugin = query.plugin.unwrap_or_default();
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT ug.discord_id FROM user_guilds ug \
         WHERE ug.guild_id = $1 \
           AND NOT EXISTS ( \
             SELECT 1 FROM user_guild_optouts o \
             WHERE o.discord_id = ug.discord_id \
               AND o.guild_id   = ug.guild_id \
               AND o.plugin IN ('', $2) \
           )",
    )
    .bind(&query.guild_id)
    .bind(&plugin)
    .fetch_all(&state.pool)
    .await?;

    let guild_name: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT guild_name FROM user_guilds \
         WHERE guild_id = $1 AND guild_name IS NOT NULL LIMIT 1",
    )
    .bind(&query.guild_id)
    .fetch_optional(&state.pool)
    .await?;

    let discord_ids: Vec<String> = rows.into_iter().map(|(id,)| id).collect();
    let name = guild_name.and_then(|(n,)| n);

    Ok(axum::Json(serde_json::json!({
        "discord_ids": discord_ids,
        "guild_name": name,
    })))
}
