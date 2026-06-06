use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::CookieJar;
use rand::Rng;
use sqlx::PgPool;

use crate::config::AppConfig;
use crate::error::AppError;
use crate::services::discord_oauth::DiscordOAuth;
use crate::services::session;
use crate::AppState;

const SESSION_COOKIE: &str = "rl_session";

#[derive(serde::Deserialize)]
pub struct LoginQuery {
    pub return_to: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: String,
    pub error: Option<String>,
}

/// Create a fresh CSRF state row and return the Discord authorize URL.
///
/// `silent = true` requests `prompt=none` so returning users who already
/// authorized this client skip the consent screen. If Discord refuses the
/// silent attempt, `callback` retries via this same helper with
/// `silent = false`. `return_to` must already be a validated relative path.
async fn begin_oauth(
    pool: &PgPool,
    config: &AppConfig,
    return_to: &str,
    silent: bool,
) -> Result<String, AppError> {
    let state_param: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let expires = chrono::Utc::now() + chrono::Duration::minutes(10);

    sqlx::query(
        "INSERT INTO oauth_states (state, return_to, expires_at, silent) VALUES ($1, $2, $3, $4)",
    )
    .bind(&state_param)
    .bind(return_to)
    .bind(expires)
    .bind(silent)
    .execute(pool)
    .await?;

    Ok(DiscordOAuth::authorize_url(config, &state_param, silent))
}

/// GET /auth/login?return_to=/genshin-player-role/verify
pub async fn login(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LoginQuery>,
) -> Result<Response, AppError> {
    let return_to = query.return_to.unwrap_or_else(|| "/".to_string());

    // Security: only allow relative paths (prevent open redirect)
    if !return_to.starts_with('/') || return_to.starts_with("//") {
        return Err(AppError::BadRequest(
            "return_to must be a relative path".into(),
        ));
    }

    // Start silent: a returning user who already granted these scopes is
    // bounced straight back with a code and never sees the consent screen.
    // First-time users / changed scopes get the real screen via `callback`.
    let url = begin_oauth(&state.pool, &state.config, &return_to, true).await?;
    Ok(Redirect::temporary(&url).into_response())
}

/// GET /auth/callback?code=...&state=...
pub async fn callback(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<CallbackQuery>,
) -> Result<(CookieJar, Redirect), AppError> {
    // Discord came back with an error (or no code). Under `prompt=none` this
    // is the *expected* path for users who haven't consented yet (error is
    // typically `consent_required` / `login_required`), so retry once with
    // the real consent screen. A failure on the non-silent attempt is a
    // genuine denial — stop there so we can't loop.
    if query.error.is_some() || query.code.is_none() {
        let prior = sqlx::query_as::<_, (String, bool)>(
            "DELETE FROM oauth_states WHERE state = $1 RETURNING return_to, silent",
        )
        .bind(&query.state)
        .fetch_optional(&state.pool)
        .await?;

        return match prior {
            // Silent attempt refused -> fall back to the real consent screen.
            Some((return_to, true)) => {
                let url =
                    begin_oauth(&state.pool, &state.config, &return_to, false).await?;
                Ok((jar, Redirect::to(&url)))
            }
            // Consent screen itself declined -> genuine denial, no retry.
            Some((return_to, false)) => Ok((jar, Redirect::to(&return_to))),
            // Unknown / expired / forged state -> safe default.
            None => Ok((jar, Redirect::to("/"))),
        };
    }
    let code = query.code.unwrap();

    // Validate CSRF state and get return_to
    let row = sqlx::query_as::<_, (String,)>(
        "DELETE FROM oauth_states WHERE state = $1 AND expires_at > now() RETURNING return_to",
    )
    .bind(&query.state)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::BadRequest(
        "Invalid or expired OAuth state".into(),
    ))?;
    let return_to = row.0;

    // Exchange code for tokens
    let oauth = DiscordOAuth::with_client(state.http.clone());
    let (access_token, refresh_token) = oauth.exchange_code(&state.config, &code).await?;
    let (discord_id, display_name) = oauth.get_user(&access_token).await?;

    // Store refresh token for guild refresh worker
    if let Some(ref rt) = refresh_token {
        sqlx::query(
            "INSERT INTO discord_tokens (discord_id, refresh_token) VALUES ($1, $2) \
             ON CONFLICT (discord_id) DO UPDATE SET refresh_token = $2",
        )
        .bind(&discord_id)
        .bind(rt)
        .execute(&state.pool)
        .await?;
    }

    // Fetch and store guild memberships
    match oauth.get_user_guilds(&access_token).await {
        Ok(guilds) if !guilds.is_empty() => {
            let mut tx = state.pool.begin().await?;

            // Snapshot the user's previous guild set BEFORE the wipe — the
            // optout helper uses this to detect "brand new" guilds and
            // apply the per-user "auto-enable new servers" preference.
            let old_guild_ids =
                crate::services::optout::snapshot_guild_ids(&mut tx, &discord_id).await?;

            sqlx::query("DELETE FROM user_guilds WHERE discord_id = $1")
                .bind(&discord_id)
                .execute(&mut *tx)
                .await?;

            let guild_ids: Vec<&str> = guilds.iter().map(|(id, _, _, _)| id.as_str()).collect();
            let guild_names: Vec<&str> = guilds.iter().map(|(_, name, _, _)| name.as_str()).collect();
            let manage_flags: Vec<bool> = guilds.iter().map(|(_, _, m, _)| *m).collect();
            let icon_hashes: Vec<Option<String>> =
                guilds.iter().map(|(_, _, _, icon)| icon.clone()).collect();
            sqlx::query(
                "INSERT INTO user_guilds (discord_id, discord_username, guild_id, guild_name, manage_guild, icon_hash, updated_at) \
                 SELECT $1, $2, UNNEST($3::text[]), UNNEST($4::text[]), UNNEST($5::bool[]), UNNEST($6::text[]), now()",
            )
            .bind(&discord_id)
            .bind(&display_name)
            .bind(&guild_ids)
            .bind(&guild_names)
            .bind(&manage_flags)
            .bind(&icon_hashes)
            .execute(&mut *tx)
            .await?;

            crate::services::optout::apply_optouts_for_new_guilds(
                &mut tx,
                &discord_id,
                &old_guild_ids,
                &guild_ids,
            )
            .await?;

            // Login just refreshed the cache, so record that — otherwise
            // guilds_refreshed_at keeps its stale value (the token upsert
            // above doesn't touch it), which would trigger a redundant
            // on-demand refresh on the next My Servers visit and let the
            // 7-day worker re-sweep a user whose cache is actually fresh.
            sqlx::query("UPDATE discord_tokens SET guilds_refreshed_at = now() WHERE discord_id = $1")
                .bind(&discord_id)
                .execute(&mut *tx)
                .await?;

            tx.commit().await?;
            tracing::info!(discord_id, guilds = guilds.len(), "Stored guild memberships");
        }
        Ok(_) => {
            tracing::debug!(discord_id, "User has no guilds");
        }
        Err(e) => {
            tracing::warn!(discord_id, "Failed to fetch guilds: {e}");
        }
    }

    // Set session cookie. The cookie's max_age must mirror the signed payload's
    // expiry, otherwise the browser silently evicts the cookie before the HMAC
    // says it should be invalid — that's the bug that forced re-OAuth every hour.
    let session_value =
        session::sign_session(&discord_id, &display_name, &state.config.session_secret);

    let cookie = axum_extra::extract::cookie::Cookie::build((SESSION_COOKIE, session_value))
        .path("/")
        .http_only(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .max_age(time::Duration::seconds(session::SESSION_TTL_SECS));

    let jar = jar.add(cookie);

    tracing::info!(discord_id, display_name, "User authenticated");
    Ok((jar, Redirect::to(&return_to)))
}

#[derive(serde::Deserialize)]
pub struct GuildPermissionQuery {
    pub guild_id: String,
    /// Optional plugin slug. Honored by `/auth/guild_members` only —
    /// when supplied, members who opted out of this plugin (or guild-wide)
    /// are stripped from the returned list, so they disappear from the
    /// plugin's public player-list pages too. `/auth/guild_permission`
    /// ignores it because opt-outs are about role assignment, not
    /// guild membership.
    pub plugin: Option<String>,
}

/// GET /auth/guild_permission?guild_id=...
///
/// Returns whether the caller (authenticated via the shared `rl_session` cookie)
/// is a member of the given guild and whether they have the MANAGE_GUILD permission.
/// This is the single source of truth plugins should consult for guild authorization —
/// their own local `user_guilds` tables are not kept in sync with Discord.
pub async fn guild_permission(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<GuildPermissionQuery>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    // Verify the caller's session cookie
    let cookie = jar.get(SESSION_COOKIE).ok_or_else(|| {
        tracing::warn!(
            guild_id = %query.guild_id,
            "guild_permission: no rl_session cookie on incoming request"
        );
        AppError::Unauthorized
    })?;

    let cookie_value = cookie.value();
    let cookie_len = cookie_value.len();
    let cookie_fp = if cookie_len >= 12 {
        format!("{}…{}", &cookie_value[..6], &cookie_value[cookie_len - 6..])
    } else {
        "<short>".to_string()
    };

    let (discord_id, _) = session::verify_session(cookie_value, &state.config.session_secret)
        .ok_or_else(|| {
            tracing::warn!(
                guild_id = %query.guild_id,
                cookie_len,
                cookie_fp = %cookie_fp,
                cookie_value = %cookie_value,
                "guild_permission: rl_session cookie present but verify_session FAILED \
                 — signature mismatch (probably the cookie value was mutated in transit, \
                 e.g. percent-decoded — or SESSION_SECRET differs from the issuer)"
            );
            AppError::Unauthorized
        })?;

    let row: Option<(bool,)> = sqlx::query_as(
        "SELECT manage_guild FROM user_guilds WHERE discord_id = $1 AND guild_id = $2",
    )
    .bind(&discord_id)
    .bind(&query.guild_id)
    .fetch_optional(&state.pool)
    .await?;

    let (is_member, is_manager) = match row {
        Some((m,)) => (true, m),
        None => (false, false),
    };

    Ok(axum::Json(serde_json::json!({
        "is_member": is_member,
        "is_manager": is_manager,
    })))
}

/// GET /auth/guild_members?guild_id=...
///
/// Returns the list of `discord_id`s the Auth Gateway knows to be members of
/// the given guild, plus the guild's display name. The caller (authenticated
/// via the shared `rl_session` cookie) must themselves be a member of the
/// guild — this prevents arbitrary enumeration of any guild's members.
///
/// This is the single source of truth for plugins that need to display or
/// filter players by guild membership; their own local `user_guilds` tables
/// are not kept in sync with Discord.
pub async fn guild_members(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<GuildPermissionQuery>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    let cookie = jar
        .get(SESSION_COOKIE)
        .ok_or(AppError::Unauthorized)?;
    let (caller_id, _) = session::verify_session(cookie.value(), &state.config.session_secret)
        .ok_or(AppError::Unauthorized)?;

    // Caller must be a member of this guild themselves.
    let caller_is_member: Option<(String,)> = sqlx::query_as(
        "SELECT discord_id FROM user_guilds WHERE discord_id = $1 AND guild_id = $2",
    )
    .bind(&caller_id)
    .bind(&query.guild_id)
    .fetch_optional(&state.pool)
    .await?;

    if caller_is_member.is_none() {
        return Err(AppError::Unauthorized);
    }

    // Fetch all member discord_ids (with usernames) and the guild name.
    //
    // When `plugin` is supplied (player-list pages do this so opted-out
    // users disappear from public listings too), anti-join against
    // `user_guild_optouts` for that plugin or the guild-wide master row.
    let plugin = query.plugin.clone().unwrap_or_default();
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT ug.discord_id, ug.discord_username FROM user_guilds ug \
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

    let discord_ids: Vec<String> = rows.iter().map(|(id, _)| id.clone()).collect();
    let usernames: serde_json::Map<String, serde_json::Value> = rows
        .iter()
        .filter_map(|(id, name)| name.as_ref().map(|n| (id.clone(), serde_json::Value::String(n.clone()))))
        .collect();
    let name = guild_name.and_then(|(n,)| n);

    Ok(axum::Json(serde_json::json!({
        "discord_ids": discord_ids,
        "usernames": usernames,
        "guild_name": name,
    })))
}

/// GET /auth/my_guilds
///
/// Returns the list of guilds the caller (authenticated via the shared
/// `rl_session` cookie) is a member of, including each guild's display name
/// and whether the caller has MANAGE_GUILD permission. Used by plugin admin
/// pages that need to show a guild picker (e.g. game registration scoping).
pub async fn my_guilds(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    let cookie = jar.get(SESSION_COOKIE).ok_or(AppError::Unauthorized)?;
    let (discord_id, _) = session::verify_session(cookie.value(), &state.config.session_secret)
        .ok_or(AppError::Unauthorized)?;

    let rows: Vec<(String, Option<String>, bool)> = sqlx::query_as(
        "SELECT guild_id, guild_name, manage_guild FROM user_guilds \
         WHERE discord_id = $1 ORDER BY guild_name NULLS LAST, guild_id",
    )
    .bind(&discord_id)
    .fetch_all(&state.pool)
    .await?;

    let guilds: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(id, name, manage)| {
            serde_json::json!({
                "guild_id": id,
                "guild_name": name,
                "manage_guild": manage,
            })
        })
        .collect();

    Ok(axum::Json(serde_json::json!({ "guilds": guilds })))
}

/// POST /auth/logout
#[derive(serde::Deserialize)]
pub struct LogoutQuery {
    pub return_to: Option<String>,
}

/// POST /auth/logout?return_to=/some/path
///
/// Clears the `rl_session` cookie and redirects. If `return_to` is provided
/// and is a relative path (starts with `/` and not `//`), the user is sent
/// there; otherwise the redirect falls back to `/`. The relative-path check
/// prevents open-redirect abuse.
pub async fn logout(
    jar: CookieJar,
    Query(query): Query<LogoutQuery>,
) -> (CookieJar, Redirect) {
    let cookie = axum_extra::extract::cookie::Cookie::build(SESSION_COOKIE)
        .path("/")
        .http_only(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .max_age(time::Duration::ZERO);

    let target = query
        .return_to
        .filter(|s| s.starts_with('/') && !s.starts_with("//"))
        .unwrap_or_else(|| "/".to_string());

    (jar.remove(cookie), Redirect::to(&target))
}
