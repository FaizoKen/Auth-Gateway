//! User-facing preferences: which servers should receive plugin-assigned
//! roles, optionally narrowed to a specific plugin.
//!
//! - `GET  /auth/preferences` (cookie-authed JSON) — returns the user's
//!   guilds, the plugin registry, and the current set of opt-outs so a
//!   client can render toggles.
//! - `POST /auth/preferences` (cookie-authed JSON) — flips a single
//!   (guild, plugin) toggle. `plugin: null` means the guild-wide master
//!   toggle that overrides every plugin in that guild.
//! - `GET  /auth/my_servers` (cookie-authed HTML) — the management page
//!   plugins link to from their verify screen. Reads `?from=<base_url>`
//!   so the "Back" link returns the user to the plugin they came from.
//!
//! Storage model: the table stores opt-outs only. No row = opted-in,
//! which keeps every existing production user's roles intact when this
//! ships. Toggling something off inserts a row; toggling it back on
//! deletes it.
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::plugins::{is_known_plugin, PLUGINS};
use crate::services::{guild_sync, optout, session};
use crate::AppState;

const SESSION_COOKIE: &str = "rl_session";

/// Minimum seconds between on-demand guild refreshes for a single user.
/// Short enough that "join the server, reload the page" succeeds within a
/// few seconds; long enough that a reload loop can't hammer Discord.
const ENSURE_GUILD_COOLDOWN_SECS: f64 = 5.0;

/// Minimum seconds between forced full guild re-syncs triggered by a
/// My Servers page load (`?refresh=1`). Slightly longer than the targeted
/// `ensure_guild` window because this fires on *every* visit, not just a
/// cache miss — a modest gate keeps reloads off Discord while any normal
/// page open still picks up servers the user joined or left.
const MY_SERVERS_REFRESH_COOLDOWN_SECS: f64 = 15.0;

fn caller_discord_id(jar: &CookieJar, secret: &str) -> Result<String, AppError> {
    let cookie = jar.get(SESSION_COOKIE).ok_or(AppError::Unauthorized)?;
    let (discord_id, _) = session::verify_session(cookie.value(), secret)
        .ok_or(AppError::Unauthorized)?;
    Ok(discord_id)
}

/// A Discord snowflake: 5–25 ASCII digits. Mirrors the client-side
/// `/^[0-9]{5,25}$/` guard so we never spend a Discord refresh on junk.
fn is_snowflake(s: &str) -> bool {
    (5..=25).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
}

#[derive(Deserialize)]
pub struct PreferencesQuery {
    /// Set by verify pages reached via a per-guild link (`?guild=<id>`).
    /// When this guild isn't in our cached `user_guilds` for the caller,
    /// we re-query Discord once (cooldown-gated) before answering — so a
    /// user who just joined the server is recognized immediately instead
    /// of waiting for their next login or the 7-day refresh sweep.
    pub ensure_guild: Option<String>,
    /// Set to `1` by the My Servers page on its initial load to force a
    /// cooldown-gated *full* re-sync of the caller's guild list from
    /// Discord. Unlike `ensure_guild` (which only ever *adds* a single
    /// named guild on a cache miss), this replaces `user_guilds`
    /// wholesale, so servers the user joined AND left since their last
    /// login are both reflected. Presence of the param is what matters.
    pub refresh: Option<String>,
}

/// GET /auth/preferences
///
/// Returns the user's guilds plus every opt-out row so the client can
/// build the toggle UI in one round-trip.
pub async fn get_preferences(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(q): Query<PreferencesQuery>,
) -> Result<Json<Value>, AppError> {
    let discord_id = caller_discord_id(&jar, &state.config.session_secret)?;

    // My Servers page load (`?refresh=1`): force a cooldown-gated FULL
    // re-sync. The cached guild list otherwise only updates on login or
    // via the 7-day worker, so the page would show a stale list — servers
    // joined since last login missing, servers left still present.
    // refresh_on_demand replaces user_guilds wholesale, so a single call
    // surfaces additions AND removals. The cooldown keeps reload storms
    // off Discord; a best-effort failure just answers from cache.
    if q.refresh.is_some() {
        match guild_sync::refresh_on_demand(&state, &discord_id, MY_SERVERS_REFRESH_COOLDOWN_SECS)
            .await
        {
            Ok(guild_sync::OnDemand::Refreshed(n)) => {
                tracing::info!(discord_id, guilds = n, "my_servers full guild refresh");
            }
            Ok(guild_sync::OnDemand::Skipped) => {}
            Err(e) => {
                tracing::warn!(discord_id, "my_servers guild refresh failed: {e}");
            }
        }
    }
    // On-demand guild refresh. The cached guild list only updates on login
    // or via the 7-day worker, so a freshly-joined server is invisible
    // until then. When a verify page asks about a specific guild we don't
    // have on file, re-query Discord once before building the response.
    // (Skipped when `refresh=1` already did a full re-sync above.)
    else if let Some(gid) = q.ensure_guild.as_deref().filter(|g| is_snowflake(g)) {
        let known: Option<(String,)> = sqlx::query_as(
            "SELECT guild_id FROM user_guilds WHERE discord_id = $1 AND guild_id = $2",
        )
        .bind(&discord_id)
        .bind(gid)
        .fetch_optional(&state.pool)
        .await?;

        if known.is_none() {
            // Best-effort: if Discord is down or the token's gone, fall
            // through and answer with the cache we have.
            match guild_sync::refresh_on_demand(&state, &discord_id, ENSURE_GUILD_COOLDOWN_SECS)
                .await
            {
                Ok(guild_sync::OnDemand::Refreshed(n)) => {
                    tracing::info!(discord_id, guild_id = gid, guilds = n, "ensure_guild refreshed");
                }
                Ok(guild_sync::OnDemand::Skipped) => {}
                Err(e) => {
                    tracing::warn!(discord_id, guild_id = gid, "ensure_guild refresh failed: {e}");
                }
            }
        }
    }

    let guild_rows: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT guild_id, guild_name, icon_hash FROM user_guilds \
         WHERE discord_id = $1 \
         ORDER BY guild_name NULLS LAST, guild_id",
    )
    .bind(&discord_id)
    .fetch_all(&state.pool)
    .await?;

    let optout_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT guild_id, plugin FROM user_guild_optouts WHERE discord_id = $1",
    )
    .bind(&discord_id)
    .fetch_all(&state.pool)
    .await?;

    // Group opt-outs by guild_id so the client gets a tidy structure.
    let mut by_guild: std::collections::HashMap<String, (bool, Vec<String>)> =
        std::collections::HashMap::new();
    for (guild_id, plugin) in optout_rows {
        let entry = by_guild.entry(guild_id).or_insert((false, Vec::new()));
        if plugin.is_empty() {
            entry.0 = true;
        } else {
            entry.1.push(plugin);
        }
    }

    let guilds: Vec<Value> = guild_rows
        .into_iter()
        .map(|(gid, name, icon_hash)| {
            let (master_optout, plugin_optouts) = by_guild
                .remove(&gid)
                .unwrap_or((false, Vec::new()));
            json!({
                "guild_id": gid,
                "guild_name": name,
                "icon_hash": icon_hash,
                "master_optout": master_optout,
                "plugin_optouts": plugin_optouts,
            })
        })
        .collect();

    let plugin_list: Vec<Value> = PLUGINS
        .iter()
        .map(|p| json!({ "slug": p.slug, "display_name": p.display_name }))
        .collect();

    let auto_enable = optout::auto_enable_new_guilds(&state.pool, &discord_id)
        .await
        .map_err(AppError::Database)?;

    Ok(Json(json!({
        "discord_id": discord_id,
        "guilds": guilds,
        "plugins": plugin_list,
        "auto_enable_new_guilds": auto_enable,
    })))
}

#[derive(Deserialize)]
pub struct UpdatePreferenceBody {
    pub guild_id: String,
    /// `None` = master guild toggle (applies to every plugin in that guild).
    /// `Some(slug)` = per-plugin override; must match a registered plugin.
    pub plugin: Option<String>,
    /// `true` = opt in (delete row), `false` = opt out (upsert row).
    pub enabled: bool,
}

/// POST /auth/preferences
///
/// Flips a single (guild, plugin) preference. Validation:
/// - The user must own a `user_guilds` row for `guild_id` (so they can't
///   create opt-outs for guilds they aren't in).
/// - `plugin`, when present, must be a known plugin slug.
pub async fn update_preference(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(body): Json<UpdatePreferenceBody>,
) -> Result<Json<Value>, AppError> {
    let discord_id = caller_discord_id(&jar, &state.config.session_secret)?;

    let plugin_slug = match body.plugin.as_deref() {
        Some(s) => {
            if !is_known_plugin(s) {
                return Err(AppError::BadRequest(format!("Unknown plugin: {s}")));
            }
            s.to_string()
        }
        None => String::new(),
    };

    // Confirm the user is actually a member of this guild — without this
    // check, a logged-in user could pollute the opt-out table for guilds
    // they have no business in.
    let member: Option<(String,)> = sqlx::query_as(
        "SELECT guild_id FROM user_guilds WHERE discord_id = $1 AND guild_id = $2",
    )
    .bind(&discord_id)
    .bind(&body.guild_id)
    .fetch_optional(&state.pool)
    .await?;
    if member.is_none() {
        return Err(AppError::BadRequest(
            "You are not a member of that server".into(),
        ));
    }

    if body.enabled {
        sqlx::query(
            "DELETE FROM user_guild_optouts \
             WHERE discord_id = $1 AND guild_id = $2 AND plugin = $3",
        )
        .bind(&discord_id)
        .bind(&body.guild_id)
        .bind(&plugin_slug)
        .execute(&state.pool)
        .await?;
    } else {
        sqlx::query(
            "INSERT INTO user_guild_optouts (discord_id, guild_id, plugin) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (discord_id, guild_id, plugin) \
             DO UPDATE SET updated_at = now()",
        )
        .bind(&discord_id)
        .bind(&body.guild_id)
        .bind(&plugin_slug)
        .execute(&state.pool)
        .await?;
    }

    tracing::info!(
        discord_id,
        guild_id = %body.guild_id,
        plugin = %plugin_slug,
        enabled = body.enabled,
        "preference updated",
    );

    Ok(Json(json!({ "success": true })))
}

#[derive(Deserialize)]
pub struct BulkUpdateBody {
    /// `true` = enable RoleLogic in every guild the user is in
    /// (deletes all master opt-out rows). `false` = pause RoleLogic in
    /// every guild (inserts a master opt-out for each). Per-plugin
    /// override rows are left untouched in both cases.
    pub enabled: bool,
}

/// POST /auth/preferences/bulk
///
/// One-shot replacement for looping POST /auth/preferences across every
/// guild the user owns. With 50+ guilds the per-request roundtrip cost
/// makes the UI feel stuck; doing it in a single transaction server-side
/// is both faster and atomic.
pub async fn bulk_update_preference(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(body): Json<BulkUpdateBody>,
) -> Result<Json<Value>, AppError> {
    let discord_id = caller_discord_id(&jar, &state.config.session_secret)?;

    let affected: i64 = if body.enabled {
        // Wipe master opt-outs only (plugin = ''). Per-plugin overrides
        // become effective again automatically.
        let res = sqlx::query(
            "DELETE FROM user_guild_optouts \
             WHERE discord_id = $1 AND plugin = ''",
        )
        .bind(&discord_id)
        .execute(&state.pool)
        .await?;
        res.rows_affected() as i64
    } else {
        // Insert a master opt-out for every guild the user is currently
        // in. Idempotent via ON CONFLICT so repeat clicks don't churn.
        let res = sqlx::query(
            "INSERT INTO user_guild_optouts (discord_id, guild_id, plugin) \
             SELECT $1, guild_id, '' FROM user_guilds WHERE discord_id = $1 \
             ON CONFLICT (discord_id, guild_id, plugin) \
             DO UPDATE SET updated_at = now()",
        )
        .bind(&discord_id)
        .execute(&state.pool)
        .await?;
        res.rows_affected() as i64
    };

    tracing::info!(
        discord_id,
        enabled = body.enabled,
        affected,
        "bulk preference updated",
    );

    Ok(Json(json!({ "success": true, "affected": affected })))
}

#[derive(Deserialize)]
pub struct AutoEnableBody {
    pub enabled: bool,
}

/// POST /auth/preferences/auto_enable
///
/// Sets the per-user "auto-enable new servers I join" preference. When
/// `false`, the OAuth callback and refresh worker insert a guild-wide
/// opt-out for any brand-new guild the user joins from that point on.
/// Existing guilds (and their per-plugin overrides) aren't touched.
pub async fn update_auto_enable(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(body): Json<AutoEnableBody>,
) -> Result<Json<Value>, AppError> {
    let discord_id = caller_discord_id(&jar, &state.config.session_secret)?;
    optout::set_auto_enable_new_guilds(&state.pool, &discord_id, body.enabled)
        .await
        .map_err(AppError::Database)?;
    tracing::info!(discord_id, enabled = body.enabled, "auto_enable_new_guilds updated");
    Ok(Json(json!({ "success": true })))
}

#[derive(Deserialize)]
pub struct MyServersQuery {
    /// Optional plugin slug the user came from. Drives a "Back to <plugin>"
    /// link so the page feels like part of the originating plugin's flow.
    pub from: Option<String>,
}

/// GET /auth/my_servers
///
/// The single management page every plugin links to. Self-contained HTML
/// + JS — calls `/auth/preferences` for state and POSTs the same path to
/// flip toggles. Cookie-authed; an unauthenticated visit redirects to
/// login and bounces back here.
pub async fn my_servers_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(q): Query<MyServersQuery>,
) -> Result<Response, AppError> {
    // If the visitor has no valid session, bounce them through OAuth and
    // return them right here when they're back.
    if caller_discord_id(&jar, &state.config.session_secret).is_err() {
        let return_to = match q.from.as_deref() {
            Some(from) if !from.is_empty() => {
                format!("/auth/my_servers?from={}", urlencoding::encode(from))
            }
            _ => "/auth/my_servers".to_string(),
        };
        let url = format!("/auth/login?return_to={}", urlencoding::encode(&return_to));
        return Ok(axum::response::Redirect::to(&url).into_response());
    }

    // The "Back" link target — a relative path so we can't be tricked
    // into open-redirecting. Falls back to "/" when no `from` is given
    // or it's not a relative path.
    let back_href = q
        .from
        .as_deref()
        .filter(|s| s.starts_with('/') && !s.starts_with("//"))
        .unwrap_or("/")
        .to_string();

    let html = render_my_servers_html(&back_href);
    Ok(([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response())
}

fn render_my_servers_html(back_href: &str) -> String {
    // Page is intentionally self-contained — no external assets, no
    // template engine. Pre-rendered once per request because the only
    // thing that varies is the back-link `href`.
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>My Servers · RoleLogic</title>
    <link rel="icon" href="/auth/favicon.ico" type="image/x-icon">
    <meta name="theme-color" content="#5865f2">
    <meta name="description" content="Control which Discord servers receive RoleLogic plugin roles for your account.">
    <style>
        :root {{ color-scheme: dark; }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        html {{ -webkit-text-size-adjust: 100%; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #0e1525; color: #c8ccd4; min-height: 100vh;
            padding: 0 16px 80px;
            -webkit-font-smoothing: antialiased;
        }}
        .wrap {{ max-width: 760px; margin: 0 auto; padding-top: 18px; }}
        a {{ color: #74b9ff; }}

        /* Topbar — sticks while scrolling so back is always reachable */
        .topbar {{
            position: sticky; top: 0; z-index: 20;
            background: linear-gradient(#0e1525, #0e1525 70%, transparent);
            display: flex; align-items: center; justify-content: space-between;
            gap: 12px; padding: 6px 0 12px;
        }}
        .back {{
            font-size: 13px; color: #94a3b8; text-decoration: none;
            padding: 8px 14px; border: 1px solid #1e293b; border-radius: 8px;
            display: inline-flex; align-items: center; gap: 6px;
            transition: background .12s, color .12s, border-color .12s;
            background: #0e1525;
        }}
        .back:hover, .back:focus-visible {{
            background: #1e2a3d; color: #e2e8f0; border-color: #334155; outline: none;
        }}
        .menu {{ position: relative; }}
        .menu-btn {{
            background: #0e1525; color: #94a3b8;
            border: 1px solid #1e293b; border-radius: 8px;
            padding: 6px 10px; min-width: 38px; min-height: 36px;
            font-size: 18px; line-height: 1; cursor: pointer;
            font-family: inherit;
        }}
        .menu-btn:hover, .menu-btn:focus-visible {{
            background: #1e2a3d; color: #e2e8f0; border-color: #334155; outline: none;
        }}
        .menu-list {{
            position: absolute; right: 0; top: calc(100% + 4px);
            background: #161d2e; border: 1px solid #1e2a3d; border-radius: 10px;
            min-width: 220px; padding: 6px; z-index: 30;
            box-shadow: 0 14px 32px rgba(0,0,0,.5);
            display: none;
        }}
        .menu-list.open {{ display: block; }}
        .menu-item {{
            display: block; width: 100%; text-align: left;
            background: transparent; color: #cbd5e1; border: 0;
            padding: 10px 12px; border-radius: 6px;
            font: inherit; font-size: 13.5px; cursor: pointer;
        }}
        .menu-item:hover, .menu-item:focus-visible {{
            background: #1e2a3d; color: #fff; outline: none;
        }}
        .menu-item.danger {{ color: #fca5a5; }}
        .menu-item.danger:hover {{ background: #2a0f0f; color: #fecaca; }}

        /* Header */
        h1 {{ color: #fff; font-size: 24px; font-weight: 600; margin: 4px 0 4px; letter-spacing: -.01em; }}
        .subtitle {{ color: #7a8299; font-size: 14px; margin-bottom: 16px; line-height: 1.5; }}

        /* Dismissible help banner */
        .help {{
            background: linear-gradient(135deg, #111827, #0f1c30);
            border: 1px solid #1e3a5f;
            padding: 12px 14px; border-radius: 10px; margin-bottom: 14px;
            display: flex; gap: 12px; align-items: flex-start;
            font-size: 13px; color: #cbd5e1; line-height: 1.55;
        }}
        .help.hidden {{ display: none; }}
        .help-icon {{ font-size: 16px; flex-shrink: 0; margin-top: 1px; }}
        .help-body {{ flex: 1; min-width: 0; }}
        .help strong {{ color: #e2e8f0; }}
        .help-close {{
            background: transparent; color: #64748b; border: 0;
            cursor: pointer; padding: 0 6px; font-size: 20px; line-height: 1;
            font-family: inherit; align-self: flex-start;
        }}
        .help-close:hover, .help-close:focus-visible {{ color: #cbd5e1; outline: none; }}

        /* Single setting card (auto-enable) */
        .setting-card {{
            background: #161d2e; padding: 13px 16px;
            border-radius: 10px; border: 1px solid #1e2a3d;
            margin-bottom: 14px;
        }}
        .setting-card.hidden {{ display: none; }}
        .setting-card .row {{ display: flex; align-items: center; justify-content: space-between; gap: 14px; }}
        .setting-card .label {{ color: #fff; font-size: 14px; font-weight: 500; }}
        .setting-card .desc {{ color: #7a8299; font-size: 12.5px; margin-top: 3px; line-height: 1.5; max-width: 480px; }}

        /* Search + stats toolbar */
        .toolbar {{
            display: flex; gap: 10px; align-items: center;
            flex-wrap: wrap; margin: 18px 0 8px;
        }}
        .toolbar.hidden {{ display: none; }}
        .search {{
            flex: 1; min-width: 220px;
            display: flex; align-items: center; gap: 8px;
            background: #161d2e; border: 1px solid #1e2a3d; border-radius: 10px;
            padding: 8px 12px;
            transition: border-color .12s;
        }}
        .search:focus-within {{ border-color: #3b82f6; }}
        .search svg {{ color: #64748b; flex-shrink: 0; }}
        .search input {{
            flex: 1; background: transparent; border: 0; outline: 0;
            color: #e2e8f0; font: inherit; font-size: 14px;
            min-width: 0; padding: 0;
        }}
        .search input::placeholder {{ color: #64748b; }}
        .clear-search {{
            background: transparent; color: #64748b; border: 0;
            cursor: pointer; padding: 0 4px; font-size: 18px; line-height: 1;
            font-family: inherit; display: none;
        }}
        .clear-search.show {{ display: inline; }}
        .clear-search:hover {{ color: #cbd5e1; }}

        .stats {{
            font-size: 12.5px; color: #7a8299;
            display: inline-flex; gap: 10px; flex-wrap: wrap; align-items: center;
        }}
        .stats .seg {{ display: inline-flex; align-items: center; gap: 5px; }}
        .stats .seg::before {{ content: ""; width: 7px; height: 7px; border-radius: 50%; display: inline-block; }}
        .stats .on::before {{ background: #22c55e; }}
        .stats .custom::before {{ background: #facc15; }}
        .stats .off::before {{ background: #f87171; }}
        .stats b {{ color: #e2e8f0; font-weight: 600; }}

        /* Server cards */
        .cards {{ margin-top: 4px; }}
        .card {{
            background: #161d2e; padding: 13px 14px;
            border-radius: 12px; margin: 8px 0;
            border: 1px solid #1e2a3d;
            transition: border-color .12s, opacity .12s, background .12s;
        }}
        .card.off {{ background: #181423; border-color: #2a2030; }}
        .card.custom {{ border-color: #3b3208; }}
        .card.hidden-by-search {{ display: none; }}
        .card .row {{
            display: flex; align-items: center; gap: 12px;
        }}
        .avatar {{
            width: 42px; height: 42px; border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            font-weight: 600; font-size: 16px; color: #fff;
            flex-shrink: 0;
            letter-spacing: -.02em;
            user-select: none;
            overflow: hidden;
        }}
        .avatar img {{
            width: 100%; height: 100%; object-fit: cover;
            display: block;
        }}
        .body {{ flex: 1; min-width: 0; }}
        .gname {{
            color: #fff; font-size: 15px; font-weight: 500;
            overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
            line-height: 1.3;
        }}
        .gname mark {{ background: rgba(59,130,246,.3); color: #dbeafe; padding: 0 1px; border-radius: 2px; }}
        .badges {{ display: flex; gap: 6px; align-items: center; margin-top: 4px; flex-wrap: wrap; min-height: 18px; }}
        .badge {{
            display: inline-flex; align-items: center;
            font-size: 10.5px; padding: 2px 7px; border-radius: 999px;
            font-weight: 600; letter-spacing: .02em;
            text-transform: uppercase;
        }}
        .badge.on {{ background: rgba(34,197,94,.12); color: #4ade80; }}
        .badge.off {{ background: rgba(248,113,113,.12); color: #f87171; }}
        .badge.custom {{ background: rgba(250,204,21,.12); color: #facc15; }}

        /* Switch */
        .switch {{ position: relative; display: inline-block; width: 44px; height: 26px; flex-shrink: 0; }}
        .switch input {{ opacity: 0; width: 0; height: 0; }}
        .slider {{
            position: absolute; cursor: pointer; inset: 0;
            background: #334155; border-radius: 26px; transition: background .2s;
        }}
        .slider:before {{
            position: absolute; content: ""; height: 20px; width: 20px;
            left: 3px; top: 3px; background: #fff; border-radius: 50%;
            transition: transform .2s;
            box-shadow: 0 1px 3px rgba(0,0,0,.3);
        }}
        input:checked + .slider {{ background: #22c55e; }}
        input:checked + .slider:before {{ transform: translateX(18px); }}
        input:disabled + .slider {{ opacity: .5; cursor: wait; }}
        input:focus-visible + .slider {{
            box-shadow: 0 0 0 3px rgba(59, 130, 246, .35);
        }}

        /* Per-plugin disclosure */
        .expand {{
            background: transparent; color: #94a3b8;
            border: 1px solid #1e293b; padding: 6px 10px;
            border-radius: 7px; font-size: 12px;
            cursor: pointer; font-family: inherit;
            margin-top: 10px;
            display: inline-flex; align-items: center; gap: 6px;
        }}
        .expand:hover, .expand:focus-visible {{
            color: #e2e8f0; border-color: #334155;
            background: #1e2a3d; outline: none;
        }}
        .expand .chev {{ transition: transform .15s; display: inline-block; }}
        .expand.open .chev {{ transform: rotate(180deg); }}
        .expand .count {{
            background: #422006; color: #facc15;
            font-size: 10px; padding: 1px 7px; border-radius: 999px;
            font-weight: 600;
        }}
        .plugins {{
            margin-top: 12px; padding-top: 12px;
            border-top: 1px solid #1e293b;
            display: none;
        }}
        .plugins.open {{ display: block; }}
        .plugin-row {{
            display: flex; align-items: center; justify-content: space-between;
            padding: 7px 6px; font-size: 13.5px; border-radius: 6px;
            gap: 10px;
        }}
        .plugin-row:hover {{ background: #0e1525; }}
        .plugin-row.hidden {{ display: none; }}
        .plugin-row .name {{ color: #cbd5e1; }}
        .off-msg {{
            margin-top: 10px; padding: 10px 12px;
            background: #1c0e0e; border: 1px solid #3a1a1a;
            border-radius: 8px; color: #fca5a5;
            font-size: 12.5px; line-height: 1.5;
        }}

        /* Toast */
        .toast {{
            position: fixed; bottom: 22px; left: 50%; transform: translateX(-50%) translateY(8px);
            background: #052e16; color: #86efac;
            padding: 10px 18px; border: 1px solid #14532d;
            border-radius: 10px; font-size: 13px;
            opacity: 0; transition: opacity .18s, transform .18s;
            pointer-events: none; z-index: 50;
            box-shadow: 0 12px 28px rgba(0,0,0,.5);
            max-width: calc(100vw - 32px);
            text-align: center;
        }}
        .toast.show {{ opacity: 1; transform: translateX(-50%) translateY(0); }}
        .toast.error {{ background: #1c0a0a; color: #fca5a5; border-color: #7f1d1d; }}
        .toast.busy {{ background: #0f172a; color: #cbd5e1; border-color: #1e3a5f; display: inline-flex; align-items: center; gap: 10px; }}
        .toast .spinner {{
            display: inline-block; width: 14px; height: 14px;
            border: 2px solid #475569; border-top-color: #cbd5e1;
            border-radius: 50%; animation: spin .8s linear infinite;
            flex-shrink: 0;
        }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}

        /* Skeleton loader */
        .skel-card {{
            background: #161d2e; padding: 13px 14px;
            border-radius: 12px; margin: 8px 0;
            border: 1px solid #1e2a3d;
            display: flex; align-items: center; gap: 12px;
        }}
        .skel {{
            background: linear-gradient(90deg, #1e2a3d 0%, #2a3b56 50%, #1e2a3d 100%);
            background-size: 200% 100%;
            animation: shimmer 1.4s infinite;
            border-radius: 6px;
        }}
        .skel-avatar {{ width: 42px; height: 42px; border-radius: 50%; flex-shrink: 0; }}
        .skel-body {{ flex: 1; }}
        .skel-line {{ height: 12px; margin-bottom: 7px; max-width: 60%; }}
        .skel-line.short {{ width: 30%; height: 10px; margin-bottom: 0; }}
        .skel-switch {{ width: 44px; height: 26px; border-radius: 26px; flex-shrink: 0; }}
        @keyframes shimmer {{ 0% {{ background-position: 100% 0; }} 100% {{ background-position: -100% 0; }} }}

        /* Empty / no-match states */
        .empty {{
            background: #161d2e; padding: 36px 24px;
            border-radius: 12px; border: 1px dashed #2a3b56;
            text-align: center;
        }}
        .empty .emoji {{ font-size: 36px; margin-bottom: 10px; display: block; }}
        .empty .title {{ color: #e2e8f0; font-size: 15px; font-weight: 500; margin-bottom: 6px; }}
        .empty p {{ font-size: 13px; line-height: 1.55; color: #94a3b8; max-width: 380px; margin: 0 auto; }}
        .empty button {{
            margin-top: 12px; background: #1e2a3d; color: #e2e8f0; border: 1px solid #334155;
            padding: 8px 16px; border-radius: 7px; font: inherit; font-size: 13px; cursor: pointer;
        }}
        .empty button:hover {{ background: #2a3b56; }}

        /* Confirm dialog */
        .scrim {{
            position: fixed; inset: 0; background: rgba(0,0,0,.65);
            display: none; align-items: center; justify-content: center;
            z-index: 100; padding: 16px;
            animation: fadein .15s;
        }}
        .scrim.show {{ display: flex; }}
        .dialog {{
            background: #161d2e; border: 1px solid #1e2a3d; border-radius: 12px;
            padding: 20px; max-width: 400px; width: 100%;
            box-shadow: 0 20px 50px rgba(0,0,0,.6);
        }}
        .dialog h3 {{ color: #fff; font-size: 16px; font-weight: 600; margin-bottom: 8px; }}
        .dialog p {{ color: #94a3b8; font-size: 13.5px; line-height: 1.55; margin-bottom: 16px; }}
        .dialog .actions {{ display: flex; gap: 8px; justify-content: flex-end; }}
        .dialog button {{
            padding: 8px 16px; border-radius: 8px; font: inherit;
            font-size: 13px; font-weight: 500; cursor: pointer; border: 0;
        }}
        .dialog .cancel {{ background: transparent; color: #94a3b8; border: 1px solid #334155; }}
        .dialog .cancel:hover {{ background: #1e2a3d; color: #e2e8f0; }}
        .dialog .confirm {{ background: #22c55e; color: #022c0e; }}
        .dialog .confirm:hover {{ background: #16a34a; }}
        .dialog .confirm.danger {{ background: #ef4444; color: #fff; }}
        .dialog .confirm.danger:hover {{ background: #dc2626; }}
        @keyframes fadein {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}

        /* Reduce motion */
        @media (prefers-reduced-motion: reduce) {{
            *, *::before, *::after {{ animation: none !important; transition: none !important; }}
        }}

        /* Mobile */
        @media (max-width: 480px) {{
            body {{ padding: 0 12px 80px; }}
            h1 {{ font-size: 20px; }}
            .card {{ padding: 12px 12px; }}
            .gname {{ font-size: 14px; }}
            .avatar {{ width: 38px; height: 38px; font-size: 14px; }}
            .stats {{ font-size: 12px; }}
        }}
    </style>
</head>
<body>
    <div class="wrap">
        <div class="topbar">
            <a class="back" href="{back_href}">
                <span aria-hidden="true">←</span>
                <span>Back</span>
            </a>
            <div class="menu">
                <button class="menu-btn" id="menu-btn" aria-label="More actions" aria-haspopup="true" aria-expanded="false">⋯</button>
                <div class="menu-list" id="menu-list" role="menu">
                    <button class="menu-item" data-action="enable-all" role="menuitem">Enable all servers</button>
                    <button class="menu-item danger" data-action="disable-all" role="menuitem">Disable all servers</button>
                </div>
            </div>
        </div>

        <h1>My Servers</h1>
        <p class="subtitle">Pick which Discord servers RoleLogic plugins can give you roles in.</p>

        <div class="help" id="help">
            <span class="help-icon" aria-hidden="true">💡</span>
            <div class="help-body">
                Each switch controls roles from <strong>every RoleLogic plugin</strong> in that server. Need finer control? Tap <strong>Customize per plugin</strong> on a server to keep some plugins on and others off. Changes apply within a few minutes — no need to re-verify.
            </div>
            <button class="help-close" id="help-close" aria-label="Dismiss help">×</button>
        </div>

        <div class="setting-card hidden" id="auto-enable-card">
            <div class="row">
                <div>
                    <div class="label">Auto-enable new servers</div>
                    <div class="desc">When you join a brand-new Discord server, automatically receive plugin roles there. Turn this off to opt in manually.</div>
                </div>
                <label class="switch">
                    <input type="checkbox" id="auto-enable-toggle" aria-label="Auto-enable new servers">
                    <span class="slider"></span>
                </label>
            </div>
        </div>

        <div class="toolbar hidden" id="toolbar">
            <div class="search">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7"></circle><path d="m20 20-3-3"></path></svg>
                <input id="search-input" type="search" placeholder="Search servers…" autocomplete="off" aria-label="Search servers">
                <button class="clear-search" id="clear-search" aria-label="Clear search">×</button>
            </div>
            <div class="stats" id="stats"></div>
        </div>

        <div id="content" aria-live="polite">
            <div class="skel-card"><div class="skel skel-avatar"></div><div class="skel-body"><div class="skel skel-line"></div><div class="skel skel-line short"></div></div><div class="skel skel-switch"></div></div>
            <div class="skel-card"><div class="skel skel-avatar"></div><div class="skel-body"><div class="skel skel-line"></div><div class="skel skel-line short"></div></div><div class="skel skel-switch"></div></div>
            <div class="skel-card"><div class="skel skel-avatar"></div><div class="skel-body"><div class="skel skel-line"></div><div class="skel skel-line short"></div></div><div class="skel skel-switch"></div></div>
        </div>

        <div id="toast" class="toast" role="status" aria-live="polite"></div>

        <div class="scrim" id="scrim" role="presentation">
            <div class="dialog" role="dialog" aria-modal="true" aria-labelledby="dlg-title" aria-describedby="dlg-msg">
                <h3 id="dlg-title"></h3>
                <p id="dlg-msg"></p>
                <div class="actions">
                    <button class="cancel" id="dlg-cancel" type="button">Cancel</button>
                    <button class="confirm" id="dlg-confirm" type="button">Confirm</button>
                </div>
            </div>
        </div>
    </div>

    <script>
    (function() {{
        const state = {{ guilds: [], plugins: [], openGuilds: new Set(), filter: '' }};
        const HELP_KEY = 'rl_help_dismissed';

        // ------- Utilities -------
        function escapeHtml(s) {{
            return (s == null ? '' : String(s)).replace(/[&<>"']/g, c =>
                ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}})[c]
            );
        }}

        // Stable letter-avatar color, derived from guild_id so the same
        // server always gets the same colour across sessions.
        const AVATAR_COLORS = ['#5865f2','#22c55e','#f59e0b','#ec4899','#8b5cf6','#14b8a6','#ef4444','#6366f1'];
        function avatarColor(gid) {{
            let h = 0;
            for (let i = 0; i < gid.length; i++) {{ h = (h * 31 + gid.charCodeAt(i)) >>> 0; }}
            return AVATAR_COLORS[h % AVATAR_COLORS.length];
        }}
        function avatarLetter(name) {{
            const trimmed = (name || '').trim();
            if (!trimmed) return '?';
            // grab first alphanumeric character we find (skip emoji etc.)
            for (const ch of trimmed) {{
                if (/[a-zA-Z0-9]/.test(ch)) return ch.toUpperCase();
            }}
            return trimmed[0].toUpperCase();
        }}

        // Real Discord server icon if we have a hash, else a colored
        // letter circle. Animated icons (hash starts with `a_`) still
        // load as a static PNG — keeps the page light. If the image
        // 404s (deleted icon), a delegated error listener swaps in the
        // letter — see setupContentDelegation.
        function avatarHtml(g) {{
            const color = avatarColor(g.guild_id);
            const letter = avatarLetter(g.guild_name || '');
            const safeLetter = escapeHtml(letter);
            if (g.icon_hash) {{
                const safeId = encodeURIComponent(g.guild_id);
                const safeHash = encodeURIComponent(g.icon_hash);
                const src = `https://cdn.discordapp.com/icons/${{safeId}}/${{safeHash}}.png?size=64`;
                return `<div class="avatar" style="background:${{color}}" aria-hidden="true" data-letter="${{safeLetter}}"><img src="${{src}}" alt="" loading="lazy" referrerpolicy="no-referrer"></div>`;
            }}
            return `<div class="avatar" style="background:${{color}}" aria-hidden="true">${{safeLetter}}</div>`;
        }}

        function highlightMatch(text, q) {{
            const safe = escapeHtml(text);
            if (!q) return safe;
            const safeQ = escapeHtml(q);
            const re = new RegExp('(' + safeQ.replace(/[.*+?^${{}}()|[\]\\]/g, '\\$&') + ')', 'i');
            return safe.replace(re, '<mark>$1</mark>');
        }}

        function guildStatus(g) {{
            if (g.master_optout) return 'off';
            if (g.plugin_optouts && g.plugin_optouts.length > 0) return 'custom';
            return 'on';
        }}

        // ------- API -------
        async function api(method, path, body) {{
            const opts = {{ method, headers: {{}}, credentials: 'include' }};
            if (body) {{
                opts.headers['Content-Type'] = 'application/json';
                opts.body = JSON.stringify(body);
            }}
            const res = await fetch(path, opts);
            const data = await res.json().catch(() => ({{}}));
            if (!res.ok) throw new Error(data.error || 'Request failed');
            return data;
        }}

        // ------- Toast -------
        let toastTimer;
        function toast(msg, isError) {{
            const el = document.getElementById('toast');
            el.innerHTML = escapeHtml(msg);
            el.className = 'toast show' + (isError ? ' error' : '');
            clearTimeout(toastTimer);
            toastTimer = setTimeout(() => el.classList.remove('show'), 2400);
        }}

        // Persistent toast with spinner — used while a bulk request is
        // in flight. Returns a function the caller invokes to dismiss.
        function busy(msg) {{
            const el = document.getElementById('toast');
            clearTimeout(toastTimer);
            el.innerHTML = `<span class="spinner" aria-hidden="true"></span>${{escapeHtml(msg)}}`;
            el.className = 'toast show busy';
            return () => {{ el.classList.remove('show', 'busy'); }};
        }}

        // ------- Confirm dialog -------
        function confirmDialog(title, message, confirmLabel, danger) {{
            return new Promise(resolve => {{
                const scrim = document.getElementById('scrim');
                document.getElementById('dlg-title').textContent = title;
                document.getElementById('dlg-msg').textContent = message;
                const btn = document.getElementById('dlg-confirm');
                btn.textContent = confirmLabel;
                btn.className = 'confirm' + (danger ? ' danger' : '');
                scrim.classList.add('show');
                btn.focus();
                function cleanup(result) {{
                    scrim.classList.remove('show');
                    btn.removeEventListener('click', onYes);
                    document.getElementById('dlg-cancel').removeEventListener('click', onNo);
                    scrim.removeEventListener('click', onScrim);
                    document.removeEventListener('keydown', onKey);
                    resolve(result);
                }}
                function onYes() {{ cleanup(true); }}
                function onNo() {{ cleanup(false); }}
                function onScrim(e) {{ if (e.target === scrim) cleanup(false); }}
                function onKey(e) {{ if (e.key === 'Escape') cleanup(false); }}
                btn.addEventListener('click', onYes);
                document.getElementById('dlg-cancel').addEventListener('click', onNo);
                scrim.addEventListener('click', onScrim);
                document.addEventListener('keydown', onKey);
            }});
        }}

        // ------- Rendering -------
        function statsHtml() {{
            const total = state.guilds.length;
            let on = 0, custom = 0, off = 0;
            for (const g of state.guilds) {{
                const s = guildStatus(g);
                if (s === 'on') on++;
                else if (s === 'custom') custom++;
                else off++;
            }}
            return `
                <span class="seg on"><b>${{on}}</b> on</span>
                <span class="seg custom"><b>${{custom}}</b> custom</span>
                <span class="seg off"><b>${{off}}</b> off</span>
                <span class="seg" style="opacity:.6"><b>${{total}}</b> total</span>
            `;
        }}

        function guildCard(g) {{
            const status = guildStatus(g);
            const masterOn = !g.master_optout;
            const safeName = g.guild_name || '(unnamed server)';
            const nameHtml = highlightMatch(safeName, state.filter);
            const customCount = g.plugin_optouts ? g.plugin_optouts.length : 0;

            let badgeHtml = '';
            if (status === 'on') badgeHtml = '<span class="badge on">All plugins on</span>';
            else if (status === 'off') badgeHtml = '<span class="badge off">Disabled</span>';
            else badgeHtml = `<span class="badge custom">${{customCount}} plugin${{customCount === 1 ? '' : 's'}} off</span>`;

            // Per-plugin section: only meaningful when master is on.
            // When master is off, show a friendly explainer instead of a
            // grid of disabled toggles — less visual noise.
            let pluginsBlock = '';
            if (masterOn) {{
                const open = state.openGuilds.has(g.guild_id);
                const showPluginSearch = state.plugins.length > 6;
                const pluginRows = state.plugins.map(p => {{
                    const off = g.plugin_optouts.includes(p.slug);
                    return `<div class="plugin-row" data-plugin-name="${{escapeHtml(p.display_name.toLowerCase())}}">
                        <span class="name">${{escapeHtml(p.display_name)}}</span>
                        <label class="switch">
                            <input type="checkbox" class="plugin-toggle"
                                data-guild="${{escapeHtml(g.guild_id)}}"
                                data-plugin="${{escapeHtml(p.slug)}}"
                                ${{!off ? 'checked' : ''}}
                                aria-label="${{escapeHtml(p.display_name)}} in ${{escapeHtml(safeName)}}">
                            <span class="slider"></span>
                        </label>
                    </div>`;
                }}).join('');
                const countBadge = customCount > 0 ? `<span class="count">${{customCount}} off</span>` : '';
                const pluginSearchHtml = showPluginSearch
                    ? `<input type="search" class="plugin-search" placeholder="Filter plugins…" autocomplete="off" data-guild="${{escapeHtml(g.guild_id)}}" aria-label="Filter plugins">`
                    : '';
                pluginsBlock = `
                    <button type="button" class="expand ${{open ? 'open' : ''}}" data-guild="${{escapeHtml(g.guild_id)}}" aria-expanded="${{open}}">
                        <span>Customize per plugin</span>
                        ${{countBadge}}
                        <span class="chev" aria-hidden="true">▾</span>
                    </button>
                    <div class="plugins ${{open ? 'open' : ''}}">
                        ${{pluginSearchHtml}}
                        ${{pluginRows}}
                    </div>
                `;
            }} else {{
                pluginsBlock = `<div class="off-msg">All RoleLogic roles are paused in this server. Turn the switch back on to receive roles again.</div>`;
            }}

            return `<div class="card ${{status}}" data-guild-id="${{escapeHtml(g.guild_id)}}" data-name="${{escapeHtml(safeName.toLowerCase())}}">
                <div class="row">
                    ${{avatarHtml(g)}}
                    <div class="body">
                        <div class="gname" title="${{escapeHtml(safeName)}}">${{nameHtml}}</div>
                        <div class="badges">${{badgeHtml}}</div>
                    </div>
                    <label class="switch" title="Receive RoleLogic roles in ${{escapeHtml(safeName)}}">
                        <input type="checkbox" class="master-toggle"
                            data-guild="${{escapeHtml(g.guild_id)}}"
                            ${{masterOn ? 'checked' : ''}}
                            aria-label="Enable RoleLogic in ${{escapeHtml(safeName)}}">
                        <span class="slider"></span>
                    </label>
                </div>
                ${{pluginsBlock}}
            </div>`;
        }}

        function applyFilter() {{
            const q = state.filter.toLowerCase().trim();
            let visible = 0;
            document.querySelectorAll('.cards .card').forEach(el => {{
                const name = el.dataset.name || '';
                const match = !q || name.includes(q);
                el.classList.toggle('hidden-by-search', !match);
                if (match) visible++;
            }});
            const root = document.getElementById('content');
            const noMatch = root.querySelector('.no-match');
            if (visible === 0 && state.guilds.length > 0) {{
                if (!noMatch) {{
                    const div = document.createElement('div');
                    div.className = 'empty no-match';
                    div.innerHTML = `
                        <span class="emoji" aria-hidden="true">🔍</span>
                        <div class="title">No servers match "${{escapeHtml(q)}}"</div>
                        <p>Try a different search, or clear it to see all your servers.</p>
                        <button type="button" id="reset-search">Clear search</button>
                    `;
                    root.appendChild(div);
                    document.getElementById('reset-search').addEventListener('click', () => {{
                        document.getElementById('search-input').value = '';
                        setFilter('');
                    }});
                }}
            }} else if (noMatch) {{
                noMatch.remove();
            }}
        }}

        function setFilter(q) {{
            state.filter = q;
            document.getElementById('clear-search').classList.toggle('show', q.length > 0);
            // re-render names so highlight updates
            render();
        }}

        function render() {{
            const root = document.getElementById('content');
            const toolbar = document.getElementById('toolbar');

            if (!state.guilds.length) {{
                toolbar.classList.add('hidden');
                root.innerHTML = `
                    <div class="empty">
                        <span class="emoji" aria-hidden="true">🪐</span>
                        <div class="title">No servers yet</div>
                        <p>You're not in any Discord servers we can see. Once you verify with a RoleLogic plugin, Discord shares your server list and they'll show up here.</p>
                    </div>
                `;
                document.getElementById('stats').innerHTML = '';
                return;
            }}

            toolbar.classList.remove('hidden');
            document.getElementById('stats').innerHTML = statsHtml();

            const cardsHtml = state.guilds.map(g => guildCard(g)).join('');
            root.innerHTML = `<div class="cards">${{cardsHtml}}</div>`;
            applyFilter();
        }}

        // ------- Event handlers -------
        async function onMasterToggle(e) {{
            const el = e.target;
            const guildId = el.dataset.guild;
            const enabled = el.checked;
            const g = state.guilds.find(x => x.guild_id === guildId);
            if (!g) return;
            el.disabled = true;
            try {{
                await api('POST', '/auth/preferences', {{ guild_id: guildId, plugin: null, enabled }});
                g.master_optout = !enabled;
                if (enabled) state.openGuilds.delete(guildId); // collapse on re-enable too is fine
                render();
                toast(enabled ? `Enabled in ${{g.guild_name || 'this server'}}` : `Paused in ${{g.guild_name || 'this server'}}`);
            }} catch (err) {{
                el.checked = !enabled;
                toast(err.message, true);
            }} finally {{
                el.disabled = false;
            }}
        }}

        async function onPluginToggle(e) {{
            const el = e.target;
            const guildId = el.dataset.guild;
            const plugin = el.dataset.plugin;
            const enabled = el.checked;
            const g = state.guilds.find(x => x.guild_id === guildId);
            if (!g) return;
            el.disabled = true;
            try {{
                await api('POST', '/auth/preferences', {{ guild_id: guildId, plugin, enabled }});
                if (enabled) g.plugin_optouts = g.plugin_optouts.filter(p => p !== plugin);
                else if (!g.plugin_optouts.includes(plugin)) g.plugin_optouts.push(plugin);
                // Refresh just stats + this card's badge — full render keeps things simple
                // and preserves the open expand state.
                state.openGuilds.add(guildId);
                render();
                toast(enabled ? 'Plugin enabled here' : 'Plugin paused here');
            }} catch (err) {{
                el.checked = !enabled;
                toast(err.message, true);
            }} finally {{
                el.disabled = false;
            }}
        }}

        async function onAutoEnableToggle(e) {{
            const el = e.target;
            const enabled = el.checked;
            el.disabled = true;
            try {{
                await api('POST', '/auth/preferences/auto_enable', {{ enabled }});
                toast(enabled ? 'New servers will be auto-enabled' : 'New servers will start paused');
            }} catch (err) {{
                el.checked = !enabled;
                toast(err.message, true);
            }} finally {{
                el.disabled = false;
            }}
        }}

        function onExpandClick(e) {{
            const btn = e.target.closest('.expand');
            if (!btn) return;
            const guildId = btn.dataset.guild;
            if (state.openGuilds.has(guildId)) state.openGuilds.delete(guildId);
            else state.openGuilds.add(guildId);
            render();
        }}

        function onPluginSearch(e) {{
            const input = e.target;
            const guildId = input.dataset.guild;
            const q = input.value.toLowerCase().trim();
            const card = document.querySelector(`.card[data-guild-id="${{CSS.escape(guildId)}}"]`);
            if (!card) return;
            card.querySelectorAll('.plugin-row').forEach(row => {{
                const name = row.dataset.pluginName || '';
                row.classList.toggle('hidden', !!q && !name.includes(q));
            }});
        }}

        async function bulkUpdate(enable) {{
            const targets = state.guilds.filter(g => (enable ? g.master_optout : !g.master_optout));
            if (targets.length === 0) {{
                toast(enable ? 'All servers are already enabled' : 'All servers are already paused');
                return;
            }}
            const title = enable ? 'Enable all servers?' : 'Pause all servers?';
            const msg = enable
                ? `Turn RoleLogic on in ${{targets.length}} server${{targets.length === 1 ? '' : 's'}}? Any per-plugin customizations stay as-is.`
                : `Pause RoleLogic in ${{targets.length}} server${{targets.length === 1 ? '' : 's'}}? You can re-enable individually any time.`;
            const ok = await confirmDialog(title, msg, enable ? 'Enable all' : 'Pause all', !enable);
            if (!ok) return;

            // Single round-trip bulk endpoint — one DB transaction, no
            // N×latency stall when the user has dozens of servers. We do
            // an optimistic local update first so the UI reflects the
            // change immediately, then roll it back if the server errors.
            const snapshot = state.guilds.map(g => g.master_optout);
            for (const g of state.guilds) g.master_optout = !enable;
            render();
            const done = busy(`${{enable ? 'Enabling' : 'Pausing'}} ${{targets.length}} server${{targets.length === 1 ? '' : 's'}}…`);

            try {{
                await api('POST', '/auth/preferences/bulk', {{ enabled: enable }});
                done();
                toast(`${{enable ? 'Enabled' : 'Paused'}} ${{targets.length}} server${{targets.length === 1 ? '' : 's'}}`);
            }} catch (err) {{
                // Roll back optimistic update on failure.
                state.guilds.forEach((g, i) => {{ g.master_optout = snapshot[i]; }});
                render();
                done();
                toast(err.message || 'Bulk update failed', true);
            }}
        }}

        // ------- Menu -------
        function setupMenu() {{
            const btn = document.getElementById('menu-btn');
            const list = document.getElementById('menu-list');
            function close() {{ list.classList.remove('open'); btn.setAttribute('aria-expanded', 'false'); }}
            function open() {{ list.classList.add('open'); btn.setAttribute('aria-expanded', 'true'); }}
            btn.addEventListener('click', e => {{
                e.stopPropagation();
                list.classList.contains('open') ? close() : open();
            }});
            document.addEventListener('click', e => {{
                if (!btn.contains(e.target) && !list.contains(e.target)) close();
            }});
            document.addEventListener('keydown', e => {{
                if (e.key === 'Escape') close();
            }});
            list.addEventListener('click', e => {{
                const item = e.target.closest('.menu-item');
                if (!item) return;
                close();
                const action = item.dataset.action;
                if (action === 'enable-all') bulkUpdate(true);
                else if (action === 'disable-all') bulkUpdate(false);
            }});
        }}

        // ------- Help banner -------
        function setupHelp() {{
            const help = document.getElementById('help');
            try {{
                if (localStorage.getItem(HELP_KEY) === '1') help.classList.add('hidden');
            }} catch (_) {{}}
            document.getElementById('help-close').addEventListener('click', () => {{
                help.classList.add('hidden');
                try {{ localStorage.setItem(HELP_KEY, '1'); }} catch (_) {{}}
            }});
        }}

        // ------- Delegated listeners on #content -------
        function setupContentDelegation() {{
            const root = document.getElementById('content');
            root.addEventListener('change', e => {{
                if (e.target.classList.contains('master-toggle')) onMasterToggle(e);
                else if (e.target.classList.contains('plugin-toggle')) onPluginToggle(e);
            }});
            root.addEventListener('click', e => {{
                if (e.target.closest('.expand')) onExpandClick(e);
            }});
            root.addEventListener('input', e => {{
                if (e.target.classList.contains('plugin-search')) onPluginSearch(e);
            }});
            // Image-load errors don't bubble, so capture phase. When a
            // Discord icon 404s (server deleted its icon), swap to the
            // letter fallback in place.
            root.addEventListener('error', e => {{
                const img = e.target;
                if (img.tagName !== 'IMG' || !img.parentElement || !img.parentElement.classList.contains('avatar')) return;
                const avatar = img.parentElement;
                avatar.textContent = avatar.dataset.letter || '?';
            }}, true);
        }}

        // ------- Search -------
        function setupSearch() {{
            const input = document.getElementById('search-input');
            input.addEventListener('input', () => setFilter(input.value));
            document.getElementById('clear-search').addEventListener('click', () => {{
                input.value = '';
                setFilter('');
                input.focus();
            }});
            // Focus search with "/" when not already in an input
            document.addEventListener('keydown', e => {{
                if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {{
                    e.preventDefault();
                    input.focus();
                }}
            }});
        }}

        // ------- Initial load -------
        async function load() {{
            try {{
                // `refresh=1` forces a cooldown-gated full re-sync of the
                // guild list from Discord, so servers joined or left since
                // last login show up / disappear instead of a stale cache.
                // The skeleton above covers the extra round-trip latency.
                const data = await api('GET', '/auth/preferences?refresh=1');
                state.guilds = data.guilds || [];
                state.plugins = data.plugins || [];

                const autoEnableCard = document.getElementById('auto-enable-card');
                const autoEnableToggle = document.getElementById('auto-enable-toggle');
                autoEnableToggle.checked = data.auto_enable_new_guilds !== false;
                autoEnableToggle.addEventListener('change', onAutoEnableToggle);
                autoEnableCard.classList.remove('hidden');

                render();
            }} catch (err) {{
                document.getElementById('content').innerHTML = `
                    <div class="empty">
                        <span class="emoji" aria-hidden="true">⚠️</span>
                        <div class="title">Could not load your servers</div>
                        <p>${{escapeHtml(err.message)}}</p>
                        <button type="button" onclick="location.reload()">Try again</button>
                    </div>
                `;
            }}
        }}

        setupMenu();
        setupHelp();
        setupContentDelegation();
        setupSearch();
        load();
    }})();
    </script>
</body>
</html>"##
    )
}
