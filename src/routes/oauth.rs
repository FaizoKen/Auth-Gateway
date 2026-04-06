use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::CookieJar;
use rand::Rng;

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

    let state_param: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let expires = chrono::Utc::now() + chrono::Duration::minutes(10);

    sqlx::query(
        "INSERT INTO oauth_states (state, return_to, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(&state_param)
    .bind(&return_to)
    .bind(expires)
    .execute(&state.pool)
    .await?;

    let url = DiscordOAuth::authorize_url(&state.config, &state_param);
    Ok(Redirect::temporary(&url).into_response())
}

/// GET /auth/callback?code=...&state=...
pub async fn callback(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<CallbackQuery>,
) -> Result<(CookieJar, Redirect), AppError> {
    // Handle user denial
    if query.error.is_some() || query.code.is_none() {
        return Ok((jar, Redirect::to("/")));
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
            sqlx::query("DELETE FROM user_guilds WHERE discord_id = $1")
                .bind(&discord_id)
                .execute(&mut *tx)
                .await?;

            let guild_ids: Vec<&str> = guilds.iter().map(|(id, _)| id.as_str()).collect();
            let guild_names: Vec<&str> = guilds.iter().map(|(_, name)| name.as_str()).collect();
            sqlx::query(
                "INSERT INTO user_guilds (discord_id, guild_id, guild_name, updated_at) \
                 SELECT $1, UNNEST($2::text[]), UNNEST($3::text[]), now()",
            )
            .bind(&discord_id)
            .bind(&guild_ids)
            .bind(&guild_names)
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

    // Set session cookie
    let session_value =
        session::sign_session(&discord_id, &display_name, &state.config.session_secret);

    let cookie = axum_extra::extract::cookie::Cookie::build((SESSION_COOKIE, session_value))
        .path("/")
        .http_only(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .max_age(time::Duration::hours(1));

    let jar = jar.add(cookie);

    tracing::info!(discord_id, display_name, "User authenticated");
    Ok((jar, Redirect::to(&return_to)))
}

/// POST /auth/logout
pub async fn logout(jar: CookieJar) -> (CookieJar, Redirect) {
    let cookie = axum_extra::extract::cookie::Cookie::build(SESSION_COOKIE)
        .path("/")
        .http_only(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .max_age(time::Duration::ZERO);

    (jar.remove(cookie), Redirect::to("/"))
}
