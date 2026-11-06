use crate::config::AppConfig;
use crate::error::AppError;

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
}

#[derive(serde::Deserialize)]
struct DiscordUser {
    id: String,
    username: String,
    global_name: Option<String>,
}

#[derive(serde::Deserialize)]
struct DiscordGuild {
    id: String,
    name: String,
    // Discord guild icon hash. `null` when the server has no custom
    // icon — we fall back to a letter avatar client-side in that case.
    #[serde(default)]
    icon: Option<String>,
    // Discord returns permissions as a string-encoded u64 bitflag.
    #[serde(default)]
    permissions: String,
    #[serde(default)]
    owner: bool,
}

pub struct DiscordOAuth {
    http: reqwest::Client,
}

/// Why trading a refresh token failed.
#[derive(Debug)]
pub enum RefreshError {
    /// Discord answered `invalid_grant`: this refresh token will never work
    /// again. The user de-authorized the app, or the token was already used.
    Revoked(String),
    /// Anything else. The token may well still be valid, so it is kept and
    /// tried again later.
    Other(String),
}

impl std::fmt::Display for RefreshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefreshError::Revoked(detail) => write!(f, "refresh token revoked: {detail}"),
            RefreshError::Other(detail) => write!(f, "{detail}"),
        }
    }
}

#[derive(serde::Deserialize)]
struct OAuthErrorBody {
    #[serde(default)]
    error: String,
}

/// Classify a non-2xx answer from Discord's token endpoint. Only a 400/401
/// whose OAuth error is `invalid_grant` is a dead token. `invalid_client`
/// (our own credentials) is deliberately NOT one: a bad secret in a deploy
/// would otherwise throw away every user's token at once.
pub fn classify_refresh_failure(status: u16, body: &str) -> RefreshError {
    let detail = format!(
        "Discord token refresh returned {status}: {}",
        body_excerpt(body)
    );
    if status == 400 || status == 401 {
        let error = serde_json::from_str::<OAuthErrorBody>(body)
            .map(|b| b.error)
            .unwrap_or_default();
        if error == "invalid_grant" {
            return RefreshError::Revoked(detail);
        }
    }
    RefreshError::Other(detail)
}

/// Enough of an error body to read in a log line, never a whole HTML page.
fn body_excerpt(body: &str) -> String {
    body.chars().take(200).collect()
}

impl DiscordOAuth {
    pub fn with_client(http: reqwest::Client) -> Self {
        Self { http }
    }

    /// Build the Discord authorize URL.
    ///
    /// When `silent` is true, `prompt=none` is appended: Discord skips the
    /// consent screen and redirects straight back **iff** the user has already
    /// authorized this client with at least the requested scopes. Otherwise it
    /// redirects back with an `error` (e.g. `consent_required` /
    /// `login_required`), which the callback handles by retrying without
    /// `prompt=none`.
    pub fn authorize_url(config: &AppConfig, state: &str, silent: bool) -> String {
        let redirect_uri = config.oauth_redirect_uri();
        let mut url = format!(
            "https://discord.com/oauth2/authorize?client_id={}&redirect_uri={}&response_type=code&scope=identify%20guilds&state={}",
            config.discord_client_id,
            urlencoding::encode(&redirect_uri),
            state
        );
        if silent {
            url.push_str("&prompt=none");
        }
        url
    }

    pub async fn exchange_code(
        &self,
        config: &AppConfig,
        code: &str,
    ) -> Result<(String, Option<String>), AppError> {
        let resp: TokenResponse = self
            .http
            .post("https://discord.com/api/v10/oauth2/token")
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &config.oauth_redirect_uri()),
                ("client_id", &config.discord_client_id),
                ("client_secret", &config.discord_client_secret),
            ])
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Discord token exchange failed: {e}")))?
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Discord token parse failed: {e}")))?;

        Ok((resp.access_token, resp.refresh_token))
    }

    /// Trade a refresh token for a new access + refresh token pair.
    ///
    /// Only Discord saying `invalid_grant` means the token is gone for good
    /// (see [`classify_refresh_failure`]). Everything else — no answer, a
    /// rate limit, a Discord 5xx, a body we can't read — leaves the token as
    /// good as it was, and the caller must keep it.
    pub async fn refresh_access_token(
        &self,
        config: &AppConfig,
        refresh_token: &str,
    ) -> Result<(String, String), RefreshError> {
        let resp = self
            .http
            .post("https://discord.com/api/v10/oauth2/token")
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", &config.discord_client_id),
                ("client_secret", &config.discord_client_secret),
            ])
            .send()
            .await
            .map_err(|e| RefreshError::Other(format!("Discord token refresh failed: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(classify_refresh_failure(status.as_u16(), &body));
        }

        let parsed: TokenResponse = resp
            .json()
            .await
            .map_err(|e| RefreshError::Other(format!("Discord token refresh parse failed: {e}")))?;
        let new_refresh = parsed.refresh_token.ok_or_else(|| {
            RefreshError::Other("Discord token refresh returned no refresh_token".into())
        })?;

        Ok((parsed.access_token, new_refresh))
    }

    pub async fn get_user(&self, access_token: &str) -> Result<(String, String), AppError> {
        let user: DiscordUser = self
            .http
            .get("https://discord.com/api/v10/users/@me")
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Discord user fetch failed: {e}")))?
            .error_for_status()
            .map_err(|e| AppError::Internal(format!("Discord user fetch failed: {e}")))?
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Discord user parse failed: {e}")))?;

        let display_name = user.global_name.unwrap_or(user.username);
        Ok((user.id, display_name))
    }

    /// Returns `(guild_id, guild_name, manage_guild, icon_hash)` for each guild the user belongs to.
    /// `manage_guild` is true if the user is the guild owner or has the MANAGE_GUILD permission bit.
    /// `icon_hash` is `None` when the server has no custom icon.
    ///
    /// [`AppError::Unauthorized`] means Discord refused this access token for
    /// the guild list outright — a token granted without the `guilds` scope.
    /// Every other failure is [`AppError::Internal`].
    pub async fn get_user_guilds(
        &self,
        access_token: &str,
    ) -> Result<Vec<(String, String, bool, Option<String>)>, AppError> {
        let resp = self
            .http
            .get("https://discord.com/api/v10/users/@me/guilds")
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Discord guilds fetch failed: {e}")))?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(AppError::Unauthorized);
        }
        let guilds: Vec<DiscordGuild> = resp
            .error_for_status()
            .map_err(|e| AppError::Internal(format!("Discord guilds fetch failed: {e}")))?
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Discord guilds parse failed: {e}")))?;

        // MANAGE_GUILD = 0x20 (bit 5) in the Discord permissions bitfield.
        const MANAGE_GUILD: u64 = 0x20;
        Ok(guilds
            .into_iter()
            .map(|g| {
                let perms = g.permissions.parse::<u64>().unwrap_or(0);
                let manage = g.owner || (perms & MANAGE_GUILD) != 0;
                (g.id, g.name, manage, g.icon)
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn revoked(r: &RefreshError) -> bool {
        matches!(r, RefreshError::Revoked(_))
    }

    #[test]
    fn invalid_grant_is_a_dead_token() {
        let body = r#"{"error": "invalid_grant", "error_description": "Invalid \"refresh_token\" in request."}"#;
        assert!(revoked(&classify_refresh_failure(400, body)));
        assert!(revoked(&classify_refresh_failure(401, body)));
    }

    #[test]
    fn our_own_credentials_being_rejected_keeps_every_token() {
        // A wrong client secret after a deploy must not log everyone out.
        let body = r#"{"error": "invalid_client"}"#;
        assert!(!revoked(&classify_refresh_failure(401, body)));
        assert!(!revoked(&classify_refresh_failure(400, body)));
    }

    #[test]
    fn rate_limits_and_outages_keep_the_token() {
        let limited =
            r#"{"message": "You are being rate limited.", "retry_after": 1.2, "global": false}"#;
        assert!(!revoked(&classify_refresh_failure(429, limited)));
        assert!(!revoked(&classify_refresh_failure(500, "")));
        assert!(!revoked(&classify_refresh_failure(
            502,
            "<html>Bad gateway</html>"
        )));
        assert!(!revoked(&classify_refresh_failure(
            503,
            "upstream connect error"
        )));
        // A 400 we cannot read is not proof the token is dead either.
        assert!(!revoked(&classify_refresh_failure(
            400,
            "<html>oops</html>"
        )));
    }

    #[test]
    fn log_detail_is_bounded() {
        let huge = "x".repeat(10_000);
        let RefreshError::Other(detail) = classify_refresh_failure(502, &huge) else {
            panic!("a 502 is never a revocation");
        };
        assert!(detail.len() < 300);
    }
}
