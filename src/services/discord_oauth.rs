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

    pub async fn refresh_access_token(
        &self,
        config: &AppConfig,
        refresh_token: &str,
    ) -> Result<(String, String), AppError> {
        let resp: TokenResponse = self
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
            .map_err(|e| AppError::Internal(format!("Discord token refresh failed: {e}")))?
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Discord token refresh parse failed: {e}")))?;

        let new_refresh = resp.refresh_token.ok_or_else(|| {
            AppError::Internal("Discord token refresh returned no refresh_token".into())
        })?;

        Ok((resp.access_token, new_refresh))
    }

    pub async fn get_user(&self, access_token: &str) -> Result<(String, String), AppError> {
        let user: DiscordUser = self
            .http
            .get("https://discord.com/api/v10/users/@me")
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .await
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
    pub async fn get_user_guilds(
        &self,
        access_token: &str,
    ) -> Result<Vec<(String, String, bool, Option<String>)>, AppError> {
        let guilds: Vec<DiscordGuild> = self
            .http
            .get("https://discord.com/api/v10/users/@me/guilds")
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .await
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
