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
}

pub struct DiscordOAuth {
    http: reqwest::Client,
}

impl DiscordOAuth {
    pub fn with_client(http: reqwest::Client) -> Self {
        Self { http }
    }

    pub fn authorize_url(config: &AppConfig, state: &str) -> String {
        let redirect_uri = config.oauth_redirect_uri();
        format!(
            "https://discord.com/oauth2/authorize?client_id={}&redirect_uri={}&response_type=code&scope=identify%20guilds&state={}",
            config.discord_client_id,
            urlencoding::encode(&redirect_uri),
            state
        )
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

    pub async fn get_user_guilds(
        &self,
        access_token: &str,
    ) -> Result<Vec<(String, String)>, AppError> {
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

        Ok(guilds.into_iter().map(|g| (g.id, g.name)).collect())
    }
}
