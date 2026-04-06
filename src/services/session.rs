use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Create a signed session cookie value: discord_id:encoded_name:expiry_ts:signature
pub fn sign_session(discord_id: &str, display_name: &str, secret: &str) -> String {
    let expires = chrono::Utc::now().timestamp() + 3600; // 1 hour
    let encoded_name = urlencoding::encode(display_name);
    let payload = format!("{discord_id}:{encoded_name}:{expires}");

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(payload.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());

    format!("{payload}:{sig}")
}

/// Verify and extract (discord_id, display_name) from a signed session cookie.
/// Used by plugins reading the shared `rl_session` cookie.
#[allow(dead_code)]
pub fn verify_session(cookie_value: &str, secret: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = cookie_value.splitn(4, ':').collect();
    if parts.len() != 4 {
        return None;
    }

    let discord_id = parts[0];
    let encoded_name = parts[1];
    let expires_str = parts[2];
    let sig = parts[3];

    // Check expiry
    let expires: i64 = expires_str.parse().ok()?;
    if chrono::Utc::now().timestamp() > expires {
        return None;
    }

    // Verify signature
    let payload = format!("{discord_id}:{encoded_name}:{expires_str}");
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(payload.as_bytes());

    let expected_sig = hex::encode(mac.finalize().into_bytes());
    if sig != expected_sig {
        return None;
    }

    let display_name = urlencoding::decode(encoded_name).ok()?.into_owned();
    Some((discord_id.to_string(), display_name))
}
