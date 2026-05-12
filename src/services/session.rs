use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Session lifetime. Cookies are self-contained HMAC tokens (no DB lookup), so
/// the only revocation path is rotating SESSION_SECRET or waiting for expiry —
/// we want it long enough that admins don't re-OAuth constantly, but short
/// enough that a leaked cookie eventually stops working. 30 days matches the
/// Discord/GitHub norm for "stay signed in".
pub const SESSION_TTL_SECS: i64 = 30 * 24 * 3600;
/// Refresh threshold for sliding sessions: when a verified cookie has less
/// than this much life left, callers should re-issue it. Picked as half of
/// TTL so an active user effectively never hits the hard cap.
pub const SESSION_REFRESH_THRESHOLD_SECS: i64 = SESSION_TTL_SECS / 2;

/// Create a signed session cookie value: discord_id:encoded_name:expiry_ts:signature
pub fn sign_session(discord_id: &str, display_name: &str, secret: &str) -> String {
    let expires = chrono::Utc::now().timestamp() + SESSION_TTL_SECS;
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

/// If the cookie is still valid but past its refresh threshold, return a freshly
/// signed cookie value so the caller can re-issue it via Set-Cookie. Returns
/// `None` if the cookie is invalid, expired, or doesn't yet need refreshing.
/// This is what gives us a sliding session — every browser request that lands
/// on a route which checks the session can extend its life.
#[allow(dead_code)]
pub fn refresh_if_due(cookie_value: &str, secret: &str) -> Option<String> {
    let parts: Vec<&str> = cookie_value.splitn(4, ':').collect();
    if parts.len() != 4 {
        return None;
    }
    let discord_id = parts[0];
    let encoded_name = parts[1];
    let expires: i64 = parts[2].parse().ok()?;
    let now = chrono::Utc::now().timestamp();
    if expires <= now {
        return None;
    }
    if expires - now > SESSION_REFRESH_THRESHOLD_SECS {
        return None;
    }
    let display_name = urlencoding::decode(encoded_name).ok()?.into_owned();
    Some(sign_session(discord_id, &display_name, secret))
}
