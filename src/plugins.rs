//! Static registry of plugins served from this gateway.
//!
//! Used by:
//! - `/auth/my_servers` to render the per-(plugin × server) toggle UI.
//! - `/auth/preferences` to validate that `plugin` query/body values
//!   refer to a known plugin (so users can't poison the table with
//!   arbitrary strings).
//!
//! Adding a new plugin: append an entry below. The `slug` must match the
//! plugin's URL prefix and the value it sends in the `plugin=` query
//! parameter to `/auth/internal/*`.
pub struct PluginEntry {
    pub slug: &'static str,
    pub display_name: &'static str,
}

pub const PLUGINS: &[PluginEntry] = &[
    PluginEntry { slug: "birthday-role",            display_name: "Birthday Role" },
    PluginEntry { slug: "bluesky-account-role",     display_name: "Bluesky Account Role" },
    PluginEntry { slug: "email-domain-role",        display_name: "Email Domain Role" },
    PluginEntry { slug: "form-respondent-role",     display_name: "Form Respondent Role" },
    PluginEntry { slug: "genshin-player-role",      display_name: "Genshin Player Role" },
    PluginEntry { slug: "github-contributor-role",  display_name: "GitHub Contributor Role" },
    PluginEntry { slug: "kick-channel-role",        display_name: "Kick Channel Role" },
    PluginEntry { slug: "member-origin-role",       display_name: "Member Origin Role" },
    PluginEntry { slug: "osu-player-role",          display_name: "osu! Player Role" },
    PluginEntry { slug: "referral-code-role",       display_name: "Referral Code Role" },
    PluginEntry { slug: "roblox-player-role",       display_name: "Roblox Player Role" },
    PluginEntry { slug: "steam-player-role",        display_name: "Steam Player Role" },
    PluginEntry { slug: "stripe-subscriber-role",   display_name: "Stripe Subscriber Role" },
    PluginEntry { slug: "tiktok-creator-role",      display_name: "TikTok Creator Role" },
    PluginEntry { slug: "twitch-follower-role",     display_name: "Twitch Follower Role" },
    PluginEntry { slug: "youtube-subscriber-role",  display_name: "YouTube Subscriber Role" },
];

pub fn is_known_plugin(slug: &str) -> bool {
    PLUGINS.iter().any(|p| p.slug == slug)
}
