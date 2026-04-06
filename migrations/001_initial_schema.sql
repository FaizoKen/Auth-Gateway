-- Auth Gateway: centralized Discord OAuth and guild membership

-- CSRF protection for OAuth flow
CREATE TABLE IF NOT EXISTS oauth_states (
    state        TEXT PRIMARY KEY,
    return_to    TEXT NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Discord OAuth refresh tokens (consolidated from all plugins)
CREATE TABLE IF NOT EXISTS discord_tokens (
    discord_id          TEXT PRIMARY KEY,
    refresh_token       TEXT NOT NULL,
    guilds_refreshed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- User guild memberships (consolidated from all plugins)
CREATE TABLE IF NOT EXISTS user_guilds (
    discord_id TEXT NOT NULL,
    guild_id   TEXT NOT NULL,
    guild_name TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (discord_id, guild_id)
);
CREATE INDEX IF NOT EXISTS idx_user_guilds_guild ON user_guilds (guild_id);
CREATE INDEX IF NOT EXISTS idx_user_guilds_discord ON user_guilds (discord_id);
