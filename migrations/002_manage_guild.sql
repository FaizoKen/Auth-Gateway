-- Track whether a user has the Discord MANAGE_GUILD permission (or is owner) in each guild.
-- Used by plugins to gate admin-only views such as the player list.
ALTER TABLE user_guilds
    ADD COLUMN IF NOT EXISTS manage_guild BOOLEAN NOT NULL DEFAULT FALSE;
