-- Per-user, per-guild opt-outs for plugin role assignment.
--
-- Storing only the negative case (opt-out) keeps the default behavior
-- ("assign roles everywhere I'm a member") intact for existing production
-- users — absence of a row means opted-in. No backfill needed; no roles
-- are wiped when this migration runs.
--
-- `plugin` is the plugin slug (e.g. `genshin-player-role`) for a
-- per-plugin override, or the empty string for the guild-wide master
-- opt-out that applies to every plugin in that guild. Combining these
-- in one table keeps the lookup a single index scan.
CREATE TABLE IF NOT EXISTS user_guild_optouts (
    discord_id TEXT NOT NULL,
    guild_id   TEXT NOT NULL,
    plugin     TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (discord_id, guild_id, plugin)
);

-- Fast filter by user (used when scoping a single user's guilds in
-- `/auth/internal/user_guild_ids`).
CREATE INDEX IF NOT EXISTS idx_user_guild_optouts_user
    ON user_guild_optouts (discord_id, plugin);

-- Fast filter by guild (used when listing a guild's member set in
-- `/auth/internal/guild_member_ids`).
CREATE INDEX IF NOT EXISTS idx_user_guild_optouts_guild
    ON user_guild_optouts (guild_id, plugin);
