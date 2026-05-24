-- Per-user settings. Currently just the "auto-enable new servers I join"
-- preference; further user-level switches go here too.
--
-- Default TRUE preserves the pre-existing behavior — users who never
-- visit `/auth/my_servers` keep getting roles auto-assigned in every
-- new guild they join, exactly like before.
CREATE TABLE IF NOT EXISTS user_settings (
    discord_id             TEXT PRIMARY KEY,
    auto_enable_new_guilds BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);
