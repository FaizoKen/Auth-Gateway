-- Drop orphan opt-out rows for plugins that have been removed from the
-- registry. Without this, the rows linger forever — harmless to runtime
-- behavior (the frontend ignores unknown slugs) but cluttering the table
-- and confusing future debugging.
--
-- Add a row here every time a plugin is retired from src/plugins.rs.
DELETE FROM user_guild_optouts
    WHERE plugin IN ('topgg-voter-role', 'lootlabs-reward-role');
