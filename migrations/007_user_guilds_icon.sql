-- Store the Discord guild icon hash alongside the guild membership, so
-- the /auth/my_servers UI can render the real server avatar instead of
-- a letter-on-color fallback.
--
-- Nullable: not every server has an icon, and existing rows pre-date
-- this column. The OAuth callback and the guild_refresh_worker both
-- DELETE-then-INSERT the whole user's guild set, so the column
-- backfills naturally as users sign in or the worker rotates them —
-- no manual backfill needed.
ALTER TABLE user_guilds
    ADD COLUMN IF NOT EXISTS icon_hash TEXT;
