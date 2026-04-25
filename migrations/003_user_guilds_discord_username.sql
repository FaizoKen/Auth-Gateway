-- Persist the Discord display name (global_name, falling back to username) on
-- user_guilds rows so plugin admin pages can show "which Discord user this is"
-- without each plugin maintaining its own copy. Captured at OAuth callback and
-- refreshed by the guild_refresh_worker.

ALTER TABLE user_guilds ADD COLUMN IF NOT EXISTS discord_username TEXT;
