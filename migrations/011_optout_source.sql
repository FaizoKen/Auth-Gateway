-- Record who decided each pause: the user, or the automatic default.
--
-- Since 008 a user with no `user_settings` row has every server they are
-- first seen in, or join later, paused for them (`apply_optouts_for_new_guilds`).
-- Those rows are a default nobody chose, but they were stored exactly like a
-- pause the user toggled on /auth/my_servers. Plugins whose members come from
-- their own records (a Stripe subscription carrying the member's Discord id)
-- then dropped paying members on the strength of a default. By 2026-11-12 the
-- table held ~814k rows, ~710k of them guild-wide, against ~12 deliberate
-- server pauses a day in the logs.
--
--   source = 'user'  the user paused it: a toggle or "pause all" on My
--                    Servers, a per-plugin switch, or new servers starting
--                    paused because they themselves turned auto-enable off.
--   source = 'auto'  applied by default to a user who never chose.
--
-- `/auth/internal/guild_optout_ids?explicit_only=true` returns only 'user'
-- rows. Every other read still honors both, so nothing changes for callers
-- that don't ask.
--
-- Existing rows predate the column. One-time classification, claimed in
-- one_time_migrations (this file re-runs on every start):
--   - per-plugin rows: only ever written by a user                -> 'user'
--   - guild-wide rows of a user with a user_settings row: they
--     have used My Servers, so any of their pauses may be chosen   -> 'user'
--   - every other guild-wide row                                  -> 'auto'
-- The last bucket can hold a pause a user toggled on My Servers before the
-- logs we keep begin (2026-10-29) without ever touching the auto-enable
-- switch. Pauses inside the log window are re-marked 'user' separately.

ALTER TABLE user_guild_optouts ADD COLUMN IF NOT EXISTS source TEXT;

WITH claimed AS (
    INSERT INTO one_time_migrations (name)
    VALUES ('011_optout_source')
    ON CONFLICT (name) DO NOTHING
    RETURNING name
)
UPDATE user_guild_optouts o
   SET source = CASE
         WHEN o.plugin <> '' THEN 'user'
         WHEN EXISTS (
             SELECT 1 FROM user_settings s WHERE s.discord_id = o.discord_id
         ) THEN 'user'
         ELSE 'auto'
       END
 WHERE EXISTS (SELECT 1 FROM claimed)
   AND o.source IS NULL;

-- Anything still unclassified is treated as the user's choice: honoring a
-- pause nobody made costs a role, ignoring one somebody made costs consent.
UPDATE user_guild_optouts SET source = 'user' WHERE source IS NULL;

ALTER TABLE user_guild_optouts ALTER COLUMN source SET DEFAULT 'user';
ALTER TABLE user_guild_optouts ALTER COLUMN source SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'user_guild_optouts_source_check'
    ) THEN
        ALTER TABLE user_guild_optouts
            ADD CONSTRAINT user_guild_optouts_source_check
            CHECK (source IN ('user', 'auto'));
    END IF;
END $$;
