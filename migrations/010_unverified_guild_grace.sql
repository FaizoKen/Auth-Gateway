-- Guild lists the gateway can no longer verify now expire.
--
-- A user whose Discord refresh token is gone (de-authorized, or lost to a
-- transient refresh error before that was told apart from a revocation)
-- used to keep their user_guilds rows forever. The worker now removes such
-- rows UNVERIFIED_GRACE_DAYS (14) after Discord last confirmed them
-- (`updated_at`), unless the user signs in again.
--
-- Users who were already token-less before this release would otherwise
-- all expire on the first sweep, since their rows are old. Give them the
-- same 14 days counted from now, so nobody loses a role the moment this
-- deploys and anyone still around has time to sign in.
--
-- Migrations here re-run on every start, so the bump is claimed once in
-- one_time_migrations: a restart must not restart the grace period.

CREATE TABLE IF NOT EXISTS one_time_migrations (
    name       TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

WITH claimed AS (
    INSERT INTO one_time_migrations (name)
    VALUES ('010_unverified_guild_grace')
    ON CONFLICT (name) DO NOTHING
    RETURNING name
)
UPDATE user_guilds ug
   SET updated_at = now()
 WHERE EXISTS (SELECT 1 FROM claimed)
   AND NOT EXISTS (
       SELECT 1 FROM discord_tokens dt WHERE dt.discord_id = ug.discord_id
   );
