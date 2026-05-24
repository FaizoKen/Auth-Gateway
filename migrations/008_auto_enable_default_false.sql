-- Flip the column default for `auto_enable_new_guilds` from TRUE to
-- FALSE. The application-level fallback (in services::optout) also
-- shifts to FALSE in the same release, so users with no row are now
-- treated as opted-out by default — new servers they join won't
-- auto-receive RoleLogic roles until they explicitly opt in via
-- /auth/my_servers.
--
-- Existing rows are untouched: anyone who has explicitly toggled the
-- setting (TRUE or FALSE) keeps the value they chose.
ALTER TABLE user_settings
    ALTER COLUMN auto_enable_new_guilds SET DEFAULT FALSE;
