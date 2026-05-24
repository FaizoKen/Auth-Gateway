-- Track whether an OAuth attempt used Discord's `prompt=none` (silent) flow.
-- The callback uses this to decide what an error means:
--   silent = true  -> Discord refused the silent attempt (user never consented,
--                      scopes changed, or not logged in) -> retry with the real
--                      consent screen.
--   silent = false -> the consent screen itself was declined -> genuine denial,
--                      do not retry (prevents an infinite redirect loop).
ALTER TABLE oauth_states
    ADD COLUMN IF NOT EXISTS silent BOOLEAN NOT NULL DEFAULT false;
