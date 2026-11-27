-- Operator-initiated cutover to at-rest storage format v1.
-- NOT a Flyway migration and never run by the server. Review, take a backup,
-- then run it deliberately (SQLite and PostgreSQL compatible):
--
--   sqlite3 -bail oauth2.db < scripts/at_rest_cutover.sql
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f scripts/at_rest_cutover.sql
--
-- Effect (all-or-nothing in one transaction):
--   * every bearer row not already in `h1$` form is removed (access/refresh
--     tokens, authorization codes, device codes): sessions and grants reset;
--   * every client secret not already in `c1$` form is replaced by an
--     unusable marker; the raw value is discarded. Operators then issue a new
--     secret per client (admin secret rotation), which is stored as v1;
--   * every registration access token not in `h1$` form is cleared.
-- Rows already in v1 form are left alone, so the script is re-runnable.

BEGIN;

DELETE FROM tokens
 WHERE access_token NOT LIKE 'h1$%'
    OR (refresh_token IS NOT NULL AND refresh_token NOT LIKE 'h1$%');

DELETE FROM authorization_codes WHERE code NOT LIKE 'h1$%';

DELETE FROM device_authorizations WHERE device_code NOT LIKE 'h1$%';

UPDATE clients
   SET client_secret = 'legacy-invalidated'
 WHERE client_secret NOT LIKE 'c1$%'
   AND token_endpoint_auth_method <> 'none';

UPDATE clients
   SET registration_access_token = ''
 WHERE registration_access_token <> ''
   AND registration_access_token NOT LIKE 'h1$%';

COMMIT;
