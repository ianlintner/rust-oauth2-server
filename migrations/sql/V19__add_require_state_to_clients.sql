-- RFC 9700 §4.7: defense-in-depth for the CSRF case that PKCE already
-- covers. When `require_state = true` the AS rejects authorization
-- requests that omit `state`, forcing the client to carry and verify
-- a CSRF token on the redirect. Defaults to FALSE so existing clients
-- continue to work without churn.
ALTER TABLE clients ADD COLUMN require_state BOOLEAN NOT NULL DEFAULT FALSE;
