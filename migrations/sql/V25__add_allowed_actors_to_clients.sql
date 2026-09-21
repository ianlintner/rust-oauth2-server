-- Phase 7 (agent/A2A OAuth): per-client allow-list of actor client_ids.
-- RFC 8693 token exchange lets one client (the actor) act on behalf of
-- another (the subject). This column records, as a JSON array of
-- client_id strings, which actor clients this client permits to be named
-- in an `actor_token` when this client is the subject. Defaults to `[]`
-- (no delegation permitted) so existing clients continue to work unchanged.
ALTER TABLE clients ADD COLUMN allowed_actors TEXT NOT NULL DEFAULT '[]';
