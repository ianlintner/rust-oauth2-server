-- Phase 7 (agent/A2A OAuth): RFC 8693 actor_token request tracking.
-- When an authorization request carries a requested actor (the agent
-- client acting on behalf of the subject client), the AS records the
-- actor's client_id here so the token endpoint can re-validate
-- `Client::allows_actor` at redemption time. NULL means no actor was
-- requested (all pre-existing rows).
ALTER TABLE authorization_codes ADD COLUMN requested_actor TEXT;
