-- RFC 9449 §11.1: DPoP proof replay prevention.
-- Each accepted proof's `jti` is recorded here until the proof's acceptance
-- window closes, so a replay is detected across restarts and across AS
-- instances sharing this database (the in-memory store only covers a single
-- process). Rows are deleted opportunistically once `expires_at` has passed.
CREATE TABLE IF NOT EXISTS dpop_jtis (
    jti TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dpop_jtis_expires_at ON dpop_jtis(expires_at);
