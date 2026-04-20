-- Admin maintainer extensions: client enabled flag, denylist, audit log.

-- Soft-disable flag for clients (mirrors users.enabled).
ALTER TABLE clients ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT TRUE;

-- Denylist for blocking users, clients, IPs, or email addresses from
-- authenticating or obtaining tokens.
CREATE TABLE IF NOT EXISTS denylist (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,               -- 'ip' | 'user_id' | 'username' | 'email' | 'client_id'
    value TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_denylist_kind_value ON denylist(kind, value);
CREATE INDEX IF NOT EXISTS idx_denylist_kind ON denylist(kind);

-- Audit log for admin mutations.
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL DEFAULT '',
    actor_email TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,             -- e.g. 'user.create', 'client.delete'
    target_kind TEXT NOT NULL DEFAULT '', -- 'user' | 'client' | 'token' | 'denylist' | ...
    target_id TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    metadata TEXT NOT NULL DEFAULT '', -- JSON blob with details
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor_id ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log(target_kind, target_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
