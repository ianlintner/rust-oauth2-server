-- Transaction Authorization Challenge (draft-rosomakho-oauth-txn-challenge-00).
--
-- A protected resource signs a challenge describing an operation that needs
-- human approval; the client submits it to
-- `POST /oauth/transaction_authorization`, a human approves or denies it on
-- the approval page, and the client then polls the token endpoint with
-- `grant_type=urn:ietf:params:oauth:grant-type:transaction-authorization`.
CREATE TABLE IF NOT EXISTS transaction_authorizations (
    id TEXT PRIMARY KEY,
    transaction_authorization_id TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL,
    user_id TEXT,
    resource_uri TEXT NOT NULL,
    txn TEXT NOT NULL,
    authorization_details TEXT NOT NULL DEFAULT '[]',
    reason TEXT NOT NULL DEFAULT '',
    reason_uri TEXT NOT NULL DEFAULT '',
    act TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    interval_seconds INTEGER NOT NULL DEFAULT 5,
    approved BOOLEAN NOT NULL DEFAULT FALSE,
    denied BOOLEAN NOT NULL DEFAULT FALSE,
    used BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_transaction_authorizations_txn_auth_id
    ON transaction_authorizations(transaction_authorization_id);
CREATE INDEX IF NOT EXISTS idx_transaction_authorizations_client_id
    ON transaction_authorizations(client_id);
