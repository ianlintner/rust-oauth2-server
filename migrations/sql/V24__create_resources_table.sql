-- Protected resources registry (RFC 8707 / RFC 9728), used by agent / A2A
-- OAuth flows to validate the `resource` parameter and advertise per-resource
-- metadata (scopes, supported `authorization_details` types, and the JWKS
-- URI used for transaction confirmation challenges).
CREATE TABLE IF NOT EXISTS resources (
    id TEXT PRIMARY KEY,
    resource_uri TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    authorization_details_types TEXT NOT NULL DEFAULT '[]',
    txn_challenge_jwks_uri TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_resources_resource_uri ON resources(resource_uri);
