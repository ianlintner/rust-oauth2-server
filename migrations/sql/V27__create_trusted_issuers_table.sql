-- Trusted issuers registry for RFC 7523 JWT bearer grants (agent / A2A OAuth).
-- Each row describes an external issuer whose signed JWTs may be exchanged
-- for a local access token via urn:ietf:params:oauth:grant-type:jwt-bearer.
CREATE TABLE IF NOT EXISTS trusted_issuers (
    id TEXT PRIMARY KEY,
    issuer TEXT NOT NULL UNIQUE,
    jwks_uri TEXT NOT NULL,
    allowed_audiences TEXT NOT NULL DEFAULT '[]',
    subject_mapping TEXT NOT NULL DEFAULT 'sub',
    jit_provision BOOLEAN NOT NULL DEFAULT FALSE,
    allowed_client_ids TEXT NOT NULL DEFAULT '[]',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_trusted_issuers_issuer ON trusted_issuers(issuer);
