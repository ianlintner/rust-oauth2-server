-- RFC 8705: mTLS client auth — store the expected TLS certificate Subject DN.
-- Used when token_endpoint_auth_method = 'tls_client_auth'.
-- Empty string means no DN restriction (accept any valid cert thumbprint).
ALTER TABLE clients ADD COLUMN tls_client_certificate_subject_dn TEXT NOT NULL DEFAULT '';
