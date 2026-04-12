-- RFC 7591 / RFC 7592: Dynamic Client Registration metadata fields
ALTER TABLE clients ADD COLUMN registration_access_token TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN response_types TEXT NOT NULL DEFAULT '["code"]';
ALTER TABLE clients ADD COLUMN contacts TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN logo_uri TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN client_uri TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN policy_uri TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN tos_uri TEXT NOT NULL DEFAULT '';

-- RFC 7523: JWT client authentication keys
ALTER TABLE clients ADD COLUMN jwks TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN jwks_uri TEXT NOT NULL DEFAULT '';
