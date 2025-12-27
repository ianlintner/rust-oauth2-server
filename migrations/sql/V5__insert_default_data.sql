-- Insert default data for development/testing only
-- WARNING: Remove or regenerate these credentials before production deployment

INSERT INTO clients (id, client_id, client_secret, redirect_uris, grant_types, scope, name, created_at, updated_at)
VALUES (
    'default-client-id',
    'default_client',
    -- Generate a secure secret before production: openssl rand -hex 32
    'INSECURE_DEFAULT_SECRET_REGENERATE_FOR_PRODUCTION',
    '["http://localhost:3000/callback"]',
    '["authorization_code", "client_credentials", "password", "refresh_token"]',
    'read write admin',
    'Default Client',
    NOW(),
    NOW()
)
ON CONFLICT (id) DO NOTHING;

-- Insert a test user for development only
-- Password is 'password' - this hash is a placeholder and will not work
-- Generate proper hash: echo 'password' | argon2 somesalt -id -t 2 -m 19 -p 1
INSERT INTO users (id, username, password_hash, email, enabled, created_at, updated_at)
VALUES (
    'test-user-id',
    'testuser',
    '$argon2id$v=19$m=524288,t=2,p=1$c29tZXNhbHQxMjM0NTY3ODkwMTIzNDU$wA1qkO0rATEtNnS/xPbbgQ1234567890123456789012',
    'test@example.com',
    TRUE,
    NOW(),
    NOW()
)
ON CONFLICT (id) DO NOTHING;
