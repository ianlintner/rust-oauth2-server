-- Add token_endpoint_auth_method to support public clients (RFC 7591 §2).
-- Default to 'client_secret_basic' for all existing clients.
ALTER TABLE clients ADD COLUMN token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic';
