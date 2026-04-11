-- Add token_family column for refresh token rotation replay detection
-- (OAuth 2.0 Security BCP §4.13.2)
ALTER TABLE tokens ADD COLUMN token_family TEXT;
CREATE INDEX idx_tokens_token_family ON tokens(token_family);
