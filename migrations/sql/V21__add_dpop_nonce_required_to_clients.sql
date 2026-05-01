-- RFC 9449 §§8, 9: per-client opt-in to server-issued DPoP nonces.
-- When TRUE, the AS rejects DPoP proofs lacking a valid nonce and returns
-- `error: use_dpop_nonce` with a fresh `DPoP-Nonce` response header.
-- Defaults to FALSE so existing clients continue to work without churn.
ALTER TABLE clients ADD COLUMN dpop_nonce_required BOOLEAN NOT NULL DEFAULT FALSE;
