-- RFC 9449 §10: DPoP-bound authorization codes. When the authorization
-- request carries a `dpop_jkt` parameter (or a DPoP proof at PAR), the AS
-- records the JWK SHA-256 thumbprint (RFC 7638) here so the token endpoint
-- can require that the code redemption is presented with a DPoP proof whose
-- key matches. NULL means the code is not DPoP-bound (all pre-existing rows).
ALTER TABLE authorization_codes ADD COLUMN dpop_jkt TEXT;
