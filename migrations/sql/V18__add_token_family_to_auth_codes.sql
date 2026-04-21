-- RFC 9700 §2.1.5: on authorization-code replay the AS MUST revoke every
-- token issued from that code. We implement this by tagging the code with
-- the same `token_family` UUID used by refresh-token rotation. On replay
-- detection the AS looks up the family from the used auth-code record and
-- cascade-revokes every access/refresh token in the family.
ALTER TABLE authorization_codes ADD COLUMN token_family TEXT;
