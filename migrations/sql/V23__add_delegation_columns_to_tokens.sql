-- RFC 8693 (Token Exchange) delegation, RFC 9449/RFC 8705 confirmation, and
-- RFC 8707 resource indicator persistence on issued tokens. These are stored
-- alongside the token row (not only embedded in JWT claims) so opaque access
-- tokens -- which have no JWT payload to decode -- can still surface them at
-- introspection time.
-- `act`: JSON-encoded actor claim (RFC 8693 §4.1), e.g. {"sub":"agent-1","iss":"..."}.
-- `cnf`: JSON-encoded confirmation claim (RFC 9449 §6 / RFC 8705 §3).
-- `resource`: JSON-encoded array of resource indicator URIs (RFC 8707).
-- NULL means none was set (all pre-existing rows).
ALTER TABLE tokens ADD COLUMN act TEXT;
ALTER TABLE tokens ADD COLUMN cnf TEXT;
ALTER TABLE tokens ADD COLUMN resource TEXT;
