-- Phase 7 (agent/A2A OAuth) — workload identity polish.
--
-- `tls_client_auth_san` (RFC 8705 §2.1.2): the expected subjectAltName of the
-- client's TLS certificate. Compared verbatim against the value the reverse
-- proxy forwards in `X-SSL-Client-SAN-URI` / `X-SSL-Client-SAN-DNS` when the
-- client authenticates with `tls_client_auth_san_uri` / `tls_client_auth_san_dns`.
--
-- `software_id` / `software_version` (RFC 7591 §2): identify the software the
-- client is an instance of. A `software_id` beginning with `agent:` marks the
-- client as an AI agent, which selects the `ai_agent` `sub_profile` (and the
-- optional AI-agent access-token TTL cap) for client-credential tokens.
--
-- All three default to the empty string so existing clients are unaffected.
ALTER TABLE clients ADD COLUMN tls_client_auth_san TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN software_id TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN software_version TEXT NOT NULL DEFAULT '';
