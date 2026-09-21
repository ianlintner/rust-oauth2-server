# Agent & A2A OAuth Roadmap — Design Draft for Review

**Status:** APPROVED for implementation (decisions D1–D7 resolved per recommendations, 2026-09-21)  
**Date:** 2026-09-21  
**Scope:** Extend rust-oauth2-server so AI agents (and agents calling agents) can obtain, delegate and chain OAuth tokens using the specs that have solidified as of September 2026, while keeping speculative drafts behind flags or out of scope.

This document is a *roadmap + design*, not an implementation plan. Once approved, each phase becomes its own spec/plan cycle. It is numbered **Phase 7** to follow Phases 1–6 in `docs/oauth2-spec-audit.md`.

---

## 1. Research Summary — what has actually solidified

Ranked by standards maturity. "Build on" means we should implement it as written; "flagged" means implement behind a feature flag with a clear note that parameter names may change; "watch" means do not build yet.

### 1.1 Published RFCs (build on)

| Spec | Role in agent flows | Status in this repo |
|---|---|---|
| RFC 8693 Token Exchange | The backbone of every delegation / on-behalf-of / chaining flow. `act` (actor) and `may_act` claims, `actor_token`, `audience`, `resource`. | **Stub only.** `actor_token` not validated, `act` never placed in the JWT, no `may_act`, no `audience`, token types ignored (`crates/oauth2-actix/src/handlers/oauth.rs:2194-2313`). |
| RFC 9449 DPoP | Sender-constraining agent tokens; required for key binding in ID-JAG and TAC. | Implemented incl. nonce. Gaps: no `ath`, in-memory replay store, `cnf` not persisted for opaque tokens. |
| RFC 8705 mTLS | Workload-style client auth, certificate-bound tokens. | Implemented via proxy headers. No SAN-based variants (`tls_client_auth_san_uri` is the SPIFFE path). |
| RFC 8707 Resource Indicators | MCP mandates `resource` on every request; audience-restriction is the #1 control for agents. | Implemented but single-valued; no allowlist; not persisted on `Token`. |
| RFC 9396 RAR | Task-scoped agent authorization; used by ID-JAG, TAC, transaction tokens. | Parsed and embedded; no type validation, dropped on exchange/refresh. |
| RFC 9728 Protected Resource Metadata | MCP servers MUST publish it; MCP clients discover the AS through it. | Implemented; `resource` hardcoded to issuer. |
| RFC 7523 JWT client auth + **JWT authorization grant** | `private_key_jwt` for agents; the jwt-bearer *grant* is how identity chaining and ID-JAG land at the receiving AS. | Client auth done. **Grant missing.** |
| RFC 9470 Step-up | Human re-auth for sensitive agent actions. | Advertised, not enforced. |

### 1.2 IETF working-group documents, standards-track (build on)

| Draft | Maturity (Sept 2026) | What it gives agents |
|---|---|---|
| **draft-ietf-oauth-identity-chaining-17** | Approved as Proposed Standard, in RFC Editor queue. | Cross-trust-domain delegation: token exchange at AS-A yields a JWT authorization grant with `aud` = AS-B; AS-B accepts it via jwt-bearer grant. Metadata `identity_chaining_requested_token_types_supported`. |
| **draft-ietf-oauth-identity-assertion-authz-grant-04 (ID-JAG)** | WG document, May 2026, standards track. Authors: Parecki, McGuinness, Campbell. | Profile of identity chaining for enterprise SSO → agent → SaaS API. Defines `urn:ietf:params:oauth:token-type:id-jag`, `typ: oauth-id-jag+jwt`, claims (`iss, sub, aud, client_id, jti, exp, iat, scope, resource, authorization_details, cnf, act`), metadata `authorization_grant_profiles_supported`. |
| **draft-ietf-oauth-transaction-tokens-11** | Past WG Last Call (ended 2026-08-18), in write-up. | Short-lived intra-domain tokens carrying `txn`, `sub`, `aud` (trust domain), `scope`, `req_wl`, `tctx`, `rctx`. Issued via token exchange with `requested_token_type = urn:ietf:params:oauth:token-type:txn_token`. Replacement-token rules. |
| **draft-ietf-oauth-client-id-metadata-document-02 (CIMD)** | WG document. MCP authorization spec says AS **SHOULD** support it and marks DCR *deprecated*. | `client_id` is an HTTPS URL pointing at a JSON metadata document. AS fetches it (SSRF-guarded, ≤5 KB, no redirects), validates `client_id` equality and redirect URIs, advertises `client_id_metadata_document_supported: true`. Only `none` or `private_key_jwt` auth. |
| draft-ietf-wimse-aims-00 | WG-adopted architecture doc (Sept 2026). | Not a protocol; says: agent = OAuth client with asymmetric auth (JWT / mTLS / SPIFFE), short-lived tokens, `client_id` = agent identity, `sub` = delegated user, token exchange across domains, CIBA for step-up. Use as the *design reference*, not as a feature. |
| draft-ietf-oauth-rfc7523bis | WG. | Tightens JWT client auth (`aud` = issuer/token endpoint, `typ`). Fold into 7.A validation rules. |
| MCP Authorization spec (draft revision, 2026) | De-facto ecosystem standard for agent tooling. | AS must be OAuth 2.1 + RFC 8414 (or OIDC discovery) + PKCE + `resource` + `iss`; SHOULD CIMD; MAY DCR. Scope challenge via `WWW-Authenticate` on 401/403 (RS-side). |

### 1.3 Individual drafts, promising (flagged)

| Draft | Why promising | Why flagged |
|---|---|---|
| **draft-mcguinness-oauth-actor-profile-00** (Apr 2026) | Defines a *consistent* `act` object across JWT grants, access tokens and txn tokens: `act.sub` + `act.iss` required, `sub_profile` (user / service / ai_agent), nested chains, chain-validation algorithm, depth limit (≥4), presenter continuation vs rebind for `cnf`. Written by an ID-JAG author; aligns with the WG direction. | Individual submission, -00. Safe to adopt its `act` shape because it is a strict superset of RFC 8693. |
| **draft-rosomakho-oauth-txn-challenge-00 (TAC)** (Jun 2026) | Human-in-the-loop for agents: RS returns a signed challenge JWT; client submits it to a new `transaction_authorization_endpoint`; polling like device flow; approved token carries `txn` + `authorization_details`. Authors: Rosomakho, Campbell, McGuinness, Kasselman. | -00, individual, but the only concrete HITL proposal from WG-core authors. |
| **draft-oauth-ai-agents-on-behalf-of-user-02** (WorkOS article) | `requested_actor` on `/authorize` so the consent screen names the agent; `actor_token` at code exchange; `act.sub` in access token. Simple, MCP-friendly. | Expired (Aug 2025), not adopted. Parameter names may change. |
| **draft-liu-oauth-a2a-profile-00** (the draft you linked) | Profile of transaction tokens for A2A: `purp` = A2A task id, `tctx` = immutable user input (`request_details`), `rctx` = mutable agent context (`request_context`). | Expired Apr 2026, thin (no security section, no IANA). Cheap to support once transaction tokens exist: it is a claim convention, not a protocol. |
| draft-araut-oauth-transaction-tokens-for-agents-01 | Adds `actor` / `principal` / `agentic_ctx` to txn tokens. | Individual; overlaps with actor-profile. Support `actor`/`principal` mapping only. |

### 1.4 Watch list (do not build now)

- **draft-rosenberg-oauth-aauth-00** (the second link you sent): new `agent_authorization` grant, agent submits *user PII collected in conversation* which the AS matches against its user DB; polling / SSE / WebSocket delivery; RS publishes `/.well-known/aauth.json`. Expired Jan 2026, no WG traction, no PoP, no token exchange, and the PII-matching model conflicts with this server's security posture. The *useful* idea (async user approval with polling) is covered better by TAC + our existing device-flow machinery.
- draft-aap-oauth-profile-01 (expired), draft-niyikiza attenuating agent tokens (macaroon-style, individual), draft-liu-oauth-chain-delegation-00 (`delegation_chain` claim, overlaps with nested `act`), draft-embesozzi agent-native authorization (depends on First-Party Apps, which we do not implement), draft-yakung agent attestation (ACAP), draft-klrc-aiagent-auth (replaced by wimse-aims).

---

## 2. Design Principles

1. **Token exchange is the primitive.** Every agent flow above reduces to "validate an inbound token, apply policy, mint a narrower token with a delegation chain". Fix RFC 8693 first; everything else composes on it.
2. **One `act` shape everywhere.** Adopt the actor-profile object (`{sub, iss, sub_profile?, act?}`) for access tokens, ID-JAGs, and transaction tokens. Never emit `act` without a validated delegation basis.
3. **Audience-restrict by default.** Multi-valued `resource`/`audience`, validated against a registry of known resource servers, persisted on the token, echoed in introspection.
4. **Flag anything not WG-adopted.** `OAUTH2_AGENT_FEATURES` (or per-feature env vars) gate 7.C, 7.E-profile and 7.F. Discovery only advertises what is enabled.
5. **No new UI frameworks.** Consent and approval pages reuse the existing login/device-verify templates.
6. **Every phase ships with `tests/rfc_compliance.rs`-style tests** built inline per the pattern in `CLAUDE.md`, plus a new `tests/agent_delegation.rs`.

---

## 3. Phased Roadmap

Effort key: XS < 1 day, S 1–2 days, M 3–5 days, L 1–2 weeks (single engineer with agent assistance).

### Phase 7.A — Make Token Exchange Real (foundation) — **L**

Goal: RFC 8693 conformance with the actor-profile `act` shape. Unblocks everything after it.

| # | Item | Notes |
|---|---|---|
| 7.A.1 | Validate `subject_token_type` / `actor_token_type` | Accept `access_token`, `jwt` (our own JWTs), `id_token`; reject `refresh_token` (RFC 8693 §2.1, txn-tokens forbid it). Unknown → `invalid_request`. |
| 7.A.2 | Validate `actor_token` | Must be a valid, unexpired token (opaque lookup or JWT verify). Extract actor `sub`/`client_id`. Reject if missing when policy requires delegation. |
| 7.A.3 | Build `act` per actor-profile | `{ "sub": <actor>, "iss": <issuer>, "sub_profile": "ai_agent"|"service"|"user" }`. If the subject token already has `act`, nest it unchanged. Enforce `OAUTH2_MAX_DELEGATION_DEPTH` (default 4). |
| 7.A.4 | `may_act` enforcement | If the subject token carries `may_act`, the actor must match `(iss, sub)`. Add per-client `allowed_actors` (JSON list of client_ids) as the server-side policy source. **Decision D2.** |
| 7.A.5 | `act` into the JWT | Add `act` to `CreateToken` (`token_actor.rs`) and remove the non-standard top-level `act` member from the token response body. |
| 7.A.6 | `audience` + multi-valued `resource` | Parse repeated params; validate each against a `resources` registry (see 7.B.3) or a config allowlist; set `aud` to the union; must be a subset of the subject token's audience unless policy allows widening (default deny). |
| 7.A.7 | Carry `authorization_details` through exchange | Requested RAR must be a subset of the subject token's RAR (per-type equality for now). |
| 7.A.8 | Persist delegation on `Token` | Migration **V22**: add `act` (JSON), `cnf` (JSON), `resource` (JSON array) to `tokens`. Update sqlx (SQLite + Postgres) and Mongo. Introspection returns `act` (RFC 8693 §4.1 allows it) and `cnf`. Fixes the opaque-token DPoP gap too. |
| 7.A.9 | DPoP on exchange | Apply actor-profile "presenter rebind": when a DPoP proof accompanies the exchange, bind the new token to *its* `jkt`; otherwise continue the subject token's `cnf`. |
| 7.A.10 | `requested_token_type` validation | Accept `access_token`, `jwt`; other values return `invalid_request` until 7.D/7.E add them. |
| 7.A.11 | rfc7523bis alignment | Tighten JWT client assertion `aud` to issuer or token endpoint, require `typ` if present. |

Tests: subject/actor validation matrix, nested `act` depth, `may_act` mismatch → `invalid_grant`, audience widening → `invalid_target`, introspection shows `act`.

### Phase 7.B — MCP-ready onboarding (CIMD + resource registry) — **M**

Goal: an MCP client or agent framework with no prior relationship can use this server per the MCP authorization spec.

| # | Item | Notes |
|---|---|---|
| 7.B.1 | Client ID Metadata Documents | Detect URL-shaped `client_id` at `/authorize`, `/par`, `/token`. Fetch with: https only, path required, no redirects followed, ≤5 KB, `application/json`, SSRF guard (block RFC 6890 special-use addresses, loopback in prod), cache per HTTP headers with a max TTL, never cache errors. Validate `client_id` equality, `redirect_uris` exact match, `token_endpoint_auth_method` ∈ {`none`, `private_key_jwt`}. Feature flag `OAUTH2_CIMD_ENABLED` (default off), optional host allowlist/denylist. Consent page shows the `client_id` hostname next to `client_name`. |
| 7.B.2 | Discovery | `client_id_metadata_document_supported: true` when enabled. |
| 7.B.3 | Protected-resource registry | New table `resources` (migration **V23**): `resource_uri`, `name`, `scopes`, `authorization_details_types`, optional `txn_challenge_jwks_uri`. Drives 7.A.6 audience validation and makes `/.well-known/oauth-protected-resource` serve per-resource metadata (`/.well-known/oauth-protected-resource/{path}` per RFC 9728 §3.1). Admin CRUD under `/admin/resources`. |
| 7.B.4 | DPoP `ath` + shared replay store | Add `ath` handling and a storage-backed `jti` replay store so multi-instance deployments are safe for agent traffic. |

### Phase 7.C — Named-agent consent (on-behalf-of user) — **M**, flagged

Goal: a user sees *which agent* will act for them and the issued token records it. Implements draft-oauth-ai-agents-on-behalf-of-user semantics using the 7.A `act` machinery.

| # | Item | Notes |
|---|---|---|
| 7.C.1 | `requested_actor` on `/authorize` and PAR | Must be a registered client (or CIMD URL). Persist on the authorization code (migration **V24**). Consent page: "App X wants Agent Y to access …". |
| 7.C.2 | `actor_token` at code exchange | Required when the code has `requested_actor`. Validated as in 7.A.2; its subject must equal `requested_actor`. |
| 7.C.3 | Issue token with `act` | `sub` = user, `client_id`/`azp` = client, `act = {sub: agent, iss, sub_profile: "ai_agent"}`. |
| 7.C.4 | Refresh preserves `act` | Refresh grant copies `act` from the parent token (needs 7.A.8). |
| 7.C.5 | Flag + discovery | `OAUTH2_AGENT_OBO_ENABLED`; when on, advertise `requested_actor_parameter_supported: true` (non-standard, documented as such). |

**Decision D1** covers whether to do this phase at all versus relying on token exchange alone.

### Phase 7.D — Cross-domain chaining (Identity Chaining + ID-JAG) — **L**

Goal: this server can act as **either** side of identity chaining: the IdP that mints a JWT authorization grant / ID-JAG, and the resource AS that accepts one.

| # | Item | Notes |
|---|---|---|
| 7.D.1 | JWT-bearer **authorization grant** | `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` with `assertion`. New table `trusted_issuers` (migration **V25**): `issuer`, `jwks_uri`, `allowed_audiences`, `subject_mapping` (`sub` | `email` | `aud_sub`), `jit_provision: bool`, `allowed_client_ids`. Validate `iss` ∈ registry, signature via cached JWKS, `aud` = our issuer or token endpoint, `exp`, `jti` replay. No refresh token issued (identity-chaining MUST). |
| 7.D.2 | ID-JAG acceptance profile | On top of 7.D.1: require `typ: oauth-id-jag+jwt`, `client_id` claim = authenticated client, honor `scope`/`resource`/`authorization_details` (narrow only), `cnf.jkt` must match the presented DPoP proof, preserve `act`. Metadata `authorization_grant_profiles_supported: ["urn:ietf:params:oauth:grant-profile:id-jag"]`. |
| 7.D.3 | Issuing side | Token exchange with `requested_token_type` = `urn:ietf:params:oauth:token-type:jwt-authz-grant` (identity chaining) or `…:id-jag`; `audience` = target AS issuer (must be in a `chaining_targets` allowlist). Mint per ID-JAG claim rules; `cnf.jkt` from DPoP proof. Metadata `identity_chaining_requested_token_types_supported`. |
| 7.D.4 | Errors | `invalid_grant`, `insufficient_user_authentication` (+ `max_age`) per ID-JAG §7. |

### Phase 7.E — Transaction Tokens + A2A profile — **L**

Goal: act as a Transaction Token Service for intra-domain agent call chains, with the draft-liu A2A claim convention on top.

| # | Item | Notes |
|---|---|---|
| 7.E.1 | `requested_token_type = …:txn_token` | Requesting workload must authenticate with `private_key_jwt` or mTLS (spec MUST). `audience` = trust-domain id (config `OAUTH2_TRUST_DOMAIN`). Subject token: our access token or JWT. |
| 7.E.2 | Txn-Token JWT | Header `typ: txntoken+jwt`, claims `txn` (uuid), `sub`, `aud`, `iat`, `exp` (short, default 300 s), `scope` (⊆ subject), `req_wl` (= authenticated client), `tctx` ← `request_details`, `rctx` ← `request_context`, optional `purp`. Signed with the existing key set; never contains the inbound access token. |
| 7.E.3 | Replacement tokens | Subject token of type `txn_token`: preserve `txn`, `sub`, `aud`; scope narrow-only; reject expired. |
| 7.E.4 | A2A profile (draft-liu) | Flag `OAUTH2_A2A_PROFILE_ENABLED`. When the request carries `purp`, set `purp` = supplied task id; validate `request_details` JSON is unchanged across replacements (immutability MUST). Map `actor`/`principal` from `act` for draft-araut compatibility. |
| 7.E.5 | Introspection | `txn_token` introspection returns `txn`, `purp`, `req_wl`. |

### Phase 7.F — Human-in-the-loop (Transaction Authorization Challenge + step-up) — **M**, flagged

Goal: an agent that hits a sensitive operation can obtain explicit user approval without embedding the user in the agent's channel.

| # | Item | Notes |
|---|---|---|
| 7.F.1 | `transaction_authorization_endpoint` | Accepts `transaction_challenge` (JWT signed by an RS registered in 7.B.3 with `txn_challenge_jwks_uri`). Validate `iss`, `aud` = our issuer, `exp`, `jti`, required `authorization_details` + `reason`. Returns `transaction_authorization_id`, `expires_in`, `interval`. |
| 7.F.2 | Approval UI + polling | Reuse the device-flow store/verify page: show `reason`, `authorization_details`, requesting client, and `act` (agent) if present. Client polls the token endpoint with a new grant `urn:ietf:params:oauth:grant-type:transaction-authorization` (draft name) until approved. |
| 7.F.3 | Issued token | Short-lived, carries `txn` from the challenge and the approved `authorization_details`; DPoP-bound if the client used DPoP. |
| 7.F.4 | RFC 9470 step-up enforcement | Honor `acr_values`/`max_age` on token exchange and TAC; return `insufficient_user_authentication` with `acr_values`/`max_age`. |
| 7.F.5 | Metadata | `transaction_authorization_endpoint` in discovery; PRM adds `txn_challenge_jwks_uri`, `txn_challenge_signing_alg_values_supported` per resource. |

**Decision D4** covers whether CIBA is also wanted.

### Phase 7.G — Workload identity polish — **S–M**, later

- `tls_client_auth_san_uri` / `_san_dns` so SPIFFE IDs can authenticate agents (RFC 8705 §2.1.2); `mtls_endpoint_aliases` in discovery.
- `software_statement` / `software_id` / `software_version` on dynamic registration for attested agent frameworks.
- Top-level `sub_profile` claim on access tokens when the entity type is known.
- Default token lifetime overrides for `sub_profile = ai_agent` clients.

### Suggested order

7.A → 7.B → 7.D → 7.E → 7.F → 7.C → 7.G.  
Rationale: A is prerequisite for all; B makes the server usable by the MCP ecosystem today; D and E are on the standards track and reuse A directly; F is the most useful flagged draft; C is flagged and partially redundant with A; G is polish.

If you want the WorkOS-style demo first, the order 7.A → 7.C → 7.B is also coherent.

---

## 4. Cross-cutting Changes

- **Config** (`crates/oauth2-config`): `OAUTH2_MAX_DELEGATION_DEPTH`, `OAUTH2_TRUST_DOMAIN`, `OAUTH2_CIMD_ENABLED`, `OAUTH2_CIMD_ALLOWED_HOSTS`, `OAUTH2_AGENT_OBO_ENABLED`, `OAUTH2_A2A_PROFILE_ENABLED`, `OAUTH2_TXN_TOKEN_TTL_SECS`, `OAUTH2_TAC_ENABLED`.
- **Migrations:** V22 tokens (`act`, `cnf`, `resource`), V23 `resources`, V24 auth codes (`requested_actor`), V25 `trusted_issuers`, plus `allowed_actors` on `clients`. Each needs sqlx SQLite + Postgres and Mongo per `CLAUDE.md` pitfall 3.
- **Core models:** `Actor` struct (`sub`, `iss`, `sub_profile`, `act: Option<Box<Actor>>`) in `oauth2-core` with `depth()`, `outermost()`, `validate_chain()`. `Claims` gains `may_act`, `txn`, `purp`, `req_wl`, `tctx`, `rctx`, `sub_profile` (all optional, `skip_serializing_if`).
- **Discovery:** only advertise enabled features; add `grant_types_supported` entries (`jwt-bearer`, `transaction-authorization`), `identity_chaining_requested_token_types_supported`, `authorization_grant_profiles_supported`, `client_id_metadata_document_supported`, `transaction_authorization_endpoint`.
- **Docs:** update `docs/oauth2-spec-audit.md` §1 (stale: still lists token exchange/DPoP/mTLS as missing) and add a §10 Phase 7 tracker.
- **Observability:** metrics for exchanges by `(subject_type, actor present, depth)`, CIMD fetch outcomes, TAC approvals/denials.

---

## 5. Decisions (resolved 2026-09-21 — recommendation column is the adopted choice)

| ID | Question | Options | My recommendation |
|---|---|---|---|
| D1 | Build the `requested_actor` consent extension (7.C)? | (a) Yes, flagged. (b) Skip; rely on token exchange + `act` for auditability. | (a) if you want the consent screen to name the agent (the WorkOS use case); otherwise (b) and save ~4 days. |
| D2 | Where does actor authorization policy live? | (a) `may_act` in the subject token only. (b) Per-client `allowed_actors` registry only. (c) Both, either satisfies. | (c): `may_act` for user-consented delegation, registry for service-to-service. |
| D3 | Trust registries as DB tables with admin CRUD, or env/config only? | Tables (`resources`, `trusted_issuers`) vs `OAUTH2_*` JSON env. | Tables, since Mongo and sqlx backends already exist and admin UI exists. |
| D4 | Human-in-the-loop: TAC only, or also CIBA (OpenID)? | TAC only / both / defer both. | TAC only now; CIBA later if a concrete client needs it. |
| D5 | Transaction tokens (7.E): in this roadmap or a separate one? | Include / defer. | Include; it is post-WGLC and the A2A draft you cited is a profile of it. |
| D6 | Adopt actor-profile `act` shape (`act.iss` required) even though it is an individual draft? | Yes / RFC 8693 minimal `{sub}` only. | Yes; it is a superset and what ID-JAG and TAC already reference. |
| D7 | Persist `act`/`cnf`/`resource` on `tokens` (V22)? | Yes / JWT-only. | Yes; otherwise opaque-token mode silently loses delegation and PoP binding. |

---

## 6. Non-goals

- Implementing the AAuth PII-matching grant.
- A generic policy engine (Rego etc.); policy stays as scope/RAR subset checks plus registries.
- Acting as an MCP *resource server* (the `mcp-server/` directory stays a thin client).
- SAML subject tokens.

---

## 7. Sources

- draft-liu-oauth-a2a-profile-00 — https://www.ietf.org/archive/id/draft-liu-oauth-a2a-profile-00.html
- WorkOS, OAuth on-behalf-of for AI agents — https://workos.com/blog/oauth-on-behalf-of-ai-agents
- draft-oauth-ai-agents-on-behalf-of-user-02 — https://datatracker.ietf.org/doc/draft-oauth-ai-agents-on-behalf-of-user/
- draft-ietf-oauth-identity-chaining-17 — https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/
- draft-ietf-oauth-identity-assertion-authz-grant-04 — https://www.ietf.org/archive/id/draft-ietf-oauth-identity-assertion-authz-grant-04.html
- draft-ietf-oauth-transaction-tokens-11 — https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11
- draft-ietf-oauth-client-id-metadata-document-02 — https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html
- draft-mcguinness-oauth-actor-profile-00 — https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-actor-profile-00
- draft-rosomakho-oauth-txn-challenge-00 — https://datatracker.ietf.org/doc/draft-rosomakho-oauth-txn-challenge/
- draft-araut-oauth-transaction-tokens-for-agents — https://datatracker.ietf.org/doc/draft-araut-oauth-transaction-tokens-for-agents/
- draft-ietf-wimse-aims-00 — https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/
- draft-rosenberg-oauth-aauth-00 — https://www.ietf.org/archive/id/draft-rosenberg-oauth-aauth-00.html
- MCP Authorization (draft) — https://modelcontextprotocol.io/specification/draft/basic/authorization
- MCP Client Registration — https://modelcontextprotocol.io/specification/draft/basic/authorization/client-registration
- OAuth 2.1 for agent builders — https://www.agenticfabriq.com/blog/oauth-2-1-for-agent-builders
- Duende, Summer 2026 identity standards recap — https://duendesoftware.com/blog/20260820-summer-2026-identity-standards-recap
