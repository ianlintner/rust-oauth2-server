## [1.1.0] — 2026-09-21

**Phase 7 — Agent & A2A Authorization.** AI agents (and agents calling
agents) can now obtain, delegate and chain OAuth tokens. Every capability
below is off by default and only advertised in discovery once its
`OAUTH2_*` flag is enabled — see [`docs/agents/README.md`](docs/agents/README.md)
for configuration and worked `curl` examples, and
[`docs/oauth2-spec-audit.md` §10](docs/oauth2-spec-audit.md#10-phase-7--agent--a2a-authorization)
for the full chunk tracker.

### Added

- RFC 8693 Token Exchange, fully implemented: `actor_token`/`act`/`may_act`
  delegation, actor-profile `act` chains (depth-limited via
  `OAUTH2_MAX_DELEGATION_DEPTH`), audience/resource validation against a new
  protected-resources registry, and RAR (RFC 9396) subset enforcement across
  exchanges.
- `act`, `cnf`, and `resource` are now persisted on tokens and exposed by
  introspection (`POST /oauth/introspect`).
- Protected-resource registry (`resources` table) with admin CRUD at
  `/admin/resources`, and per-resource Protected Resource Metadata at
  `GET /.well-known/oauth-protected-resource/{id}` (RFC 9728 §3.1).
- Trusted-issuer registry (`trusted_issuers` table) with admin CRUD at
  `/admin/trusted-issuers`, backing a new
  `urn:ietf:params:oauth:grant-type:jwt-bearer` authorization grant
  (RFC 7523 §2.1) with JIT user provisioning.
- Identity chaining and Identity Assertion Authorization Grant (ID-JAG)
  support (`draft-ietf-oauth-identity-chaining`,
  `draft-ietf-oauth-identity-assertion-authz-grant`): both acceptance (as an
  assertion on the jwt-bearer grant) and issuance (via token exchange with
  `requested_token_type=id-jag`), gated by `OAUTH2_ID_JAG_ENABLED`.
- Transaction Tokens (`draft-ietf-oauth-transaction-tokens`) with the
  draft-liu-oauth-a2a-profile claims (`purp`, immutable `tctx`), gated by
  `OAUTH2_TXN_TOKENS_ENABLED` and `OAUTH2_TRUST_DOMAIN`, requiring asymmetric
  client authentication.
- Transaction Authorization Challenge
  (`draft-rosomakho-oauth-txn-challenge`): `POST /oauth/transaction_authorization`,
  a human approval page, and a polling grant
  (`urn:ietf:params:oauth:grant-type:transaction-authorization`), gated by
  `OAUTH2_TAC_ENABLED`.
- Client ID Metadata Document (CIMD) support
  (`draft-ietf-oauth-client-id-metadata-document`): URL-shaped `client_id`s
  are resolved (SSRF-guarded, ≤5 KB, HTTPS-only) at `/authorize`, `/oauth/par`
  and `/oauth/token`, gated by `OAUTH2_CIMD_ENABLED` and capped by
  `OAUTH2_CIMD_MAX_CLIENTS`.
- Named-agent consent: `requested_actor` on `/authorize` plus `actor_token`
  at code exchange, so a consent screen can name the agent acting for the
  user, gated by `OAUTH2_AGENT_OBO_ENABLED`.
- Workload identity polish: SAN-based mTLS client auth
  (`tls_client_auth_san_uri`/`_dns`), RFC 7591 §2.3 software statements
  attested via trusted issuers, `sub_profile` classification (`user` /
  `service` / `ai_agent`) on access tokens, and an optional AI-agent
  access-token TTL cap (`OAUTH2_AI_AGENT_ACCESS_TOKEN_TTL_SECS`).
- DPoP `ath` claim validation on introspection and a storage-backed DPoP
  `jti` replay store (`dpop_jtis`), replacing the in-memory-only replay guard
  for multi-instance deployments.
- Migrations V23–V31 for all of the above (delegation columns on `tokens`,
  the `resources` and `trusted_issuers` tables, `allowed_actors` on
  `clients`, `requested_actor` on `authorization_codes`, `dpop_jtis`,
  `transaction_authorizations`, workload-identity columns, `cimd_managed`).

### Changed

Everything above is behind a flag. The changes in this section are **not** —
they apply to every deployment on upgrade.

- **Token endpoint.** A JWT client assertion's `aud` may now be either the
  issuer or the token endpoint URL (RFC 7523 §3 allows both; only the token
  endpoint was accepted before). `resource` and `audience` may be repeated,
  and the resulting access token carries a multi-valued `aud`.
- **Refresh rotation.** A refreshed token keeps the `act` chain of the token
  it replaces, so a delegation survives rotation instead of being silently
  dropped.
- **Introspection** responses gained `txn`, `purp` and `req_wl` for
  transaction tokens. `act` is returned only to an authenticated caller — it
  names the delegating agent, so it is PII on the same footing as `sub`.
- **Client registration.** A `software_statement` is now always verified,
  whether or not trusted issuers are configured; an unsigned or
  unknown-issuer statement is rejected with `invalid_software_statement`
  (previously it could be ignored). Self-service dynamic registration strips
  body-supplied `allowed_actors`, `software_id` and `software_version` —
  the last two are accepted only from a verified software statement, and the
  admin endpoint remains exempt. Selecting `tls_client_auth_san_uri` or
  `tls_client_auth_san_dns` requires a `tls_client_auth_san` value. The
  registration response gained three fields (`allowed_actors`,
  `software_id`, `software_version`), and an RFC 7592 update replaces
  `tls_client_auth_san` rather than merging it.
- **Discovery** (`/.well-known/openid-configuration` and
  `/.well-known/oauth-authorization-server`) gained `mtls_endpoint_aliases`
  and the two SAN client-authentication methods, and
  `authorization_details_types_supported` is now derived from the
  authorization-details types actually registered in the database rather
  than from a static list.
- **Login page** now names the client that initiated the authorization
  request (and the agent it asked to act, when `requested_actor` was used).
  Library API: `handlers::login::login_page` takes a `Session`.
- **Library API break (`oauth2-actix`).** `handlers::dpop::validate_dpop_proof`
  and `DpopReplayStore::check_and_insert` are now `async` (the replay store
  may hit the database), and `DpopReplayStore`'s fields are private —
  construct it with `new()` / `with_storage()`.
- `docs/oauth2-spec-audit.md` §1 (Current Implementation Inventory) corrected
  for Token Exchange, the JWT authorization grant, DPoP, mutual-TLS, and RFC
  9728 Protected Resource Metadata — these had shipped in earlier waves but
  §1 had gone stale.

### Security

Also always on, and rejections where previous versions accepted the request:

- **Token exchange hardening.** A `subject_token_type` of `jwt` requires the
  JOSE header to say `typ: "at+JWT"`. A refresh token is never accepted as a
  subject token (except on the ID-JAG path, where the draft calls for it). A
  subject token carrying `cnf` requires proof of possession — a DPoP proof or
  the matching mTLS certificate — at the exchange. Exchanging a token issued
  to a *different* client requires that client's `allowed_actors` to name the
  requesting client. The resulting scope must be a subset of the requesting
  client's own registered scope, not merely of the subject token's.
- **URL-shaped `client_id`s are rejected** with `invalid_client` unless CIMD
  is enabled, instead of being looked up as an opaque identifier.
- **The transaction-approval form fails closed:** only an explicit
  `action=approve` approves; any other (or absent) value denies.
- Trusted issuers are an explicit, admin-controlled registry (`allowed_audiences`,
  `subject_mapping`, `allowed_client_ids`, `jit_provision`); email-based
  subject mapping trusts the issuer to assert accurate local email addresses.
  See `docs/agents/README.md#security-considerations`.
- CIMD fetches are SSRF-guarded (loopback, private/link-local/CGNAT ranges
  blocked; HTTPS-only; no redirects; ≤5 KB); materialized `clients` rows are
  capped by `OAUTH2_CIMD_MAX_CLIENTS` and never overwrite operator-set fields
  on re-fetch — nor any client that was not itself created from a metadata
  document. Row cleanup is not yet automated — a documented follow-up.
  See `docs/agents/README.md#security-considerations`.
- RFC 9470 step-up enforcement for the Transaction Authorization Challenge is
  documented but not yet implemented — a documented follow-up.

## [1.0.0] — 2026-06-21

**Breaking changes — consolidates all Dependabot dependency upgrades into a single major release.**

### Dependencies upgraded (breaking)
- `redis` 0.27 → 1.2.3 — `AsyncCommands` single-key methods now require `ToSingleRedisArg` bound
- `lapin` 2.5 → 4.10 — `exchange_declare`/`basic_publish` args changed from `&str` to `ShortString`
- `sha2` 0.10 → 0.11 + `hmac` 0.12 → 0.13 — `digest` 0.11 coupling; `new_from_slice` moved to `KeyInit` trait
- `opentelemetry` / `opentelemetry_sdk` / `opentelemetry-otlp` 0.31 → 0.32
- `tracing-opentelemetry` 0.32 → 0.33 (bridges to otel 0.32)
- `lru` 0.16 → 0.18
- `cucumber` 0.22.1 → 0.23

### Non-breaking upgrades (also included)
- All minor and patch Dependabot bumps from PRs #318, #327, #332, #338–#346, #349

## [2026-W17] — 2026-04-20

- weekly reconciliation 2026-04-13 — Wave 2/3/4 RFCs, opaque tokens, PAR, JWT introspection (#69)
- setup caretaker (#72)
- add V16 OIDC session logout migration to k8s ConfigMap (#73)
- Pin caretaker install to v0.1.1 (#76)
- Bump caretaker runtime pin to v0.2.0 and fix related CI workflow failures (#78)
- Mitigate rand ThreadRng unsoundness path in OAuth token/code generation (#98)
- Fix Semgrep inline suppressions: move nosemgrep annotations onto flagged lines (#100)
- update caretaker to v0.2.1 and sync templates (#102)
- chore: improve `CLAUDE.md` with Karpathy-inspired behavioral guidelines for AI coding agents (Think Before Coding, Simplicity First, Surgical Changes, Goal-Driven Execution) (#104)
- upgrade rustls-webpki 0.103.10 → 0.103.12 (RUSTSEC-2026-0098, RUSTSEC-2026-0099) (#108)
- upgrade caretaker from 0.2.1 to 0.4.0 (#110)
- reconcile CHANGELOG — 2026-W16 (#111)
- reconcile CHANGELOG — 2026-W16 (#112)
- reconcile CHANGELOG — 2026-W16 (#114)
- upgrade caretaker to v0.5.2 (#115)
- upgrade caretaker from v0.4.0 to v0.5.2 (#117)
- reconcile CHANGELOG — 2026-W16 (#120)
- docs: reorganize README and docs to prioritize AI agent prompts and instructions before technical content; add agent-specific workflow examples (#125)
- reconcile CHANGELOG — 2026-W16 (#127)
- chore: update agent skill definitions and custom agent configurations for current Claude/Copilot tooling; add new agent workflows and MCP server configuration (#132)
- upgrade caretaker to v0.5.2 (#135)
- fix: repair broken cross-directory doc links in `AI_TOOLING_SUMMARY.md` and `ai-workflows/EXAMPLES.md` that caused MkDocs strict-mode CI failures (#139)
- security: Wave 2 hardening — CRITICAL + HIGH fixes (C1/C2/C3/H1–H5) (#142)
- upgrade caretaker to v0.6.4 (#146)
- upgrade caretaker from v0.6.4 to v0.6.5 (#149)
- upgrade caretaker from v0.6.5 to v0.7.2 (#151)
- chore: upgrade caretaker from v0.6.5 to v0.7.2 — backport of (#151) (#159)
- fix: correct caretaker package name from `caretaker` to `caretaker-github` in CI maintainer workflow (#160)
- upgrade caretaker to v0.9.0 (#162)
- chore: add `.prod.env` to `.gitignore` to prevent accidental commit of production environment secrets (#163)
- jti in introspection, device-flow Basic auth, DB URL redaction (#164)
- sort list queries application-side to avoid CosmosDB BadValue (#165)
- replace `sort_by` with `sort_by_key` in oauth2-storage-mongo to fix clippy CI (#168)
- Bearer token auth for admin API + MCP server admin tools (#170)
- rustfmt formatting in admin_guard.rs unblocks CI (#172)
- Tailwind UI overhaul, server-side paging, dark mode, new dashboards (#173)
- replace removed `upgrade-only` caretaker mode and pin kustomize installation (#178)
- modernize dashboard UI and fix broken latency charts (#179)
- resolve runtime errors breaking admin dashboard UI (#181)
- maintainer CRUD, denylist, audit log (V17) (#182)
- capabilities reflect storage backend (#183)
- http status_class counter + duration histogram (#184)
- update stale pinned action SHAs causing CI Scan job failure (#188)
- fanout admin audit to RecentEventsStore (#190)

## [2026-W19] — 2026-05-04

- sort SQL migrations numerically in benchmark harness (#280)
- upgrade pin v0.22.3 → v0.25.0 + thin workflow template (#281)
- [WIP] Fix missing required scopes for workflow token (#285)
- heal mixed BSON Date/String User timestamps (GitHub callback 500) (#288)
- extend tolerant DateTime + RFC 3339 writes to all models (#289)
- rebase-retry on Flux race; assert tag matches Cargo.toml (#290)
- reconcile CHANGELOG — 2026-W18 (#291)
- drop pip cache from setup-python (#292)
- remove obsolete .github/workflows/maintainer.yml (#293)
- RFC compliance matrix generator + 21-file annotation pass (#294)
- Update Kubernetes image references and OAuth2 URLs (#295)
- Implement server-issued DPoP nonces with client opt-in (#297)

## [2026-W18] — 2026-04-27

- replace removed `upgrade-only` caretaker mode and pin kustomize installation (#178)
- capabilities reflect storage backend (#183)
- http status_class counter + duration histogram (#184)
- update stale pinned action SHAs causing CI Scan job failure (#188)
- wire oauth_authorization_codes_issued counter (#189)
- fanout admin audit to RecentEventsStore (#190)
- wire oauth_failed_authentications counter (#191)
- wire oauth_token_revoked_total counter (#192)
- reconcile CHANGELOG — 2026-W17 (#193)
- RFC 9700 Phase 6 hardening — audience wiring, 303 redirect, conformance tests (#196)
- RFC 9700 Phase 6.4 — configurable token TTLs (#197)
- RFC 9700 Phase 6.8 — application-layer HTTPS enforcement (#198)
- RFC 9700 Phase 6.11 — scope introspection PII (#199)
- RFC 9700 Phase 6.1 — cascade-revoke tokens on auth-code replay (#200)
- RFC 9700 Phase 6.5 — reject replayed client_assertion jti (#201)
- upgrade caretaker from v0.9.0 to v0.10.1 (#203)
- RFC 9700 Phase 6.13 — RFC 8252 native-app redirect tightening (#204)
- paved-path baseline metrics + k8s scrape annotations (#205)
- accept HTTP 303 from login endpoint in e2e KIND scripts (#208)
- e2e login check expects HTTP 303 after RFC 9700 §4.11 hardening (#209)
- RFC 9700 Phase 6.6 — per-client require_state policy flag (#210)
- upgrade caretaker from v0.10.1 to v0.10.2 (#212)
- RFC 9700 Phase 6.9 — token-endpoint rate limiting + invalid_client penalty bucket (#213)
- key invalid_client bucket by client_id, not peer IP (Istio-safe) (#214)
- bridge EventActor to RecentEventsStore so admin Events page shows OAuth flow events (#215)
- Redis-backed RecentEventsStore for cross-replica admin Events visibility (#216)
- correct Events table field paths for EventEnvelope structure (#219)
- gate `REDIS_KEY` constant behind `redis-cache` feature flag (#227)
- OTEL Wave 1 — OTLP export, tracecontext propagation, log↔trace linking (#228)
- GitOps + image automation for bigboy AKS (#230)
- app_info version reads workspace root (#233)
- pin production postgres-pvc to managed-premium storage class (#235)
- replace commonLabels with labels block in production overlay (#236)
- remove postgres/pgbouncer stack, rightsize CPU requests (#237)
- resolve value+valueFrom conflict in e2e-kind Deployment manifest (#244)
- skip postgres/flyway wait when StatefulSet not deployed (#250)
- enable fleet registry heartbeats (#253)
- upgrade caretaker from v0.19.4 to v0.19.6 (#256)
- adopt v0.20.0 fleet workflow (OAuth2 envs) (#257)
- adopt OAuth2 fleet_registry config (v0.20) (#258)
- resolve caretaker bootstrap-check failures blocking CI (#260)
- stylize SSO login and error pages with light/dark mode (#261)
- k8s: add SecretProviderClass and wire Google/GitHub OAuth2 env vars (#262)
- RFC 9700 — mTLS Subject DN validation (RFC 8705 §2.1) + DPoP-bound introspection (RFC 9449 §7.1) (#263)
- upgrade caretaker from v0.19.6 to v0.22.3 (#270)
- route all scan configs to SQLite instead of MongoDB (#271)
- sort SQL migrations numerically in benchmark harness (#280)
- upgrade pin v0.22.3 → v0.25.0 + thin workflow template (#281)
- [WIP] Fix missing required scopes for workflow token (#285)
- heal mixed BSON Date/String User timestamps (GitHub callback 500) (#288)
- extend tolerant DateTime + RFC 3339 writes to all models (#289)

## [2026-W16] — 2026-04-17

- docs: weekly reconciliation 2026-04-09 — client auth defaults, revoke example, benchmark CI (#60)
- feat: add LLM-driven security scanning framework — Kustomize K8s config variants (prod-hardened, dev-relaxed, misconfig), OAuth2 flow/timing/entropy/error-leakage scanners, CI validation workflow (#61)
- fix: restore Semgrep code scanning workflow using modern `semgrep/semgrep` container with SARIF upload to GitHub code scanning (#62)
- security: address 56 Semgrep findings — fix shell injection, root containers, K8s securityContext; annotate intentional test fixtures (#64)
- feat: Wave 2 — OIDC Core Compliance & Refresh Token Security: refresh token rotation with replay detection (token family lineage), nonce round-trip, `c_hash` claim in ID tokens (#65)
- docs: add comprehensive OAuth 2.0 specification audit and roadmap (`docs/oauth2-spec-audit.md`) — 30+ RFC gap analysis, stack-ranked missing features, phased implementation plan (#66)
- feat: implement Wave 2 RFC Additions — Dynamic Client Registration (RFC 7591), Dynamic Client Management (RFC 7592), JWT client authentication `private_key_jwt`/`client_secret_jwt` (RFC 7523) (#67)
- docs: weekly reconciliation 2026-04-13 — Wave 2/3/4 RFC coverage, opaque tokens, Pushed Authorization Requests (PAR/RFC 9126), JWT introspection (#69)
- fix: add `adduser` package to Dockerfile runtime stage for `debian:trixie-slim` (#70)
- chore: set up Caretaker autonomous repo maintenance system — weekly GitHub Actions orchestrator, Copilot agent instruction files for PR/issue/upgrade tasks (#72)
- fix: add V16 OIDC session logout migration to Kubernetes ConfigMap — resolves missing `backchannel_logout_uri` column in PostgreSQL deployments (#73)
- chore: pin caretaker install to v0.1.1 for reproducible CI (#76)
- chore: bump caretaker runtime pin to v0.2.0; fix maintainer workflow `403` assignee error and e2e-kind `curl` exit-code 23 (#78)
- security: replace `rand::ThreadRng` with `StdRng::from_os_rng()` in OAuth token/code generation paths to eliminate ThreadRng unsoundness under reentrancy (#98)
- fix: move Semgrep `nosemgrep` suppression annotations onto flagged lines — resolves 20 previously un-suppressed code scanning alerts (#100)
- chore: update caretaker to v0.2.1 and sync CI workflow templates (#102)
- chore: improve `CLAUDE.md` with Karpathy-inspired behavioral guidelines for AI coding agents (Think Before Coding, Simplicity First, Surgical Changes, Goal-Driven Execution) (#104)
- fix: upgrade `rustls-webpki` 0.103.10 → 0.103.12 (RUSTSEC-2026-0098: URI name constraints bypass; RUSTSEC-2026-0099: wildcard certificate name constraint bypass) (#108)
- chore: upgrade caretaker from 0.2.1 to 0.4.0 — updates orchestrator workflow, agent instruction templates, and CI pin (#110)
- docs: reconcile CHANGELOG — 2026-W16, adding expanded descriptions for PRs #60–#110 (#111)
- docs: reconcile CHANGELOG — 2026-W16, consolidate duplicate sections and expand cryptic titles (#112)
- docs: reconcile CHANGELOG — 2026-W16, further consolidation pass (#114)
- chore: upgrade caretaker to v0.5.2 (#115)
- chore: upgrade caretaker from v0.4.0 to v0.5.2 — updates orchestrator workflow and agent instruction templates (#117)
- docs: reconcile CHANGELOG — 2026-W16 (#120)
