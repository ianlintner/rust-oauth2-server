# Phase 7 — Agent & A2A OAuth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement every item of Phase 7 in `docs/superpowers/specs/2026-09-21-agent-a2a-oauth-roadmap-design.md` (7.A–7.G) so AI agents can obtain, delegate and chain tokens per RFC 8693, identity chaining / ID-JAG, transaction tokens (+ A2A profile), CIMD, the Transaction Authorization Challenge, and named-agent consent.

**Architecture:** Token exchange becomes the primitive (new `token_exchange.rs` module with a `requested_token_type` dispatch table). A single `Actor` type in `oauth2-core` carries the delegation chain everywhere. New registries (`resources`, `trusted_issuers`) and per-client policy (`allowed_actors`) drive authorization decisions. Everything not WG-adopted is behind an `AgentConfig` flag and only advertised in discovery when enabled.

**Tech Stack:** Rust 2021, actix-web 4, actix actors, sqlx (SQLite + Postgres), mongodb, jsonwebtoken, reqwest 0.12 (rustls), serde_json. Tests: `#[actix_web::test]` integration tests in `tests/`, cargo-nextest.

## Global Constraints

- Every migration is a new file `migrations/sql/V<n>__<desc>.sql` AND the matching `CREATE TABLE` / idempotent `ALTER TABLE` shim in `crates/oauth2-storage-sqlx/src/sqlx.rs::init()` for BOTH `DatabasePool::Sqlite` and `DatabasePool::Postgres` branches AND the Mongo equivalent in `crates/oauth2-storage-mongo/src/lib.rs`. Migration numbers are fixed by this plan (V22 is already taken on main by `V22__add_dpop_jkt_to_auth_codes.sql`): V23 tokens delegation columns, V24 resources, V25 clients.allowed_actors, V26 authorization_codes.requested_actor, V27 trusted_issuers, V28 dpop_jtis, V29 transaction_authorizations, V30 workload identity columns (tls_client_auth_san, software_id, software_version), V31 clients.cimd_managed (allocated during Task 14 fix round).
- New struct fields that map to DB columns get `#[serde(default)]` (or `default = "..."`) and `#[cfg_attr(feature = "sqlx", sqlx(default))]` so old rows and old JSON still deserialize.
- New `Storage` trait methods get a default implementation (return `Ok(None)` / `Ok(())` / `Ok(vec![])`) so unrelated backends compile.
- Any new `app_data` a handler requires must be `Option<web::Data<T>>` (so the 15+ inline `App::new()` builders in `tests/security_http.rs` and `tests/rfc_compliance.rs` keep working) OR every existing test App builder must be updated in the same task.
- `TokenActor::new(storage, jwt_secret, issuer)` signature must not change.
- Feature flags default OFF except `max_delegation_depth = 4`. Discovery advertises a capability only when its flag is on.
- All actor/delegation claims use the `oauth2_core::Actor` shape: `{ "sub": ..., "iss": ..., "sub_profile"?: ..., "act"?: <nested Actor> }`. Never emit `act` without a validated delegation basis (actor token present and authorized).
- Error codes: unknown/forbidden audience or resource → `invalid_target` (RFC 8693 §2.2.2); unauthorized actor / bad subject or actor token → `invalid_grant`; depth exceeded, missing required parameter, unsupported token type → `invalid_request`; RAR not a subset → `invalid_authorization_details`.
- Token type URNs (constants in `oauth2_core::token_types`): `urn:ietf:params:oauth:token-type:access_token`, `...:refresh_token`, `...:id_token`, `...:jwt`, `...:saml2`, `...:id-jag`, `...:txn_token`. Grant URNs: `urn:ietf:params:oauth:grant-type:token-exchange`, `urn:ietf:params:oauth:grant-type:jwt-bearer`, `urn:ietf:params:oauth:grant-type:transaction-authorization`.
- Tests follow `tests/security_token_exchange_expiry.rs`: `sqlite::memory:` storage via `oauth2_storage_factory::create_storage`, `TokenActor::new(storage, secret, "http://localhost")`, `TokenActorPool::new(vec![...])`, `OidcConfig { issuer: "http://localhost", jwt_secret, id_token_alg: "HS256", id_token_kid: None, id_token_private_key_pem: None }`, App built inline per test. All test fns are `#[actix_web::test] async fn`.
- Before committing each task: `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo nextest run --all-features --locked -E 'not binary(bdd)'` (or `cargo test --all-features --locked` if nextest is unavailable) must be green.
- Branch/commit: each task works on branch `p7/task-<N>` created from the integration branch HEAD it was dispatched from. Commit messages: `feat(<area>): <what>` and end with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Do not modify `docs/oauth2-spec-audit.md` until Task 18.

## Waves (parallelism map)

| Wave | Tasks (parallel within wave) | Depends on |
|---|---|---|
| 1 | 1 Actor+Claims, 2 AgentConfig, 3 Token persistence, 4 Resources registry, 5 Client/auth-code columns, 6 Trusted issuers, 7 CIMD fetcher, 8 DPoP ath+replay | — |
| 2 | 9 Token exchange rewrite, 10 JWT-bearer grant + ID-JAG accept, 11 Discovery + per-resource PRM | Wave 1 |
| 3 | 12 ID-JAG/chaining issue, 13 Transaction tokens + A2A, 14 CIMD integration, 15 TAC, 16 Workload polish | Wave 2 |
| 4 | 17 Named-agent consent, 18 Docs + audit tracker | Wave 3 |

File ownership per wave is disjoint except where noted; Task 12 and 13 both add a match arm in `token_exchange.rs` (one line each), Task 14 and 17 both touch `oauth.rs` authorize (Task 17 runs after 14 merges).

---

## Wave 1

### Task 1: `Actor` model, delegation chain validation, new `Claims` fields, token-type constants

**Files:**
- Create: `crates/oauth2-core/src/models/actor.rs`
- Create: `crates/oauth2-core/src/token_types.rs`
- Modify: `crates/oauth2-core/src/models/mod.rs`, `crates/oauth2-core/src/lib.rs` (re-export `Actor`, `ActorChainError`, `token_types`)
- Modify: `crates/oauth2-core/src/models/token.rs` (`Claims` struct + `Claims::new`)
- Test: unit tests inside `actor.rs`; `crates/oauth2-core` tests for Claims round-trip

**Interfaces (Produces):**
```rust
pub const SUB_PROFILE_USER: &str = "user";
pub const SUB_PROFILE_SERVICE: &str = "service";
pub const SUB_PROFILE_AI_AGENT: &str = "ai_agent";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub sub: String,
    pub iss: String,
    #[serde(skip_serializing_if = "Option::is_none")] pub sub_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub act: Option<Box<Actor>>,
}
#[derive(Debug, thiserror-free, PartialEq, Eq)]
pub enum ActorChainError { MissingSub, MissingIss, DepthExceeded { depth: usize, max: usize }, Malformed(String) }
impl Actor {
    pub fn new(sub: impl Into<String>, iss: impl Into<String>) -> Self;
    pub fn with_profile(self, profile: &str) -> Self;
    pub fn with_inner(self, inner: Actor) -> Self;          // nests `inner` as self.act (preserved unchanged)
    pub fn depth(&self) -> usize;                            // 1 when act is None
    pub fn matches(&self, iss: &str, sub: &str) -> bool;
    pub fn from_value(v: &serde_json::Value) -> Result<Actor, ActorChainError>; // every level needs string sub+iss
    pub fn to_value(&self) -> serde_json::Value;
    pub fn validate_chain(&self, max_depth: usize) -> Result<(), ActorChainError>;
}
```
`Claims` gains (all `Option`, `#[serde(skip_serializing_if = "Option::is_none")]`, initialised to `None` in `Claims::new`): `may_act: Option<serde_json::Value>`, `sub_profile: Option<String>`, `txn: Option<String>`, `purp: Option<String>`, `req_wl: Option<String>`, `tctx: Option<serde_json::Value>`, `rctx: Option<serde_json::Value>`. `act` stays `Option<serde_json::Value>`; add `Claims::actor(&self) -> Option<Result<Actor, ActorChainError>>` and `Claims::with_actor(self, Actor) -> Self`.

`token_types.rs`: `pub const ACCESS_TOKEN`, `REFRESH_TOKEN`, `ID_TOKEN`, `JWT`, `SAML2`, `ID_JAG`, `TXN_TOKEN` (URNs from Global Constraints) and `pub const GRANT_TOKEN_EXCHANGE`, `GRANT_JWT_BEARER`, `GRANT_TRANSACTION_AUTHORIZATION`.

- [ ] Write failing unit tests: depth of single/nested actor; `from_value` rejects missing `iss`; `validate_chain(4)` rejects depth 5; JSON round-trip preserves nested order; `Claims` with new fields omits them when `None`.
- [ ] Implement; run `cargo test -p oauth2-core`; commit `feat(core): add Actor delegation chain model and agent claims`.

### Task 2: `AgentConfig` in `oauth2-config`

**Files:** Modify `crates/oauth2-config/src/lib.rs` (+ unit tests in the same file).

**Interfaces (Produces):**
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(default = "default_max_delegation_depth")] pub max_delegation_depth: usize, // OAUTH2_MAX_DELEGATION_DEPTH, default 4
    #[serde(default)] pub trust_domain: Option<String>,        // OAUTH2_TRUST_DOMAIN
    #[serde(default)] pub cimd_enabled: bool,                  // OAUTH2_CIMD_ENABLED
    #[serde(default)] pub cimd_allowed_hosts: Vec<String>,     // OAUTH2_CIMD_ALLOWED_HOSTS (comma list; empty = any public host)
    #[serde(default)] pub cimd_denied_hosts: Vec<String>,      // OAUTH2_CIMD_DENIED_HOSTS
    #[serde(default)] pub obo_enabled: bool,                   // OAUTH2_AGENT_OBO_ENABLED
    #[serde(default)] pub a2a_profile_enabled: bool,           // OAUTH2_A2A_PROFILE_ENABLED
    #[serde(default = "default_txn_token_ttl_secs")] pub txn_token_ttl_secs: u64, // OAUTH2_TXN_TOKEN_TTL_SECS default 300
    #[serde(default)] pub txn_tokens_enabled: bool,            // OAUTH2_TXN_TOKENS_ENABLED
    #[serde(default)] pub tac_enabled: bool,                   // OAUTH2_TAC_ENABLED
    #[serde(default)] pub id_jag_enabled: bool,                // OAUTH2_ID_JAG_ENABLED (issue + accept)
    #[serde(default)] pub chaining_targets: Vec<String>,       // OAUTH2_CHAINING_TARGETS (issuer URLs we may mint grants for)
}
impl Default for AgentConfig { /* reads env like the other default_* fns in this file */ }
// Config gains: #[serde(default)] pub agent: AgentConfig,
```
Follow the existing pattern (`default_access_token_ttl_secs` reads env). Booleans parse `1|true|yes` case-insensitively.

- [ ] Tests: defaults when env unset; env override for depth/ttl/bool/list parsing.
- [ ] Commit `feat(config): add AgentConfig for Phase 7 agent features`.

### Task 3: Persist delegation on tokens (V23), `act` in `CreateToken`, introspection exposes `act`/`cnf`

**Files:**
- Create: `migrations/sql/V23__add_delegation_columns_to_tokens.sql` (three `ALTER TABLE tokens ADD COLUMN act TEXT;` / `cnf TEXT;` / `resource TEXT;`)
- Modify: `crates/oauth2-core/src/models/token.rs` (`Token` fields + builder), `crates/oauth2-storage-sqlx/src/sqlx.rs` (init create/alter shims, `save_token` both branches), `crates/oauth2-storage-mongo/src/lib.rs` (no schema; verify serde round-trip), `crates/oauth2-actix/src/actors/token_actor.rs` (`CreateToken.act`, write `act/cnf/resource` into `Token`), every `CreateToken { .. }` call site (`oauth.rs`, `device.rs`, `admin*.rs`, social-login if any) gets `act: None`, `crates/oauth2-actix/src/handlers/token.rs` (introspection)
- Test: `tests/agent_token_persistence.rs`

**Interfaces (Produces):**
```rust
// Token
#[serde(default)] #[cfg_attr(feature = "sqlx", sqlx(default))] pub act: Option<String>,      // JSON of Actor
#[serde(default)] #[cfg_attr(feature = "sqlx", sqlx(default))] pub cnf: Option<String>,      // JSON of cnf object
#[serde(default)] #[cfg_attr(feature = "sqlx", sqlx(default))] pub resource: Option<String>, // JSON array of strings
impl Token { pub fn with_delegation(self, act: Option<&serde_json::Value>, cnf: Option<&serde_json::Value>, resources: &[String]) -> Self; pub fn actor(&self) -> Option<Actor>; pub fn cnf_value(&self) -> Option<serde_json::Value>; pub fn resources(&self) -> Vec<String>; }
// CreateToken gains: pub act: Option<serde_json::Value>,
// IntrospectionResponse gains: #[serde(skip_serializing_if = "Option::is_none")] pub act: Option<serde_json::Value>,
```
Introspection (`token.rs`): populate `act` from JWT claims when JWT, or from `Token.act` when opaque; populate `cnf` from `Token.cnf` when the JWT path has none. `CreateToken` handler embeds `act` into `Claims.act` for JWT access tokens and stores `act`/`cnf`/`resource` (as `vec![resource]` when `Some`) on the row.

- [ ] Test: create token via `CreateToken` with `act = Actor::new("agent-1","http://localhost")`, opaque mode ON via `TokenActor::with_access_tokens_opaque(true)`; introspect → `act.sub == "agent-1"` and `cnf` present when supplied. Same test in JWT mode.
- [ ] Commit `feat(storage): persist act/cnf/resource on tokens and expose act in introspection`.

### Task 4: Protected resources registry (V24) + storage + admin CRUD

**Files:**
- Create: `migrations/sql/V24__create_resources_table.sql`, `crates/oauth2-core/src/models/resource.rs`, `crates/oauth2-actix/src/handlers/admin_resources.rs`
- Modify: `crates/oauth2-ports/src/storage.rs`, sqlx + mongo backends, `crates/oauth2-core` exports, `crates/oauth2-actix/src/handlers/mod.rs`, `crates/oauth2-server/src/lib.rs` (routes under existing `/admin` scope, behind the same `AdminGuard`)
- Test: `tests/agent_resources_registry.rs`

**Interfaces (Produces):**
```rust
pub struct ProtectedResource { pub id: String, pub resource_uri: String, pub name: String, pub scopes: String /* JSON array */, pub authorization_details_types: String /* JSON array */, pub txn_challenge_jwks_uri: String, pub created_at: DateTime<Utc>, pub updated_at: DateTime<Utc> }
impl ProtectedResource { pub fn new(resource_uri, name, scopes: Vec<String>) -> Self; pub fn scopes_vec(&self) -> Vec<String>; pub fn validate_uri(uri: &str) -> Result<(), OAuth2Error> /* absolute, https or http, no fragment → else invalid_target */ }
// Storage (all default impls):
async fn save_resource(&self, r: &ProtectedResource) -> Result<(), OAuth2Error>;
async fn get_resource_by_uri(&self, uri: &str) -> Result<Option<ProtectedResource>, OAuth2Error>;
async fn list_resources(&self) -> Result<Vec<ProtectedResource>, OAuth2Error>;
async fn delete_resource(&self, id: &str) -> Result<(), OAuth2Error>;
```
SQL: `resources(id TEXT PRIMARY KEY, resource_uri TEXT NOT NULL UNIQUE, name TEXT NOT NULL, scopes TEXT NOT NULL DEFAULT '[]', authorization_details_types TEXT NOT NULL DEFAULT '[]', txn_challenge_jwks_uri TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`. Admin JSON API: `GET /admin/resources` (list), `POST /admin/resources` (body `{resource_uri,name,scopes[],authorization_details_types[],txn_challenge_jwks_uri}` → 201), `DELETE /admin/resources/{id}` → 204.

- [ ] Tests: save/get/list/delete via storage on sqlite memory; `validate_uri` rejects `mcp.example.com` (no scheme) and `https://x#frag`; admin POST then GET round-trip (use the pattern in `tests/security_http.rs` for admin auth).
- [ ] Commit `feat(storage): add protected resources registry with admin CRUD`.

### Task 5: `clients.allowed_actors` (V25) and `authorization_codes.requested_actor` (V26)

**Files:** migrations V25/V26; `crates/oauth2-core/src/models/client.rs` (`Client.allowed_actors: String` JSON array, default `"[]"`, helper `allowed_actors_vec()` and `allows_actor(&self, client_id: &str) -> bool`; `ClientRegistration.allowed_actors: Option<Vec<String>>`), `crates/oauth2-core/src/models/authorization.rs` (`AuthorizationCode.requested_actor: Option<String>`), sqlx (create/alter shims, client INSERT/UPDATE both branches, auth code INSERT both branches), mongo (verify serde), `crates/oauth2-actix/src/handlers/client.rs` (registration copies `allowed_actors`; admins only — dynamic (public) registration must ignore it), admin client edit form if one exists (`admin.rs`).
- Test: `tests/agent_client_columns.rs`: save client with `allowed_actors=["agent-a"]`, reload, `allows_actor("agent-a")`; save auth code with `requested_actor`, reload.
- [ ] Commit `feat(storage): add allowed_actors to clients and requested_actor to auth codes`.

### Task 6: Trusted issuers registry (V27) + `get_user_by_email`

**Files:** `migrations/sql/V27__create_trusted_issuers_table.sql`, `crates/oauth2-core/src/models/trusted_issuer.rs`, storage trait + both backends, `crates/oauth2-actix/src/handlers/admin_trusted_issuers.rs`, routes under `/admin` (`GET/POST /admin/trusted-issuers`, `DELETE /admin/trusted-issuers/{id}`), `Storage::get_user_by_email(&self, email) -> Result<Option<User>>` (default `Ok(None)`, implemented in sqlx + mongo).
- Test: `tests/agent_trusted_issuers.rs`.

**Interfaces (Produces):**
```rust
pub struct TrustedIssuer { pub id: String, pub issuer: String /* UNIQUE */, pub jwks_uri: String, pub allowed_audiences: String /* JSON array; empty = only our issuer/token endpoint */, pub subject_mapping: String /* "sub" | "email" */, pub jit_provision: bool, pub allowed_client_ids: String /* JSON array; empty = any */, pub enabled: bool, pub created_at, pub updated_at }
async fn save_trusted_issuer / get_trusted_issuer(&self, issuer: &str) / list_trusted_issuers / delete_trusted_issuer(id)
```
- [ ] Commit `feat(storage): add trusted issuers registry for JWT bearer grants`.

### Task 7: CIMD fetcher module (no flow integration yet)

**Files:** Create `crates/oauth2-actix/src/handlers/cimd.rs`; modify `handlers/mod.rs`; unit tests in-file using an `actix_web::test` server or `wiremock` if adding the dev-dep is acceptable (prefer in-process actix test server bound to 127.0.0.1 with the loopback guard disabled via a `allow_loopback_for_tests: bool` field).

**Interfaces (Produces):**
```rust
pub fn is_client_id_url(client_id: &str) -> bool; // https scheme, non-empty path other than "/", no userinfo, no fragment, no "." or ".." segments, no query (SHOULD → reject)
pub struct CimdFetcher { /* reqwest::Client with redirect(Policy::none()), 5s timeout; Mutex<HashMap<String,(Client, Instant)>> cache; max_bytes = 5120; max_ttl = 1h */ }
impl CimdFetcher {
    pub fn new(allowed_hosts: Vec<String>, denied_hosts: Vec<String>) -> Self;
    pub fn allow_loopback_for_tests(self) -> Self;
    pub async fn resolve(&self, client_id: &str) -> Result<oauth2_core::Client, OAuth2Error>;
}
```
`resolve` MUST: validate URL shape (`invalid_client`), host allow/deny lists, DNS-resolve and reject special-use IPs (loopback, private 10/8 172.16/12 192.168/16, link-local 169.254/16, CGNAT 100.64/10, 0.0.0.0/8, multicast, unspecified, ::1, fc00::/7, fe80::/10), fetch with `Accept: application/json`, require HTTP 200 (`invalid_client` otherwise, never cached), content-type `application/json` or `application/*+json`, body ≤ 5120 bytes, JSON object with `client_id` string equal to the URL (byte comparison), `redirect_uris` non-empty array of strings, `token_endpoint_auth_method` ∈ {absent → `none`, `none`, `private_key_jwt`} (any `client_secret_*` → `invalid_client`), reject if `client_secret` present. Map to `oauth2_core::Client` via `Client::new(...)` then set `token_endpoint_auth_method`, `jwks`, `jwks_uri`, `client_uri`, `logo_uri`, `name = client_name || host`, `grant_types = doc.grant_types || ["authorization_code","refresh_token"]`, `response_types`, `scope = doc.scope || ""`. Cache successes honoring `Cache-Control: max-age` capped at 1h, default 5 min.

- [ ] Tests: valid doc resolves; `client_id` mismatch → invalid_client; 404 → invalid_client and not cached; oversize body rejected; `client_secret_basic` rejected; redirect response rejected; URL shape rules (root path, userinfo, fragment, http scheme).
- [ ] Commit `feat(cimd): add Client ID Metadata Document fetcher with SSRF guards`.

### Task 8: DPoP `ath` claim + storage-backed replay store (V28)

**Files:** `crates/oauth2-actix/src/handlers/dpop.rs`, `crates/oauth2-actix/src/handlers/token.rs` (introspection passes the presented access token so `ath` is checked), `migrations/sql/V28__create_dpop_jtis_table.sql` (`dpop_jtis(jti TEXT PRIMARY KEY, expires_at TEXT NOT NULL)`), storage trait `async fn dpop_jti_check_and_insert(&self, jti: &str, expires_at: DateTime<Utc>) -> Result<bool /* true = fresh */, OAuth2Error>` default in-memory semantics `Ok(true)`, sqlx + mongo impls (insert; unique violation → `Ok(false)`; opportunistic delete of expired rows), `DpopReplayStore` gains `Storage`-backed variant selected in `crates/oauth2-server/src/lib.rs`.
- `DpopClaims.ath: Option<String>`; `validate_dpop_proof(...)` gains `expected_ath: Option<&str>`; when `Some`, proof MUST carry `ath == base64url(SHA-256(access_token))` else `invalid_dpop_proof`.
- Tests in `tests/dpop_*.rs` style: `ath` mismatch rejected at introspection; replay across two `DpopReplayStore` instances sharing the same sqlite storage is rejected.
- [ ] Commit `feat(dpop): validate ath claim and persist jti replay store`.

---

## Wave 2

### Task 9: RFC 8693 token exchange rewrite (7.A)

**Files:**
- Create: `crates/oauth2-actix/src/handlers/token_exchange.rs` (move `handle_token_exchange_grant` out of `oauth.rs`; expose `pub(crate) async fn handle_token_exchange_grant(ctx: ExchangeContext) -> Result<HttpResponse, OAuth2Error>` and `pub(crate) struct ExchangeContext { req: TokenRequest, client: Client, cnf_claim: Option<Value>, dpop_present: bool, subject: ResolvedToken, actor: Option<ResolvedToken>, config: AgentConfig, storage: DynStorage, token_actor: web::Data<TokenActorPool>, metrics: web::Data<Metrics>, oidc_config: web::Data<OidcConfig> }`).
- Modify: `oauth.rs` — `TokenRequest.resource: Vec<String>` (collect ALL `resource` form values; update every use: auth code path uses `.first()`), `TokenRequest.audience: Vec<String>`, `TokenRequest.actor_token_type`/`subject_token_type` no longer `dead_code`; dispatch arm calls the new module; `CreateToken.resource: Option<String>` → `resources: Vec<String>` (update token_actor + all call sites; `aud` = resources when non-empty else client_id; `Token.resource` column stores the JSON array).
- Modify: `crates/oauth2-actix/src/handlers/mod.rs`, `crates/oauth2-server/src/lib.rs` (pass `web::Data<AgentConfig>` — handlers read it as `Option<web::Data<AgentConfig>>` with `AgentConfig::default()` fallback).
- Test: `tests/agent_token_exchange.rs`

**Algorithm (normative for this task):**
1. Authenticate client as today (confidential only, `supports_grant_type`).
2. `subject_token` and `subject_token_type` REQUIRED → `invalid_request`. Allowed subject types: `ACCESS_TOKEN` (LookupToken, `is_valid()`, claims via `Claims::decode_unverified` when JWT else synthesize from row: `sub = user_id || client_id`, `aud = resources() || [client_id]`, `act = Token.act`, `authorization_details = None`), `JWT` (verify signature with keyset/secret via existing `Claims::decode`/`decode_with_keyset`, then also require not revoked if persisted), `ID_TOKEN` (verify as our ID token; subject = `sub`, scope = `""`, no act). `REFRESH_TOKEN`/`SAML2`/unknown → `invalid_request`.
3. `actor_token` optional; if present `actor_token_type` REQUIRED; resolve like step 2. The actor token's `client_id` MUST equal the authenticated client (`invalid_grant` "actor token was not issued to this client"). Actor identity: `Actor::new(actor_claims.sub, issuer).with_profile(actor_sub_profile or SUB_PROFILE_SERVICE)`.
4. Delegation policy (only when actor present): allowed if `subject.may_act` (Value) has `sub` equal to actor sub AND (`iss` absent or equal), OR the subject token's issuing client (`Token.client_id`) `allows_actor(req.client_id)`. Otherwise `invalid_grant` "actor not authorized to act for subject".
5. Build `act`: `new_actor.with_inner(existing_subject_actor)` when the subject already carries `act`; `validate_chain(config.max_delegation_depth)` → `invalid_request` on `DepthExceeded`. No actor token → `act` = subject's existing `act` unchanged (may be None).
6. Requested resources = `req.resource ∪ req.audience` (audience values are treated as resource URIs or registered `resource_uri`s). Each must pass `ProtectedResource::validate_uri`. If the registry (`list_resources`) is non-empty, each must be registered → `invalid_target`. If the subject token's `aud` is exactly `[subject.client_id]` (no resource restriction) any registered/valid resource is allowed; otherwise requested ⊆ subject `aud` → `invalid_target`. Empty request → inherit subject `aud` (minus the client_id default → treated as none).
7. `scope`: subset check as today (`validate_scope_subset`); default inherit.
8. `authorization_details`: if requested, parse JSON array, every element must have a string `type` and be JSON-equal to an element of the subject's `authorization_details` → else `invalid_authorization_details`; default inherit subject's.
9. `requested_token_type`: default `ACCESS_TOKEN`; `ACCESS_TOKEN | JWT` handled here; `ID_JAG | TXN_TOKEN` → call `crate::handlers::id_jag::issue` / `crate::handlers::txn_token::issue` **stubs that return `invalid_request` "requested_token_type not enabled"** (Tasks 12/13 replace the stubs); anything else `invalid_request`.
10. `cnf`: DPoP proof present → `{jkt}` of the proof (rebind); mTLS thumbprint → `{x5t#S256}`; else inherit subject's `cnf` only if `subject.client_id == req.client_id`, otherwise none.
11. Mint via `CreateToken { user_id: subject user_id, client_id: req.client_id, scope, include_refresh: false, token_family: None, resources, cnf, authorization_details, act, .. }`. Response JSON exactly: `access_token`, `issued_token_type` (`ACCESS_TOKEN` or `JWT` as requested), `token_type` (`DPoP` if jkt else `Bearer`), `expires_in`, `scope`. No `act` member in the body.
12. rfc7523bis: in `validate_jwt_client_assertion`, accept `aud` equal to the issuer OR the token endpoint URL (both exact string compare); reject others.
13. Metrics: `oauth_token_exchange_total{outcome, actor_present}` if the `Metrics` struct pattern allows adding a labelled counter cheaply; otherwise increment `oauth_token_issued_total` only.

- [ ] Tests (each an inline App): missing `subject_token_type` → 400 invalid_request; access_token subject narrowing works and response has no `act`; actor token from another client → invalid_grant; actor allowed via `allowed_actors` → introspection shows `act.sub == actor`, `act.iss == issuer`, `act.sub_profile`; actor allowed via `may_act` in a JWT subject; nested chain: exchange twice → depth 2, with `max_delegation_depth = 1` → invalid_request; `resource=https://api.example` when registry has it → `aud` == that; unregistered → invalid_target; `audience` widening beyond subject aud → invalid_target; RAR subset OK / superset → invalid_authorization_details; `requested_token_type=...:saml2` → invalid_request; DPoP proof at exchange → `token_type: "DPoP"` and `cnf.jkt` in introspection. Update `tests/security_token_exchange_expiry.rs` and any wave4 test to send `subject_token_type`.
- [ ] Commit `feat(oauth): implement RFC 8693 token exchange with actor delegation chains`.

### Task 10: JWT-bearer authorization grant + ID-JAG acceptance (7.D.1, 7.D.2)

**Files:** Create `crates/oauth2-actix/src/handlers/jwt_bearer.rs`; modify `oauth.rs` (dispatch arm for `GRANT_JWT_BEARER`, `TokenRequest.assertion: Option<String>`), `wellknown.rs` (add `GRANT_JWT_BEARER` to `grant_types_supported` and `authorization_grant_profiles_supported: ["urn:ietf:params:oauth:grant-profile:id-jag"]` when `agent.id_jag_enabled`), `lib.rs` wiring, `handlers/mod.rs`. Test: `tests/agent_jwt_bearer_grant.rs` (mint assertions with a test RSA/EC key and serve its JWKS from an in-process actix test server registered as the `jwks_uri`; the existing `JwksCache` fetches it).

**Rules:** `assertion` REQUIRED. Decode header+claims unverified to get `iss`, `kid`, `typ`. `iss` MUST match an enabled `TrustedIssuer` (else `invalid_grant`). Verify signature with JWKS from `jwks_uri` via `JwksCache` (alg from header, RS256/ES256/PS256 only). Required claims `iss, sub, aud, exp, iat, jti`; `aud` MUST equal our issuer or token endpoint URL, or be in the issuer's `allowed_audiences` (`invalid_grant`). `exp` in the future, `iat` ≤ now+60s. `jti` replay via the existing client-assertion replay guard (reuse it). Client auth: standard confidential client auth; if `allowed_client_ids` non-empty the client must be listed. If `typ == "oauth-id-jag+jwt"` (ID-JAG): require `agent.id_jag_enabled`; `client_id` claim MUST equal authenticated client; `scope`/`resource`/`authorization_details` from the assertion are the ceiling (request may narrow via `scope`/`resource`, else inherit); if `cnf.jkt` present the request MUST carry a DPoP proof whose thumbprint equals it (`invalid_grant`), and the issued token is DPoP-bound; `act` from the assertion is validated with `Actor::from_value` + depth and copied to the issued token. Subject resolution: `subject_mapping == "sub"` → user id = `sub` (JIT create a `User { id: sub, username: sub, email: email claim or "" , role: "user", enabled: true, password_hash: "" }` when `jit_provision` and missing, else `invalid_grant` if no user); `"email"` → `get_user_by_email(email claim)`. Issue access token only (`include_refresh: false`), audience = requested resources ∩ registry rules from Task 9 (reuse its resource validation helper — expose `pub(crate) fn resolve_requested_resources(...)` from `token_exchange.rs`). Response: standard `TokenResponse` (+ `authorization_details`, `resource` echoed when present).

- [ ] Tests: unknown issuer → invalid_grant; bad signature → invalid_grant; aud mismatch → invalid_grant; happy path with `subject_mapping=sub`, `jit_provision=true` creates user and issues token; ID-JAG `typ` with `client_id` mismatch → invalid_grant; ID-JAG with `cnf.jkt` and no DPoP → invalid_grant; refresh token never issued; discovery lists the grant.
- [ ] Commit `feat(oauth): add JWT bearer authorization grant with trusted issuers and ID-JAG acceptance`.

### Task 11: Discovery + per-resource Protected Resource Metadata (7.B.2, 7.B.3 metadata, 7.D metadata)

**Files:** `crates/oauth2-actix/src/handlers/wellknown.rs`, `crates/oauth2-server/src/lib.rs` (route `GET /.well-known/oauth-protected-resource/{id}`), tests in `tests/agent_discovery.rs`.
- `openid_configuration` reads `Option<web::Data<AgentConfig>>`: emit `client_id_metadata_document_supported: true` iff `cimd_enabled`; `identity_chaining_requested_token_types_supported: ["urn:ietf:params:oauth:token-type:jwt","urn:ietf:params:oauth:token-type:id-jag"]` iff `id_jag_enabled`; `authorization_grant_profiles_supported` iff `id_jag_enabled`; `transaction_authorization_endpoint: "{issuer}/oauth/transaction_authorization"` iff `tac_enabled`; `requested_actor_parameter_supported: true` iff `obo_enabled`; `grant_types_supported` includes `GRANT_JWT_BEARER` always (Task 10) and `GRANT_TRANSACTION_AUTHORIZATION` iff `tac_enabled`; `authorization_details_types_supported` = union of `["openid"]` and every registered resource's types (storage optional).
- `/.well-known/oauth-protected-resource/{id}`: look up `ProtectedResource` by id (404 JSON `{error:"not_found"}` otherwise) and emit RFC 9728 fields: `resource`, `authorization_servers: [issuer]`, `scopes_supported`, `bearer_methods_supported: ["header"]`, `dpop_signing_alg_values_supported`, `tls_client_certificate_bound_access_tokens`, `authorization_details_types_supported`, `resource_name`, and when `txn_challenge_jwks_uri` non-empty: `txn_challenge_jwks_uri`, `txn_challenge_signing_alg_values_supported: ["RS256","ES256"]`.
- [ ] Tests: flags off → fields absent; flags on → present with exact values; per-resource PRM 200/404.
- [ ] Commit `feat(discovery): advertise Phase 7 agent capabilities and per-resource metadata`.

---

## Wave 3

### Task 12: Identity chaining / ID-JAG issuing (7.D.3)

**Files:** Create `crates/oauth2-actix/src/handlers/id_jag.rs` (replace the Task 9 stub); modify `token_exchange.rs` dispatch only. Test: `tests/agent_id_jag_issue.rs`.
- Trigger: `requested_token_type == ID_JAG`, or `requested_token_type == JWT` with an `audience` value that is in `agent.chaining_targets` (identity chaining). Require `agent.id_jag_enabled` else `invalid_request`.
- Exactly one `audience` REQUIRED and it MUST be in `chaining_targets` → `invalid_target`. Subject token types allowed: `ID_TOKEN`, `ACCESS_TOKEN`, `REFRESH_TOKEN` (for this path only: validate like the refresh grant — must belong to the client, not revoked). Actor token: if present, processed per Task 9 policy and placed in `act`.
- Mint JWT with header `typ: "oauth-id-jag+jwt"`, `alg` from the current signing key (`kid` set), claims: `iss` (ours), `sub` (user id), `aud` (the audience string), `client_id` (requesting client), `jti`, `iat`, `exp` = now + min(300s, subject remaining lifetime), `scope` (requested ⊆ subject, default inherit), `resource` (optional, from `req.resource`), `authorization_details` (subset rule), `email` (user's email when available), `auth_time`/`acr` when the subject was an ID token carrying them, `act` when actor present, `cnf: {jkt}` when a DPoP proof was presented. Sign with the keyset like access tokens (`Claims::encode_with_key`-style helper for a generic JSON map; add `oauth2_core::jwt::sign_map(header_typ, map, key)` if none exists).
- Response: `{ issued_token_type: ID_JAG (or JWT for chaining), access_token: <jwt>, token_type: "N_A", expires_in, scope, authorization_details? }`. Never persisted as an access token; do not call `CreateToken`.
- [ ] Tests: flag off → invalid_request; audience not in targets → invalid_target; happy path decodes with `typ`, `aud`, `client_id`, `token_type == "N_A"`; DPoP proof → `cnf.jkt`; actor → `act`.
- [ ] Commit `feat(oauth): issue ID-JAG / identity chaining JWT authorization grants`.

### Task 13: Transaction tokens + A2A profile (7.E)

**Files:** Create `crates/oauth2-actix/src/handlers/txn_token.rs` (replace stub); modify `token_exchange.rs` dispatch, `TokenRequest` (`request_details: Option<String>`, `request_context: Option<String>`, `purp: Option<String>` form fields), `wellknown.rs` (`txn_token` in `identity_chaining_requested_token_types_supported`? no — add `transaction_token_supported: true` iff `txn_tokens_enabled`). Test: `tests/agent_txn_tokens.rs`.
- Require `agent.txn_tokens_enabled` and `agent.trust_domain` set (else `invalid_request`). Requesting client MUST authenticate with `private_key_jwt`, `tls_client_auth` or `self_signed_tls_client_auth` (else `invalid_client` "transaction tokens require asymmetric client authentication"). `audience` REQUIRED and MUST equal `trust_domain` (`invalid_target`). Subject types: `ACCESS_TOKEN`, `JWT`, `TXN_TOKEN` (replacement). `request_details` / `request_context`: optional JSON objects (string form value → `serde_json::Value::Object`, else `invalid_request`).
- Claims: header `typ: "txntoken+jwt"`, `kid`; `iss`, `iat`, `exp` = now + `txn_token_ttl_secs`, `aud` = trust_domain, `txn` = new UUID v4 (or preserved from a TXN_TOKEN subject), `sub` = subject sub, `scope` ⊆ subject scope (default inherit), `req_wl` = authenticated client_id, `tctx` = request_details, `rctx` = request_context, `purp` = `req.purp` when `a2a_profile_enabled` (else omitted), `act` = subject's act (unchanged) plus, when `a2a_profile_enabled` and the subject has an act: `actor` = outermost `act.sub`, `principal` = `sub` (draft-araut compatibility).
- Replacement rules (subject is TXN_TOKEN): verify signature with our keys, not expired; `txn`, `sub`, `aud` preserved; scope narrow-only; `tctx` MUST be byte-identical to the subject's `tctx` if `request_details` is supplied (A2A immutability) → else `invalid_request`; `rctx` may change.
- Response: `{ token_type: "N_A", access_token: <jwt>, issued_token_type: TXN_TOKEN, expires_in }` — no refresh token, not persisted. Introspection of a txn token (JWT path) returns `txn`, `purp`, `req_wl` (add optional fields to `IntrospectionResponse`).
- [ ] Tests: flag off → invalid_request; secret-based client → invalid_client; audience mismatch → invalid_target; happy path claims; replacement preserves `txn` and rejects widened scope; A2A `purp`/`tctx` set and immutability enforced.
- [ ] Commit `feat(oauth): add transaction token service with A2A profile`.

### Task 14: CIMD integration into authorize / PAR / token (7.B.1)

**Files:** Create `crates/oauth2-actix/src/handlers/client_resolver.rs` with `pub(crate) async fn resolve_client(client_id: &str, client_actor: &Addr<ClientActor>, cimd: Option<&CimdFetcher>, agent: &AgentConfig) -> Result<Client, OAuth2Error>` (URL client_id + cimd enabled → `CimdFetcher::resolve`; URL client_id + disabled → `invalid_client`; else `GetClient`). Modify `oauth.rs`: every `GetClient` send in `authorize`, `par`, the token endpoint (nonce check) and each grant handler goes through `resolve_client`. Public CIMD clients (`token_endpoint_auth_method = none`) follow the existing public-client rules (PKCE required). Consent page (`login.rs`/`oauth.rs` consent template): when the client is CIMD-derived show `client_name` and the `client_id` host (e.g. "Example MCP Client (app.example.com)"). `lib.rs`: construct `CimdFetcher` from `AgentConfig` and register as `web::Data<CimdFetcher>` when `cimd_enabled`.
- [ ] Tests (`tests/agent_cimd_flow.rs`, in-process metadata server with `allow_loopback_for_tests`): authorize with URL client_id + PKCE reaches consent/login (302) and a redirect_uri not in the doc → 400; token exchange for a code works with `client_id=<url>`; disabled flag → invalid_client; `private_key_jwt` CIMD client authenticates at the token endpoint using `jwks` from the document.
- [ ] Commit `feat(oauth): resolve URL client_ids via Client ID Metadata Documents`.

### Task 15: Transaction Authorization Challenge (7.F)

**Files:** Create `migrations/sql/V29__create_transaction_authorizations_table.sql`, `crates/oauth2-core/src/models/transaction_authorization.rs`, `crates/oauth2-actix/src/handlers/transaction_authorization.rs`; storage trait + both backends; `oauth.rs` dispatch arm for `GRANT_TRANSACTION_AUTHORIZATION` (`TokenRequest.transaction_authorization_id`); routes `POST /oauth/transaction_authorization`, `GET/POST /oauth/transaction_authorization/approve` (reuse the device verify page style from `device.rs`); `lib.rs`. Test: `tests/agent_tac.rs`.
- Model: `TransactionAuthorization { id, transaction_authorization_id, client_id, user_id: Option<String>, resource_uri, txn, authorization_details: String, reason: String, reason_uri: String, act: Option<String>, created_at, expires_at, interval_seconds: i32, approved: bool, denied: bool, used: bool }`.
- `POST /oauth/transaction_authorization` (client-authenticated, requires `agent.tac_enabled`): body `transaction_challenge=<jwt>`. Decode header/claims; `iss` MUST equal a registered `ProtectedResource.resource_uri` with non-empty `txn_challenge_jwks_uri` (`invalid_request` "unknown protected resource"); verify signature via `JwksCache` on that URI; required `iss, aud (== our issuer), iat, exp, jti, txn, authorization_details (array), reason (string)`; optional `reason_uri`, `act`. Reject expired / replayed `jti` (reuse replay guard). Store a row with `transaction_authorization_id = uuid`, expiry = min(challenge `exp`, now+600s), `interval_seconds = 5`. Response 200 `{ transaction_authorization_id, expires_in, interval }`.
- Approval UI: `GET /oauth/transaction_authorization/approve?transaction_authorization_id=...` requires an authenticated session (same guard as device verify); renders `reason`, the `authorization_details` JSON pretty-printed, requesting `client` name and, if `act` present, "acting agent: <act.sub>". `POST` with `action=approve|deny` sets flags and `user_id`.
- Polling grant `grant_type=GRANT_TRANSACTION_AUTHORIZATION&transaction_authorization_id=...`: client must match; pending → `authorization_pending`; denied → `access_denied`; expired → `expired_token`; approved & unused → issue access token via `CreateToken` with `scope = ""` unless `authorization_details` carry a `scope`-like hint (leave scope empty), `authorization_details` = approved array, `act` = challenge act if present, `resources = [resource_uri]`, `cnf` from DPoP proof if presented, TTL = min(access TTL, 300s) — add `CreateToken.ttl_override_secs: Option<u64>`; mark `used`. The issued JWT MUST carry `txn` (Claims.txn from Task 1).
- RFC 9470 step-up (7.F.4): if the challenge carries `acr_values` or `max_age` and the approving session's `auth_time`/acr do not satisfy them, the approval page redirects to login with `prompt=login` (reuse the existing max_age enforcement helper from Phase 1.D) — document this in the module doc; test only the `max_age` case if a helper exists, otherwise leave a documented follow-up in the report.
- [ ] Tests: flag off → 400; unknown RS issuer → invalid_request; bad signature → invalid_request; happy path: submit → pending → approve via session → token with `txn` and `authorization_details`; deny → access_denied; second poll after use → invalid_grant.
- [ ] Commit `feat(oauth): add transaction authorization challenge endpoint and grant`.

### Task 16: Workload identity polish (7.G)

**Files:** `oauth.rs` (`authenticate_confidential_client`), `client.rs` model + registration, sqlx/mongo, `wellknown.rs`, `token_actor.rs`. Test: `tests/agent_workload_identity.rs`.
- `token_endpoint_auth_method` values `tls_client_auth_san_uri` and `tls_client_auth_san_dns`: the reverse proxy supplies `X-SSL-Client-SAN-URI` / `X-SSL-Client-SAN-DNS`; the client stores the expected value in a new column `tls_client_auth_san` (migration reuses V25? No — add the column in this task's sqlx `init()` shim AND a new file `migrations/sql/V30__add_tls_client_auth_san.sql`). Match exact string; thumbprint header still required.
- `mtls_endpoint_aliases: { token_endpoint, introspection_endpoint, revocation_endpoint }` in discovery pointing at `{issuer}/oauth/...` (same URLs; documents the aliases).
- Dynamic registration accepts `software_id`, `software_version`, `software_statement` (RFC 7591 §2.3): store `software_id`/`software_version` (columns in V30), and when `software_statement` is a JWT signed by a `TrustedIssuer` (Task 6), claims in the statement override the request body; unsigned/unknown-issuer statements → `invalid_software_statement`.
- `Claims.sub_profile` set on every access token: `user` when `user_id` is Some, else `service`; when the client has `software_id` starting with `agent:` or `allowed_actors` non-empty use `ai_agent` for client-credential tokens. Add `CreateToken.sub_profile: Option<String>` override.
- Config `agent.ai_agent_access_token_ttl_secs: Option<u64>` (env `OAUTH2_AI_AGENT_ACCESS_TOKEN_TTL_SECS`): when set and `sub_profile == ai_agent`, cap TTL.
- [ ] Tests: SAN URI auth success/mismatch; software_statement signed by trusted issuer applied; `sub_profile` present in JWT; agent TTL cap.
- [ ] Commit `feat(oauth): workload identity polish — SAN mTLS, software statements, sub_profile`.

---

## Wave 4

### Task 17: Named-agent consent (7.C)

**Files:** `oauth.rs` (`authorize`: parse `requested_actor`; PAR passthrough; auth code carries it; `handle_authorization_code_grant`: require and validate `actor_token`), consent template, `wellknown.rs` already done in Task 11. Test: `tests/agent_obo_consent.rs`.
- Only when `agent.obo_enabled`; otherwise `requested_actor` is ignored (RFC 6749 unknown params ignored).
- `requested_actor` MUST be a registered client (or resolvable CIMD URL) else redirect error `invalid_request` "unknown requested_actor". Persist on the auth code (`requested_actor`, Task 5). Consent page text: "<client name> wants <actor name> to access …".
- At code exchange: if the code has `requested_actor`, `actor_token` + `actor_token_type` (`ACCESS_TOKEN` or `JWT`) REQUIRED → `invalid_request`; resolve via the Task 9 helper; the actor token's `client_id` MUST equal `requested_actor` → `invalid_grant`. Issue tokens with `act = Actor::new(requested_actor, issuer).with_profile(SUB_PROFILE_AI_AGENT)`; refresh grant copies `act` from the old token (`Token.actor()`), which also fixes 7.C.4.
- [ ] Tests: flag off → param ignored; unknown actor → error redirect; happy path: authorize with `requested_actor` → login → consent → code → token exchange with `actor_token` → introspection shows `act.sub == agent`; missing actor_token → invalid_request; refresh keeps `act`.
- [ ] Commit `feat(oauth): named-agent consent via requested_actor and actor_token`.

### Task 18: Documentation and audit tracker

**Files:** `docs/oauth2-spec-audit.md` (fix stale §1 rows for token exchange/DPoP/mTLS/RFC 9728/PAR; add `## 10. Phase 7 — Agent & A2A Authorization` with a chunk table 7.A–7.G all ✅ and the flags), `docs/agents/README.md` (new: how to configure each feature, example curl flows for exchange with actor token, ID-JAG, txn token, CIMD, TAC, requested_actor), `CHANGELOG.md` (add `## [1.1.0] — Unreleased` section listing Phase 7), `CLAUDE.md` (add the new test files and the `AgentConfig` app_data note to the tables), `README.md` feature list bullets.
- [ ] Commit `docs: document Phase 7 agent and A2A OAuth features`.

---

## After all tasks
1. Final whole-branch review (most capable model), one fix wave.
2. Full CI gate locally, open PR to `main`, merge when green.
3. Bump version to `1.1.0` and trigger the Release workflow (`gh workflow run release.yml -f version=1.1.0`) once main is green.
