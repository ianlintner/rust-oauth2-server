# OAuth 2.0 Specification Audit & Implementation Roadmap

**Source:** https://oauth.net/specs/  
**Audit Date:** 2026-04-12  
**Codebase Version:** 0.0.10  
**Branch:** `claude/oauth2-spec-audit-UheZ5`

---

## Table of Contents

1. [Current Implementation Inventory](#1-current-implementation-inventory)
2. [Gap Analysis — Published RFCs](#2-gap-analysis--published-rfcs)
3. [Gap Analysis — Active Drafts](#3-gap-analysis--active-drafts)
4. [Stack-Ranked Missing Features](#4-stack-ranked-missing-features)
5. [Phased Roadmap](#5-phased-roadmap)
6. [Phase 1 Checklist (Bite-Size Chunks)](#6-phase-1-checklist-bite-size-chunks)
7. [Progress Tracker](#7-progress-tracker)

---

## 1. Current Implementation Inventory

### 1.1 Grant Types

| Grant Type | RFC | Status | Notes |
|---|---|---|---|
| Authorization Code | RFC 6749 §4.1 | ✅ Implemented | Full flow with session, redirect |
| Client Credentials | RFC 6749 §4.4 | ✅ Implemented | Scope enforcement |
| Refresh Token | RFC 6749 §6 | ✅ Implemented | Token rotation + family revocation |
| Device Authorization | RFC 8628 | ✅ Implemented | Full device flow + user verify page |
| Password (ROPC) | RFC 6749 §4.3 | ✅ Intentionally disabled | Security BCP compliant |
| Implicit | RFC 6749 §4.2 | ✅ Intentionally removed | Security BCP compliant |
| Token Exchange | RFC 8693 | ❌ Missing | — |
| JWT Assertion | RFC 7521/7523 | ❌ Missing | — |
| SAML Assertion | RFC 7521/7522 | ❌ Out of scope | — |

### 1.2 Endpoints

| Endpoint | Spec | Status | Notes |
|---|---|---|---|
| `GET /oauth/authorize` | RFC 6749 | ✅ Implemented | `response_type=code` only |
| `POST /oauth/token` | RFC 6749 | ✅ Implemented | 4 grant types |
| `POST /oauth/introspect` | RFC 7662 | ✅ Implemented | Stateless + DB-backed |
| `POST /oauth/revoke` | RFC 7009 | ✅ Implemented | Per-token revocation |
| `GET /.well-known/openid-configuration` | RFC 8414 + OIDC | ✅ Implemented | Full metadata doc |
| `GET /.well-known/jwks.json` | OIDC Core | ✅ Implemented | RSA public keys |
| `GET /oauth/userinfo` | OIDC Core §5.3 | ✅ Implemented | Basic claims (placeholder email) |
| `GET /oauth/logout` | OIDC Session | ✅ Implemented | RP-initiated logout |
| `POST /oauth/device_authorization` | RFC 8628 | ✅ Implemented | |
| `GET /oauth/device/verify` | RFC 8628 | ✅ Implemented | Browser UI |
| `POST /oauth/device/verify` | RFC 8628 | ✅ Implemented | Approve/deny |
| `POST /admin/clients/register` | RFC 7591 (partial) | ⚠️ Partial | No registration_access_token, limited metadata |
| `POST /oauth/par` | RFC 9126 | ❌ Missing | Pushed Authorization Requests |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 | ⚠️ Partial | Served via openid-configuration only |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 | ❌ Missing | Resource server metadata |

### 1.3 Security Features

| Feature | Spec | Status | Notes |
|---|---|---|---|
| PKCE (S256 required) | RFC 7636 | ✅ Implemented | `plain` disabled per BCP |
| Bearer tokens in header | RFC 6750 | ✅ Implemented | |
| Bearer tokens in form body | RFC 6750 §2.2 | ⚠️ Partial | Only on introspect/revoke |
| `Cache-Control: no-store` on token responses | RFC 6749 | ✅ Implemented | |
| Constant-time secret comparison | Security BCP | ✅ Implemented | `subtle::ConstantTimeEq` |
| Duplicate parameter rejection | Security BCP §4.6 | ✅ Implemented | Query + form |
| Fragment rejection on redirect_uri | Security BCP | ✅ Implemented | |
| Security response headers | Security BCP | ✅ Implemented | CSP, X-Frame-Options, Referrer-Policy |
| Token family / refresh rotation | Security BCP §4.13.2 | ✅ Implemented | Full chain revocation on replay |
| Redirect URI exact match | RFC 6749 §3.1.2 | ✅ Implemented | |
| Rate limiting | — | ✅ Implemented | In-memory + Redis backends |
| Authorization response `iss` parameter | RFC 9207 | ❌ Missing | |
| `state` parameter enforcement (CSRF) | RFC 6749 §10.12 | ⚠️ Partial | Passed through, not enforced server-side |
| DPoP | RFC 9449 | ❌ Missing | |
| Mutual-TLS client auth | RFC 8705 | ❌ Missing | |

### 1.4 Token Formats

| Feature | Spec | Status | Notes |
|---|---|---|---|
| JWT access tokens (HS256) | RFC 7519 | ✅ Implemented | |
| JWT access tokens (RS256) | RFC 7519 | ✅ Implemented | |
| Opaque access tokens | — | ✅ Implemented | Configurable |
| OIDC ID tokens (HS256/RS256) | OIDC Core | ✅ Implemented | nonce, at_hash, c_hash |
| `kid` header in JWT | RFC 7515 | ✅ Implemented | KeySet management |
| JWT Profile for Access Tokens | RFC 9068 | ⚠️ Partial | Missing `typ: "at+JWT"`, `client_id` claim not in standard position |
| JWT Introspection Response | RFC 9701 | ❌ Missing | Returns plain JSON |
| JWK Thumbprint URI | RFC 9278 | ❌ Missing | |

### 1.5 Client Authentication Methods

| Method | Spec | Status | Notes |
|---|---|---|---|
| `client_secret_basic` | RFC 6749 §2.3.1 | ✅ Implemented | HTTP Basic auth |
| `client_secret_post` | RFC 6749 §2.3.1 | ✅ Implemented | Body params |
| `none` (public clients) | RFC 6749 / PKCE | ❌ Missing | Public clients require PKCE but have no secret |
| `client_secret_jwt` | RFC 7523 | ❌ Missing | |
| `private_key_jwt` | RFC 7523 | ❌ Missing | |
| `tls_client_auth` | RFC 8705 | ❌ Missing | Mutual-TLS |
| `self_signed_tls_client_auth` | RFC 8705 | ❌ Missing | |

### 1.6 OIDC Core Features

| Feature | Spec | Status | Notes |
|---|---|---|---|
| `openid` scope handling | OIDC Core | ✅ Implemented | Triggers id_token |
| ID token issuance | OIDC Core §3.1 | ✅ Implemented | |
| `nonce` binding | OIDC Core §3.1.2.1 | ✅ Implemented | |
| `at_hash` claim | OIDC Core §3.3.2.11 | ✅ Implemented | |
| `c_hash` claim | OIDC Core §3.3.2.11 | ✅ Implemented | |
| UserInfo endpoint | OIDC Core §5.3 | ⚠️ Partial | Claims not populated from real user store; placeholder email |
| RP-initiated logout | OIDC Session | ✅ Implemented | id_token_hint validation pending |
| `prompt` parameter | OIDC Core §3.1.2.1 | ❌ Missing | none/login/consent/select_account |
| `login_hint` parameter | OIDC Core §3.1.2.1 | ❌ Missing | |
| `max_age` parameter | OIDC Core §3.1.2.1 | ❌ Missing | |
| `acr_values` parameter | OIDC Core §3.1.2.1 | ❌ Missing | |
| `claims` parameter | OIDC Core §5.5 | ❌ Missing | Fine-grained claim requests |
| Hybrid flow | OIDC Core §3.3 | ❌ Missing | response_type: code id_token |
| `response_mode=fragment` | OAuth2 / OIDC | ❌ Missing | |
| `response_mode=form_post` | OAuth2 / OIDC | ❌ Missing | |
| Session management | OIDC Session | ❌ Missing | |
| `id_token_hint` validation | OIDC Core | ❌ Missing | Currently accepted but not validated |

### 1.7 Dynamic Client Registration (RFC 7591)

| Feature | Status | Notes |
|---|---|---|
| Client registration endpoint | ⚠️ Partial | `POST /admin/clients/register` — admin-only, not a standards-compliant RFC 7591 endpoint |
| `registration_access_token` | ❌ Missing | Required for RFC 7591 read/update/delete |
| `registration_client_uri` | ❌ Missing | |
| Full client metadata fields | ❌ Missing | Only: name, redirect_uris, grant_types, scope |
| `POST /connect/register` (public endpoint) | ❌ Missing | RFC 7591 requires open or bearer-token-protected |
| Client update (`PUT`) | ❌ Missing | RFC 7592 |
| Client delete (`DELETE`) | ❌ Missing | RFC 7592 |
| Initial access tokens | ❌ Missing | |

### 1.8 Infrastructure & Observability

| Feature | Status | Notes |
|---|---|---|
| SQLite storage | ✅ Implemented | |
| PostgreSQL storage | ✅ Implemented | |
| MongoDB storage | ✅ Implemented | |
| Redis cache | ✅ Implemented | |
| Redis rate-limiting | ✅ Implemented | |
| Prometheus metrics | ✅ Implemented | |
| OpenTelemetry tracing | ✅ Implemented | |
| Kafka event bus | ✅ Implemented | |
| RabbitMQ event bus | ✅ Implemented | |
| Redis Streams event bus | ✅ Implemented | |
| Social login (GitHub, Google, Microsoft) | ✅ Implemented | |
| Circuit breaker / bulkhead | ✅ Implemented | |
| OpenAPI / Swagger docs | ✅ Implemented | |
| Admin dashboard API | ✅ Implemented | |
| Key management API | ✅ Implemented | |

---

## 2. Gap Analysis — Published RFCs

| RFC | Title | Priority | Gap Summary |
|---|---|---|---|
| RFC 6749 | OAuth 2.0 Core | High | `state` not enforced; missing `error_uri`; `scope` response not always returned |
| RFC 6750 | Bearer Token Usage | Medium | Bearer token in URI query param not supported (intentional?); `WWW-Authenticate` header lacks full error params |
| RFC 7009 | Token Revocation | Low | Revocation does not cascade to linked refresh tokens when only access token presented |
| RFC 7521 | Assertion Framework | Low | Not implemented |
| RFC 7522 | SAML 2.0 Profile | None | Out of scope |
| RFC 7523 | JWT Client Auth | Medium | `private_key_jwt` and `client_secret_jwt` not implemented |
| RFC 7591 | Dynamic Client Registration | High | Admin endpoint only; not RFC 7591 compliant; missing `registration_access_token`, full metadata |
| RFC 7592 | Client Registration Management | Medium | No update/delete operations |
| RFC 7636 | PKCE | Minimal | S256 done; `plain` intentionally disabled |
| RFC 7662 | Token Introspection | Low | Missing `nbf`, `jti`, `token_type` (only "Bearer") fields; no JWT response |
| RFC 8252 | OAuth 2.0 for Native Apps | Medium | PKCE done; loopback redirect (`127.0.0.1`/`[::1]`) and custom URI scheme handling not explicit |
| RFC 8414 | Authorization Server Metadata | Low | `/.well-known/oauth-authorization-server` path not served separately; `signed_metadata` missing |
| RFC 8628 | Device Authorization Grant | Minimal | Fully implemented |
| RFC 8693 | Token Exchange | Low | Not implemented |
| RFC 8705 | Mutual-TLS Client Auth | Low | Not implemented |
| RFC 8707 | Resource Indicators | Medium | `resource` parameter not handled |
| RFC 8725 | JWT Best Current Practices | Medium | Audience validation uses single string; `alg: none` explicitly tested? |
| RFC 9068 | JWT Profile for Access Tokens | High | Missing `typ: "at+JWT"`, proper `iss` in token claims uses hardcoded string |
| RFC 9101 | JAR (JWT-Secured Auth Request) | Medium | `request` and `request_uri` params not supported |
| RFC 9126 | Pushed Authorization Requests | High | Not implemented |
| RFC 9207 | Authorization Server Issuer ID | High | `iss` not returned in authorization response |
| RFC 9278 | JWK Thumbprint URI | Low | Not implemented |
| RFC 9396 | Rich Authorization Requests | Low | Not implemented |
| RFC 9449 | DPoP | Medium | Not implemented |
| RFC 9470 | Step-Up Authentication | Low | Not implemented |
| RFC 9700 | Security BCP | High | Several gaps: `iss` response param, `state` enforcement, public client support |
| RFC 9701 | JWT Introspection Response | Low | Not implemented |
| RFC 9728 | Protected Resource Metadata | Low | Not implemented |
| RFC 9901 | SD-JWT | None | Out of scope |

---

## 3. Gap Analysis — Active Drafts

| Draft | Title | Priority | Notes |
|---|---|---|---|
| OAuth 2.1 | Consolidation of 2.0 + BCP | High | Partially aligned; formal compliance tracking needed |
| Browser-Based Apps BCP | SPA security guidance | Medium | CORS headers, no implicit, PKCE done |
| Cross-Device Flows Security BCP | Device flow attack mitigations | Low | — |
| Attestation-Based Client Authentication | Hardware-backed client auth | Low | Not implemented |
| Token Status List | Efficient revocation | Low | Not implemented |
| Transaction Tokens | Action-specific tokens | Low | Not implemented |
| First-Party Applications | Native app patterns | Low | Not implemented |

---

## 4. Stack-Ranked Missing Features

Items ranked by: **Security Impact** × **Interoperability Gain** × **Standards Compliance**.

| Rank | Feature | RFC(s) | Rationale |
|---|---|---|---|
| 1 | RFC 9207: `iss` param in authorization response | RFC 9207, RFC 9700 | Prevents Mix-Up attacks; required by Security BCP; 1-line addition |
| 2 | Public client support (`token_endpoint_auth_method: none`) | RFC 6749, RFC 7591 | Enables SPAs and native apps without secrets; PKCE already enforced |
| 3 | RFC 9068: JWT Profile for Access Tokens (proper `typ: "at+JWT"`) | RFC 9068 | Corrects `typ` header claim; fixes issuer hardcode; broad ecosystem impact |
| 4 | RFC 6749 `state` enforcement option | RFC 6749 §10.12, RFC 9700 | Configurable CSRF protection option; currently passed through but not validated |
| 5 | RFC 7591 full Dynamic Client Registration | RFC 7591, RFC 7592 | Required for standards-compliant client onboarding; needed by many IdP federations |
| 6 | RFC 7662 Introspection — missing fields (`nbf`, `jti`, `aud`) | RFC 7662 | Conformance with spec; used by many resource servers |
| 7 | UserInfo endpoint real claims population | OIDC Core §5.3 | Currently returns placeholder email; breaks OIDC-dependent clients |
| 8 | OIDC `prompt`, `login_hint`, `max_age` parameters | OIDC Core §3.1.2.1 | Standard OIDC parameters expected by all OIDC relying parties |
| 9 | RFC 9126 Pushed Authorization Requests (PAR) | RFC 9126 | Prevents request tampering; required by many enterprise/FAPI profiles |
| 10 | JWT Profile for Client Auth (`private_key_jwt`) | RFC 7523 | Eliminates shared secrets for confidential clients; widely required |
| 11 | RFC 8707 Resource Indicators | RFC 8707 | Required for multi-resource APIs; FAPI profile dependency |
| 12 | RFC 8252 Native App handling | RFC 8252 | Loopback redirect support; proper custom URI scheme handling |
| 13 | RFC 9101 JAR (signed request objects) | RFC 9101 | Integrity-protected authorize requests; FAPI requirement |
| 14 | RFC 9449 DPoP | RFC 9449 | Sender-constrained tokens; prevents token theft |
| 15 | RFC 7592 Client Registration Management | RFC 7592 | Update/delete client registrations |
| 16 | RFC 9701 JWT Introspection Response | RFC 9701 | JWT-formatted introspection; reduces parsing complexity at RS |
| 17 | RFC 8705 Mutual-TLS Client Auth | RFC 8705 | Certificate-bound tokens; enterprise/banking requirement |
| 18 | RFC 8693 Token Exchange | RFC 8693 | Delegation/impersonation patterns |
| 19 | RFC 9396 Rich Authorization Requests | RFC 9396 | Fine-grained permissions; FAPI2 requirement |
| 20 | RFC 9470 Step-Up Authentication | RFC 9470 | Re-authentication enforcement |
| 21 | RFC 9728 Protected Resource Metadata | RFC 9728 | Resource server discovery |
| 22 | OIDC Hybrid Flow | OIDC Core §3.3 | Legacy RP compatibility |
| 23 | Token Status List | Draft | Efficient distributed revocation |

---

## 5. Phased Roadmap

### Phase 1 — Spec Compliance Hardening (No New Protocols)

**Goal:** Fix conformance gaps in already-implemented features. Low risk, high standards-compliance gain.

| # | Item | RFC(s) | Effort |
|---|---|---|---|
| 1.1 | Add `iss` to authorization response query parameters | RFC 9207 | XS |
| 1.2 | Add `typ: "at+JWT"` to JWT access token header | RFC 9068 | XS |
| 1.3 | Fix issuer in JWT Claims (use configured issuer URL not hardcoded string) | RFC 9068 | XS |
| 1.4 | Add `nbf`, `jti`, `aud` fields to introspection response | RFC 7662 | XS |
| 1.5 | Support public clients (`token_endpoint_auth_method: none`) | RFC 6749 | S |
| 1.6 | Add `error_uri` to OAuth2 error responses | RFC 6749 | XS |
| 1.7 | `scope` in token response when different from requested | RFC 6749 §5.1 | XS |
| 1.8 | Populate UserInfo claims from real user store (drop placeholder email) | OIDC Core §5.3 | S |
| 1.9 | Validate `id_token_hint` in logout endpoint | OIDC Session | S |
| 1.10 | Add OIDC `prompt=none` support (silent auth) | OIDC Core | M |
| 1.11 | Add OIDC `login_hint` parameter passthrough | OIDC Core | XS |
| 1.12 | Add OIDC `max_age` enforcement | OIDC Core | S |
| 1.13 | Serve `/.well-known/oauth-authorization-server` separately | RFC 8414 | XS |
| 1.14 | Add `state` parameter server-side validation option (configurable) | RFC 9700 §4.7 | S |
| 1.15 | Cascade revocation: revoking refresh token revokes linked access tokens | RFC 7009 | S |

### Phase 2 — New Client Authentication & Registration

**Goal:** Expand client authentication methods and complete Dynamic Client Registration.

| # | Item | RFC(s) | Effort |
|---|---|---|---|
| 2.1 | Full RFC 7591 Dynamic Client Registration endpoint (`/connect/register`) | RFC 7591 | L |
| 2.2 | `registration_access_token` for client configuration endpoint | RFC 7591 §3.2 | M |
| 2.3 | Client update (`PUT /connect/register/{client_id}`) | RFC 7592 | M |
| 2.4 | Client delete (`DELETE /connect/register/{client_id}`) | RFC 7592 | S |
| 2.5 | `private_key_jwt` client authentication | RFC 7523 | L |
| 2.6 | `client_secret_jwt` client authentication | RFC 7523 | M |
| 2.7 | Update discovery doc to reflect new auth methods | RFC 8414 | XS |
| 2.8 | Add full OIDC metadata fields to client registration | OIDC Core | M |

### Phase 3 — Advanced Request Security

**Goal:** Hardened request integrity, Resource Indicators, PAR, JAR.

| # | Item | RFC(s) | Effort |
|---|---|---|---|
| 3.1 | Pushed Authorization Requests (PAR) | RFC 9126 | L |
| 3.2 | Resource Indicators (`resource` parameter) | RFC 8707 | M |
| 3.3 | JWT-Secured Authorization Request (JAR / `request` object) | RFC 9101 | L |
| 3.4 | `response_mode=form_post` | OAuth2 / OIDC | S |
| 3.5 | OIDC Hybrid Flow (`response_type: code id_token`) | OIDC Core §3.3 | M |
| 3.6 | RFC 8252 Native Apps — loopback redirect + custom URI scheme validation | RFC 8252 | S |
| 3.7 | JWT Token Introspection Response | RFC 9701 | M |

### Phase 4 — Sender-Constrained Tokens & Advanced Features

**Goal:** DPoP, mTLS, Token Exchange, Rich Authorization.

| # | Item | RFC(s) | Effort |
|---|---|---|---|
| 4.1 | DPoP (Demonstrating Proof-of-Possession) | RFC 9449 | XL |
| 4.2 | Mutual-TLS Client Authentication | RFC 8705 | XL |
| 4.3 | Token Exchange | RFC 8693 | L |
| 4.4 | Rich Authorization Requests (RAR) | RFC 9396 | L |
| 4.5 | Step-Up Authentication | RFC 9470 | M |
| 4.6 | Protected Resource Metadata | RFC 9728 | M |
| 4.7 | Token Status List | Draft | L |
| 4.8 | OIDC Claims Request parameter | OIDC Core §5.5 | M |

---

## 6. Phase 1 Checklist (Bite-Size Chunks)

> **All items target the `claude/oauth2-spec-audit-UheZ5` branch and subsequent PRs.**
> Effort: XS = < 30 min, S = 1–2h, M = half day, L = 1–2 days, XL = 3+ days

---

### Chunk 1.A — Quick Wins (XS items, single-commit each)

- [x] **1.1** `iss` in authorization response
  - File: `crates/oauth2-actix/src/handlers/oauth.rs`
  - Add `iss` query param (value = `oidc_config.issuer`) to the redirect URL in `authorize()`
  - Update discovery doc to include `"authorization_response_iss_parameter_supported": true`

- [x] **1.2** `typ: "at+JWT"` in access token header
  - File: `crates/oauth2-core/src/models/token.rs`
  - In `Claims::encode()` and `Claims::encode_with_key()`, set `header.typ = Some("at+JWT".to_string())`

- [x] **1.3** Fix hardcoded issuer in JWT claims
  - File: `crates/oauth2-core/src/models/token.rs` → `Claims::new()`
  - Change `iss: "rust_oauth2_server".to_string()` to accept issuer as parameter; thread from config

- [x] **1.4a** Add `nbf` field to introspection response
  - File: `crates/oauth2-core/src/models/token.rs` → `IntrospectionResponse`
  - Add `nbf: Option<i64>` field; populate from token `created_at`

- [x] **1.4b** Add `jti` field to introspection response
  - File: `crates/oauth2-core/src/models/token.rs` → `IntrospectionResponse`
  - Add `jti: Option<String>` field; decode from JWT claims or use token `id`

- [x] **1.4c** Add `aud` field to introspection response
  - File: `crates/oauth2-core/src/models/token.rs` → `IntrospectionResponse`
  - Add `aud: Option<String>` field; populate from `token.client_id`

- [ ] **1.6** Add `error_uri` field to `OAuth2Error`
  - File: `crates/oauth2-core/src/models/error.rs`
  - Add optional `error_uri` field to the error struct; serialize when present

- [ ] **1.7** Return `scope` in token response when modified
  - File: `crates/oauth2-actix/src/handlers/oauth.rs`
  - Ensure `scope` in `TokenResponse` is always populated (already is via `From<Token>`)
  - Verify scope is returned even when server-downscoped

- [x] **1.11** `login_hint` passthrough in authorize
  - File: `crates/oauth2-actix/src/handlers/oauth.rs` → `AuthorizeQuery`
  - Add `login_hint: Option<String>` field; store in session for pre-filling login form

- [x] **1.13** Serve `/.well-known/oauth-authorization-server`
  - File: `crates/oauth2-actix/src/handlers/wellknown.rs`
  - Register the same `openid_configuration` handler at `/.well-known/oauth-authorization-server`
  - Update `lib.rs` route registration

---

### Chunk 1.B — Public Client Support (S)

- [x] **1.5a** Add `token_endpoint_auth_method` field to `Client` model
  - File: `crates/oauth2-core/src/models/client.rs`
  - Add `token_endpoint_auth_method: String` (default `"client_secret_basic"`)
  - Add migration for SQLx and MongoDB storage

- [x] **1.5b** Skip secret check for public clients in token endpoint
  - File: `crates/oauth2-actix/src/handlers/oauth.rs`
  - In `handle_authorization_code_grant()`: if `client.token_endpoint_auth_method == "none"`, skip `client_secret` requirement (PKCE already enforced)

- [x] **1.5c** Add `none` to supported auth methods in discovery doc
  - File: `crates/oauth2-actix/src/handlers/wellknown.rs`
  - Add `"none"` to `token_endpoint_auth_methods_supported` array

- [x] **1.5d** Update `validate_grant_types()` / registration to accept public clients
  - File: `crates/oauth2-actix/src/handlers/client.rs`
  - Allow registration of public clients with `"none"` auth method

---

### Chunk 1.C — Issuer Consistency & UserInfo (S–M)

- [x] **1.3-full** Thread issuer through `Claims::new()` call sites
  - Files: `crates/oauth2-actix/src/actors/token_actor.rs`, `crates/oauth2-server/src/lib.rs`
  - Update `CreateToken` message to carry `issuer` string from config
  - Pass through actor to `Claims::new()`

- [x] **1.8a** UserInfo returns real email and profile claims from storage
  - File: `crates/oauth2-actix/src/handlers/wellknown.rs` → `userinfo()`
  - Look up user by `token.user_id` from storage via `get_user_by_id()`
  - Scope-gate claims: `email` scope → email, `profile` scope → preferred_username

- [x] **1.8b** Populate UserInfo claims from storage
  - File: `crates/oauth2-actix/src/handlers/wellknown.rs` → `userinfo()`
  - Added `Storage::get_user_by_id()` with forwarding through `ObservedStorage`
  - Graceful fallback when storage unavailable or user not found

---

### Chunk 1.D — OIDC Parameter Additions (S)

- [x] **1.10** `prompt=none` support
  - File: `crates/oauth2-actix/src/handlers/oauth.rs` → `AuthorizeQuery`
  - Add `prompt: Option<String>` to query struct
  - If `prompt=none` and no session → return `login_required` error redirect
  - If `prompt=login` → force re-authentication (redirect to login)

- [x] **1.12** `max_age` enforcement
  - File: `crates/oauth2-actix/src/handlers/oauth.rs`
  - Add `max_age: Option<u64>` to `AuthorizeQuery`
  - Store `auth_time` in session at login; compare against `max_age` in authorize
  - Return redirect to login if `auth_time + max_age < now` or if `auth_time` missing

---

### Chunk 1.E — Logout & Revocation Fixes (S)

- [x] **1.9** Validate `id_token_hint` in logout
  - File: `crates/oauth2-actix/src/handlers/oidc_logout.rs`
  - If `id_token_hint` present: decode (without signature check), extract `sub` and `aud`
  - Verify `aud` matches a registered client; use `sub` to revoke tokens for the user

- [x] **1.15** Cascade refresh token revocation
  - File: `crates/oauth2-actix/src/actors/token_actor.rs` → `RevokeToken` handler
  - When revoking by refresh token: also revoke the associated access token via `token_family`
  - When revoking by access token: also revoke linked refresh token (via `token_family`)
  - Added `LookupRefreshToken` actor message for refresh token lookup in revoke handler
  - Revoke handler now tries both access and refresh token lookup for ownership check

---

### Chunk 1.F — Discovery Doc Cleanup (XS)

- [x] Update discovery doc to reflect Phase 1 additions:
  - `"authorization_response_iss_parameter_supported": true`
  - `"prompt_values_supported": ["none", "login"]`
  - `"claims_supported"` — added `name`, `picture` to real user claims
  - `"token_endpoint_auth_methods_supported"` — includes `"none"` for public clients
  - `"introspection_endpoint_auth_methods_supported"` — verified complete

---

## 7. Progress Tracker

| Item | Status | PR / Commit | Notes |
|---|---|---|---|
| Spec audit document | ✅ Done | Initial commit | This file |
| **Phase 1 items** | ✅ Done | claude/oauth2-spec-audit-UheZ5 | All 6 chunks complete |
| **Phase 2 items** | 🔲 Not started | — | After Phase 1 complete |
| **Phase 3 items** | 🔲 Not started | — | After Phase 2 complete |
| **Phase 4 items** | 🔲 Not started | — | Long-term roadmap |

### Phase 1 Chunk Status

| Chunk | Description | Status |
|---|---|---|
| 1.A | Quick wins (XS items) | ✅ Done |
| 1.B | Public client support | ✅ Done |
| 1.C | Issuer consistency & UserInfo | ✅ Done |
| 1.D | OIDC parameter additions | ✅ Done |
| 1.E | Logout & revocation fixes | ✅ Done |
| 1.F | Discovery doc cleanup | ✅ Done |

---

*Last updated: 2026-04-12 — Generated from audit of codebase v0.0.10*
