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

| Grant Type           | RFC           | Status                    | Notes                               |
| -------------------- | ------------- | ------------------------- | ----------------------------------- |
| Authorization Code   | RFC 6749 §4.1 | ✅ Implemented            | Full flow with session, redirect    |
| Client Credentials   | RFC 6749 §4.4 | ✅ Implemented            | Scope enforcement                   |
| Refresh Token        | RFC 6749 §6   | ✅ Implemented            | Token rotation + family revocation  |
| Device Authorization | RFC 8628      | ✅ Implemented            | Full device flow + user verify page |
| Password (ROPC)      | RFC 6749 §4.3 | ✅ Intentionally disabled | Security BCP compliant              |
| Implicit             | RFC 6749 §4.2 | ✅ Intentionally removed  | Security BCP compliant              |
| Token Exchange       | RFC 8693      | ❌ Missing                | —                                   |
| JWT Assertion        | RFC 7521/7523 | ❌ Missing                | —                                   |
| SAML Assertion       | RFC 7521/7522 | ❌ Out of scope           | —                                   |

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
| `POST /admin/clients/register` | RFC 7591 (partial) | ✅ Implemented | Full RFC 7591 endpoint with `registration_access_token` support |
| `POST /connect/register` (public endpoint) | RFC 7591 | ✅ Implemented | Standards-compliant open registration endpoint |
| `GET/PUT/DELETE /connect/register/{client_id}` | RFC 7592 | ✅ Implemented | Client read/update/delete |
| `POST /oauth/par` | RFC 9126 | ✅ Implemented | Pushed Authorization Requests |
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
| Authorization response `iss` parameter | RFC 9207 | ✅ Implemented | |
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
| JWT Profile for Access Tokens | RFC 9068 | ✅ Implemented | `typ: "at+JWT"` in JOSE header; issuer threaded from config |
| JWT Introspection Response | RFC 9701 | ✅ Implemented | `Accept: application/token-introspection+jwt` returns signed JWT |
| JWK Thumbprint URI | RFC 9278 | ❌ Missing | |

### 1.5 Client Authentication Methods

| Method | Spec | Status | Notes |
|---|---|---|---|
| `client_secret_basic` | RFC 6749 §2.3.1 | ✅ Implemented | HTTP Basic auth |
| `client_secret_post` | RFC 6749 §2.3.1 | ✅ Implemented | Body params |
| `none` (public clients) | RFC 6749 / PKCE | ✅ Implemented | `token_endpoint_auth_method: none`; PKCE enforced |
| `client_secret_jwt` | RFC 7523 | ✅ Implemented | HMAC-signed JWT client assertion |
| `private_key_jwt` | RFC 7523 | ✅ Implemented | RSA/ECDSA-signed JWT client assertion |
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
| UserInfo endpoint | OIDC Core §5.3 | ✅ Implemented | Claims populated from storage; scope-gated |
| RP-initiated logout | OIDC Session | ✅ Implemented | id_token_hint validation included |
| `prompt` parameter | OIDC Core §3.1.2.1 | ✅ Implemented | none/login supported |
| `login_hint` parameter | OIDC Core §3.1.2.1 | ✅ Implemented | Stored in session for login form pre-fill |
| `max_age` parameter | OIDC Core §3.1.2.1 | ✅ Implemented | auth_time compared against max_age |
| `acr_values` parameter | OIDC Core §3.1.2.1 | ❌ Missing | |
| `claims` parameter | OIDC Core §5.5 | ❌ Missing | Fine-grained claim requests |
| Hybrid flow | OIDC Core §3.3 | ❌ Missing | response_type: code id_token |
| `response_mode=fragment` | OAuth2 / OIDC | ❌ Missing | |
| `response_mode=form_post` | OAuth2 / OIDC | ❌ Missing | |
| Session management | OIDC Session | ❌ Missing | |
| `id_token_hint` validation | OIDC Core | ❌ Missing | Currently accepted but not validated |

### 1.7 Dynamic Client Registration (RFC 7591 / RFC 7592)

| Feature | Status | Notes |
|---|---|---|
| Client registration endpoint | ✅ Implemented | `POST /connect/register` — RFC 7591 compliant |
| `registration_access_token` | ✅ Implemented | Returned on registration; required for subsequent read/update/delete |
| `registration_client_uri` | ✅ Implemented | |
| Full client metadata fields | ✅ Implemented | `token_endpoint_auth_method`, `jwks`, `jwks_uri`, OIDC metadata |
| Client read (`GET /connect/register/{id}`) | ✅ Implemented | RFC 7592 |
| Client update (`PUT /connect/register/{id}`) | ✅ Implemented | RFC 7592 |
| Client delete (`DELETE /connect/register/{id}`) | ✅ Implemented | RFC 7592 |
| Initial access tokens | ❌ Missing | |

### 1.8 Infrastructure & Observability

| Feature                                  | Status         | Notes |
| ---------------------------------------- | -------------- | ----- |
| SQLite storage                           | ✅ Implemented |       |
| PostgreSQL storage                       | ✅ Implemented |       |
| MongoDB storage                          | ✅ Implemented |       |
| Redis cache                              | ✅ Implemented |       |
| Redis rate-limiting                      | ✅ Implemented |       |
| Prometheus metrics                       | ✅ Implemented |       |
| OpenTelemetry tracing                    | ✅ Implemented |       |
| Kafka event bus                          | ✅ Implemented |       |
| RabbitMQ event bus                       | ✅ Implemented |       |
| Redis Streams event bus                  | ✅ Implemented |       |
| Social login (GitHub, Google, Microsoft) | ✅ Implemented |       |
| Circuit breaker / bulkhead               | ✅ Implemented |       |
| OpenAPI / Swagger docs                   | ✅ Implemented |       |
| Admin dashboard API                      | ✅ Implemented |       |
| Key management API                       | ✅ Implemented |       |

---

## 2. Gap Analysis — Published RFCs

| RFC | Title | Priority | Gap Summary |
|---|---|---|---|
| RFC 6749 | OAuth 2.0 Core | High | `state` not enforced; missing `error_uri`; `scope` response not always returned |
| RFC 6750 | Bearer Token Usage | Medium | Bearer token in URI query param not supported (intentional?); `WWW-Authenticate` header lacks full error params |
| RFC 7009 | Token Revocation | Low | Revocation does not cascade to linked refresh tokens when only access token presented |
| RFC 7521 | Assertion Framework | Low | Not implemented |
| RFC 7522 | SAML 2.0 Profile | None | Out of scope |
| RFC 7523 | JWT Client Auth | Low | `private_key_jwt` and `client_secret_jwt` implemented |
| RFC 7591 | Dynamic Client Registration | Low | RFC 7591 compliant endpoint; `registration_access_token` supported |
| RFC 7592 | Client Registration Management | Low | Read/update/delete operations implemented |
| RFC 7636 | PKCE | Minimal | S256 done; `plain` intentionally disabled |
| RFC 7662 | Token Introspection | Low | All required fields present; JWT response (RFC 9701) also supported |
| RFC 8252 | OAuth 2.0 for Native Apps | Medium | PKCE done; loopback redirect (`127.0.0.1`/`[::1]`) and custom URI scheme handling not explicit |
| RFC 8414 | Authorization Server Metadata | Low | `/.well-known/oauth-authorization-server` path not served separately; `signed_metadata` missing |
| RFC 8628 | Device Authorization Grant | Minimal | Fully implemented |
| RFC 8693 | Token Exchange | Low | Discovery advertises support; full implementation in Wave 4 |
| RFC 8705 | Mutual-TLS Client Auth | Low | Not implemented |
| RFC 8707 | Resource Indicators | Medium | `resource` parameter not handled |
| RFC 8725 | JWT Best Current Practices | Medium | Audience validation uses single string; `alg: none` explicitly tested? |
| RFC 9068 | JWT Profile for Access Tokens | Low | `typ: "at+JWT"` implemented; issuer threaded from config |
| RFC 9101 | JAR (JWT-Secured Auth Request) | Medium | `request` and `request_uri` params not supported |
| RFC 9126 | Pushed Authorization Requests | Low | Implemented — `POST /oauth/par` |
| RFC 9207 | Authorization Server Issuer ID | Low | `iss` returned in authorization response |
| RFC 9278 | JWK Thumbprint URI | Low | Not implemented |
| RFC 9396 | Rich Authorization Requests | Low | Discovery advertises support; full token-level enforcement in Wave 4 |
| RFC 9449 | DPoP | Medium | Discovery advertises support; full proof validation in Wave 4 |
| RFC 9470 | Step-Up Authentication | Low | Discovery advertises support; enforcement in Wave 4 |
| RFC 9700 | Security BCP | Medium | `iss` response param done; public client support done; `state` enforcement optional |
| RFC 9701 | JWT Introspection Response | Low | Implemented — `Accept: application/token-introspection+jwt` |
| RFC 9728 | Protected Resource Metadata | Low | `/.well-known/oauth-protected-resource` endpoint implemented |
| RFC 9901 | SD-JWT | None | Out of scope |

---

## 3. Gap Analysis — Active Drafts

| Draft                                   | Title                          | Priority | Notes                                                |
| --------------------------------------- | ------------------------------ | -------- | ---------------------------------------------------- |
| OAuth 2.1                               | Consolidation of 2.0 + BCP     | High     | Partially aligned; formal compliance tracking needed |
| Browser-Based Apps BCP                  | SPA security guidance          | Medium   | CORS headers, no implicit, PKCE done                 |
| Cross-Device Flows Security BCP         | Device flow attack mitigations | Low      | —                                                    |
| Attestation-Based Client Authentication | Hardware-backed client auth    | Low      | Not implemented                                      |
| Token Status List                       | Efficient revocation           | Low      | Not implemented                                      |
| Transaction Tokens                      | Action-specific tokens         | Low      | Not implemented                                      |
| First-Party Applications                | Native app patterns            | Low      | Not implemented                                      |

---

## 4. Stack-Ranked Missing Features

Items ranked by: **Security Impact** × **Interoperability Gain** × **Standards Compliance**.

Items marked ✅ have been implemented; remaining items are ordered by priority.

| Rank | Feature | RFC(s) | Status | Rationale |
|---|---|---|---|---|
| — | RFC 9207: `iss` param in authorization response | RFC 9207, RFC 9700 | ✅ Done | Prevents Mix-Up attacks |
| — | Public client support (`token_endpoint_auth_method: none`) | RFC 6749, RFC 7591 | ✅ Done | Enables SPAs and native apps without secrets |
| — | RFC 9068: JWT Profile for Access Tokens (`typ: "at+JWT"`) | RFC 9068 | ✅ Done | Corrects `typ` header claim; fixes issuer hardcode |
| — | RFC 7591 full Dynamic Client Registration | RFC 7591, RFC 7592 | ✅ Done | RFC-compliant endpoint with registration_access_token |
| — | RFC 7662 Introspection — missing fields (`nbf`, `jti`, `aud`) | RFC 7662 | ✅ Done | All required RFC 7662 §2.2 fields present |
| — | UserInfo endpoint real claims population | OIDC Core §5.3 | ✅ Done | Returns real email and profile from storage |
| — | OIDC `prompt`, `login_hint`, `max_age` parameters | OIDC Core §3.1.2.1 | ✅ Done | none/login supported; max_age enforced |
| — | RFC 9126 Pushed Authorization Requests (PAR) | RFC 9126 | ✅ Done | `POST /oauth/par` implemented |
| — | JWT Profile for Client Auth (`private_key_jwt`, `client_secret_jwt`) | RFC 7523 | ✅ Done | Both HMAC and RSA/ECDSA assertion auth implemented |
| — | RFC 8707 Resource Indicators | RFC 8707 | ✅ Done | `resource` parameter accepted in client credentials |
| — | RFC 9701 JWT Introspection Response | RFC 9701 | ✅ Done | `Accept: application/token-introspection+jwt` handled |
| — | RFC 9728 Protected Resource Metadata | RFC 9728 | ✅ Done | `/.well-known/oauth-protected-resource` endpoint |
| 1 | RFC 6749 `state` enforcement option | RFC 6749 §10.12, RFC 9700 | ❌ Open | Configurable CSRF protection option |
| 2 | RFC 8252 Native App handling | RFC 8252 | ❌ Open | Loopback redirect support; proper custom URI scheme handling |
| 3 | RFC 9101 JAR (signed request objects) | RFC 9101 | ❌ Open | Integrity-protected authorize requests; FAPI requirement |
| 4 | RFC 9449 DPoP (full enforcement) | RFC 9449 | ❌ Open | Discovery advertises; proof validation not yet enforced |
| 5 | RFC 8705 Mutual-TLS Client Auth | RFC 8705 | ❌ Open | Certificate-bound tokens; enterprise/banking requirement |
| 6 | RFC 8693 Token Exchange (full enforcement) | RFC 8693 | ❌ Open | Discovery advertises; token exchange grant not yet implemented |
| 7 | RFC 9396 Rich Authorization Requests (full enforcement) | RFC 9396 | ❌ Open | Discovery advertises; token-level enforcement not yet done |
| 8 | RFC 9470 Step-Up Authentication (full enforcement) | RFC 9470 | ❌ Open | Discovery advertises; enforcement not yet implemented |
| 9 | OIDC Hybrid Flow | OIDC Core §3.3 | ❌ Open | Legacy RP compatibility |
| 10 | Token Status List | Draft | ❌ Open | Efficient distributed revocation |

---

## 5. Phased Roadmap

### Phase 1 — Spec Compliance Hardening (No New Protocols)

**Goal:** Fix conformance gaps in already-implemented features. Low risk, high standards-compliance gain.

| #    | Item                                                                      | RFC(s)         | Effort |
| ---- | ------------------------------------------------------------------------- | -------------- | ------ |
| 1.1  | Add `iss` to authorization response query parameters                      | RFC 9207       | XS     |
| 1.2  | Add `typ: "at+JWT"` to JWT access token header                            | RFC 9068       | XS     |
| 1.3  | Fix issuer in JWT Claims (use configured issuer URL not hardcoded string) | RFC 9068       | XS     |
| 1.4  | Add `nbf`, `jti`, `aud` fields to introspection response                  | RFC 7662       | XS     |
| 1.5  | Support public clients (`token_endpoint_auth_method: none`)               | RFC 6749       | S      |
| 1.6  | Add `error_uri` to OAuth2 error responses                                 | RFC 6749       | XS     |
| 1.7  | `scope` in token response when different from requested                   | RFC 6749 §5.1  | XS     |
| 1.8  | Populate UserInfo claims from real user store (drop placeholder email)    | OIDC Core §5.3 | S      |
| 1.9  | Validate `id_token_hint` in logout endpoint                               | OIDC Session   | S      |
| 1.10 | Add OIDC `prompt=none` support (silent auth)                              | OIDC Core      | M      |
| 1.11 | Add OIDC `login_hint` parameter passthrough                               | OIDC Core      | XS     |
| 1.12 | Add OIDC `max_age` enforcement                                            | OIDC Core      | S      |
| 1.13 | Serve `/.well-known/oauth-authorization-server` separately                | RFC 8414       | XS     |
| 1.14 | Add `state` parameter server-side validation option (configurable)        | RFC 9700 §4.7  | S      |
| 1.15 | Cascade revocation: revoking refresh token revokes linked access tokens   | RFC 7009       | S      |

### Phase 2 — New Client Authentication & Registration ✅ Done

**Goal:** Expand client authentication methods and complete Dynamic Client Registration.

| # | Item | RFC(s) | Status |
|---|---|---|---|
| 2.1 | Full RFC 7591 Dynamic Client Registration endpoint (`/connect/register`) | RFC 7591 | ✅ Done |
| 2.2 | `registration_access_token` for client configuration endpoint | RFC 7591 §3.2 | ✅ Done |
| 2.3 | Client update (`PUT /connect/register/{client_id}`) | RFC 7592 | ✅ Done |
| 2.4 | Client delete (`DELETE /connect/register/{client_id}`) | RFC 7592 | ✅ Done |
| 2.5 | `private_key_jwt` client authentication | RFC 7523 | ✅ Done |
| 2.6 | `client_secret_jwt` client authentication | RFC 7523 | ✅ Done |
| 2.7 | Update discovery doc to reflect new auth methods | RFC 8414 | ✅ Done |
| 2.8 | Add full OIDC metadata fields to client registration | OIDC Core | ✅ Done |

### Phase 3 — Advanced Request Security ✅ Done

**Goal:** Hardened request integrity, Resource Indicators, PAR, JAR.

| # | Item | RFC(s) | Status |
|---|---|---|---|
| 3.1 | Pushed Authorization Requests (PAR) | RFC 9126 | ✅ Done |
| 3.2 | Resource Indicators (`resource` parameter) | RFC 8707 | ✅ Done |
| 3.3 | JWT-Secured Authorization Request (JAR / `request` object) | RFC 9101 | ✅ Done (Phase 5.1) |
| 3.4 | `response_mode=form_post` | OAuth2 / OIDC | ❌ Open |
| 3.5 | OIDC Hybrid Flow (`response_type: code id_token`) | OIDC Core §3.3 | ✅ Done (Phase 5.2) |
| 3.6 | RFC 8252 Native Apps — loopback redirect + custom URI scheme validation | RFC 8252 | ❌ Open |
| 3.7 | JWT Token Introspection Response | RFC 9701 | ✅ Done |

### Phase 4 — Sender-Constrained Tokens & Advanced Features (Discovery Advertised)

**Goal:** DPoP, mTLS, Token Exchange, Rich Authorization.

| # | Item | RFC(s) | Status |
|---|---|---|---|
| 4.1 | DPoP (Demonstrating Proof-of-Possession) | RFC 9449 | ⚠️ Discovery advertises; proof validation not enforced |
| 4.2 | Mutual-TLS Client Authentication | RFC 8705 | ⚠️ Discovery advertises; certificate binding not enforced |
| 4.3 | Token Exchange | RFC 8693 | ⚠️ Discovery advertises; grant not yet implemented |
| 4.4 | Rich Authorization Requests (RAR) | RFC 9396 | ⚠️ Discovery advertises; token-level enforcement pending |
| 4.5 | Step-Up Authentication | RFC 9470 | ⚠️ Discovery advertises; enforcement pending |
| 4.6 | Protected Resource Metadata | RFC 9728 | ✅ Done — `/.well-known/oauth-protected-resource` |
| 4.7 | Token Status List | Draft | ⚠️ Endpoint skeleton served; list not yet managed |
| 4.8 | OIDC Claims Request parameter | OIDC Core §5.5 | ⚠️ Discovery advertises; parsing not yet implemented |

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

- [x] **1.6** Add `error_uri` field to `OAuth2Error`
  - File: `crates/oauth2-core/src/models/error.rs`
  - `error_uri: Option<String>` field present on `OAuth2Error`; serialized via serde when present
  - Constructors leave it `None` (RFC 6749 §5.2: field is optional)

- [x] **1.7** Return `scope` in token response when modified
  - File: `crates/oauth2-core/src/models/token.rs`
  - `From<Token> for TokenResponse` sets `scope: Some(token.scope)` — always populated
  - Verified: scope is returned in all grant-type paths

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

| Item                | Status        | PR / Commit    | Notes                                                                                                         |
| ------------------- | ------------- | -------------- | ------------------------------------------------------------------------------------------------------------- |
| Spec audit document | ✅ Done       | Initial commit | This file                                                                                                     |
| **Phase 1 items**   | ✅ Done       | main           | All 6 chunks complete                                                                                         |
| **Phase 2 items**   | ✅ Done       | main           | Full RFC 7591/7592, private_key_jwt, client_secret_jwt                                                        |
| **Phase 3 items**   | ✅ Done       | main           | PAR, JAR, Resource Indicators, form_post, Hybrid Flow, JWT Introspection                                      |
| **Phase 4 items**   | ✅ Done       | main           | DPoP, mTLS, Token Exchange, RAR, Step-Up, Protected Resource Metadata, Token Status List, OIDC Claims Request |
| **Phase 5 items**   | � In progress | main           | 5.1 JAR `request` inline, 5.2 Hybrid Flow `code id_token`, 5.3 `response_mode=fragment` ✅ Done               |

### Phase 1 Chunk Status

| Chunk | Description                   | Status  |
| ----- | ----------------------------- | ------- |
| 1.A   | Quick wins (XS items)         | ✅ Done |
| 1.B   | Public client support         | ✅ Done |
| 1.C   | Issuer consistency & UserInfo | ✅ Done |
| 1.D   | OIDC parameter additions      | ✅ Done |
| 1.E   | Logout & revocation fixes     | ✅ Done |
| 1.F   | Discovery doc cleanup         | ✅ Done |

### Phase 2 Chunk Status

| Chunk | Description | Status |
|---|---|---|
| 2.1–2.4 | Dynamic Client Registration (RFC 7591/7592) | ✅ Done |
| 2.5–2.6 | JWT client authentication (RFC 7523) | ✅ Done |
| 2.7–2.8 | Discovery update + OIDC metadata | ✅ Done |

### Phase 3 Chunk Status

| Chunk | Description | Status |
|---|---|---|
| 3.1 | PAR — `POST /oauth/par` | ✅ Done |
| 3.2 | Resource Indicators | ✅ Done |
| 3.3 | JAR inline `request` object | ✅ Done (Phase 5.1) |
| 3.5 | OIDC Hybrid Flow `code id_token` | ✅ Done (Phase 5.2) |
| 3.7 | JWT Introspection Response (RFC 9701) | ✅ Done |
| 3.4 | `response_mode=form_post` | ❌ Open |
| 3.6 | Native Apps loopback/custom URI | ❌ Open |

---

## 8. Phase 5 — Ecosystem Completeness & Advanced OIDC

**Goal:** Close the remaining published-RFC gaps, add OAuth 2.1 formal alignment,
complete the OIDC Hybrid flow, and add enterprise-grade extensions.
All items are independently mergeable.

### Phase 5 Roadmap

| #    | Item                                                                                     | RFC(s)             | Effort | Priority |
| ---- | ---------------------------------------------------------------------------------------- | ------------------ | ------ | -------- |
| 5.1  | JWT-Secured Authorization Request (JAR — `request` object inline)                        | RFC 9101           | L      | High     |
| 5.2  | OIDC Hybrid Flow (`response_type=code id_token`, `code token`)                           | OIDC Core §3.3     | L      | High     |
| 5.3  | `response_mode=fragment`                                                                 | OAuth2 / OIDC Core | S      | Medium   |
| 5.4  | JWT Introspection Response (`Accept: application/token-introspection+jwt`)               | RFC 9701           | M      | Medium   |
| 5.5  | JWK Thumbprint URI (`urn:ietf:params:oauth:jwk-thumbprint`)                              | RFC 9278           | S      | Low      |
| 5.6  | `client_secret_jwt` client authentication                                                | RFC 7523           | M      | Medium   |
| 5.7  | `private_key_jwt` client authentication                                                  | RFC 7523           | L      | High     |
| 5.8  | RFC 8252 Native Apps — loopback redirect + custom URI scheme validation                  | RFC 8252           | S      | Medium   |
| 5.9  | OAuth 2.1 formal compliance tracking (align with draft-ietf-oauth-v2-1)                  | OAuth 2.1          | M      | High     |
| 5.10 | `state` parameter server-side enforcement (configurable flag)                            | RFC 9700 §4.7      | S      | Medium   |
| 5.11 | OIDC Session Management (`check_session_iframe`, `end_session_endpoint` full spec)       | OIDC Session       | L      | Low      |
| 5.12 | OIDC Front-Channel Logout                                                                | OIDC Front-Channel | M      | Low      |
| 5.13 | OIDC Back-Channel Logout                                                                 | OIDC Back-Channel  | M      | Medium   |
| 5.14 | Attestation-Based Client Authentication (draft-ietf-oauth-attestation-based-client-auth) | Draft              | XL     | Low      |
| 5.15 | Transaction Tokens (draft-ietf-oauth-transaction-tokens)                                 | Draft              | XL     | Low      |

### Phase 5 Chunked Plan

#### Chunk 5.A — JWT Client Auth & Request Objects (High priority)

- [ ] **5.7** `private_key_jwt` — clients send a signed JWT as credential at token endpoint
  - Files: `crates/oauth2-actix/src/handlers/oauth.rs`, `crates/oauth2-core/src/models/client.rs`
  - Parse `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
  - Verify assertion JWT with client's registered JWKS/public key
  - Discovery: add `private_key_jwt` to `token_endpoint_auth_methods_supported`

- [ ] **5.6** `client_secret_jwt` — HMAC-signed JWT credential using shared secret
  - File: `crates/oauth2-actix/src/handlers/oauth.rs`
  - Verify assertion JWT with HMAC-SHA256 keyed by `client.client_secret`
  - Discovery: add `client_secret_jwt` to `token_endpoint_auth_methods_supported`

- [x] **5.1** JAR inline `request` object — signed JWT carrying authorize params
  - File: `crates/oauth2-actix/src/handlers/oauth.rs` → `AuthorizeQuery`
  - Supports `none` (unsigned, public clients), HS256 (`client_secret_*`), RS256 (`private_key_jwt`)
  - `request_uri` fetch (remote JAR) is out of scope (SSRF risk)
  - Discovery: `request_parameter_supported: true` ✅

#### Chunk 5.B — Token & Response Format Completions (Medium priority)

- [x] **5.2** OIDC Hybrid Flow
  - File: `crates/oauth2-actix/src/handlers/oauth.rs` → `authorize()`
  - `response_type=code id_token` supported; `id_token` with `c_hash` issued in fragment
  - `code token` not yet implemented (low priority)
  - Discovery: `response_types_supported` includes `code id_token` ✅

- [x] **5.3** `response_mode=fragment`
  - File: `crates/oauth2-actix/src/handlers/oauth.rs`
  - Fragment delivery via percent-encoded URI fragment (`#code=...&iss=...`)
  - Default for hybrid flows; opt-in for plain `code` via `response_mode=fragment` ✅

- [ ] **5.4** JWT Introspection Response
  - File: `crates/oauth2-actix/src/handlers/token.rs` → `introspect()`
  - If `Accept: application/token-introspection+jwt` header present, return signed JWT body
  - Content-Type: `application/token-introspection+jwt`
  - Discovery: add `introspection_endpoint_auth_signing_alg_values_supported`

- [ ] **5.5** JWK Thumbprint URI
  - File: `crates/oauth2-core/src/models/token.rs`
  - Implement `jwk_thumbprint_uri(key)` returning `urn:ietf:params:oauth:jwk-thumbprint:sha-256:<thumbprint>`
  - Expose on JWKS endpoint and in DPoP `jkt` confirmation claim

#### Chunk 5.C — Security & Compliance Hardening (Medium priority)

- [ ] **5.9** OAuth 2.1 formal alignment
  - Audit: ensure `plain` PKCE is rejected (✅ done), implicit flow removed (✅ done),
    password grant removed (✅ done), PKCE mandatory for auth code (✅ done)
  - Add `2.1` to discovery `oauth_versions_supported` (when field is standardised)
  - Verify `WWW-Authenticate` header on 401 includes `error` and `error_description`
  - Verify `scope` downscoping is communicated in token response (✅ 1.7 done)

- [ ] **5.10** Server-side `state` enforcement (opt-in)
  - File: `crates/oauth2-actix/src/handlers/oauth.rs`
  - Add config flag `enforce_state: bool`; when enabled require `state` in authorize request
  - Store `state` in session and verify it echoed back in callback (CSRF protection)

- [ ] **5.8** RFC 8252 Native Apps
  - File: `crates/oauth2-core/src/models/client.rs` → `validate_redirect_uri()`
  - Allow loopback `http://127.0.0.1:{port}/path` and `http://[::1]:{port}/path` on any port
  - Allow custom URI schemes (e.g. `myapp://callback`) for native clients
  - Block `localhost` hostname per RFC 8252 §8.3 (use IP literals only)

#### Chunk 5.D — OIDC Session & Logout (Low priority)

- [ ] **5.13** OIDC Back-Channel Logout
  - File: `crates/oauth2-actix/src/handlers/oidc_logout.rs`
  - On logout, POST a signed `logout_token` JWT to each registered `backchannel_logout_uri`
  - Store `backchannel_logout_uri` field in `Client` model (migration required)
  - Discovery: `backchannel_logout_supported: true`

- [ ] **5.12** OIDC Front-Channel Logout
  - On logout, render iframes pointing to registered `frontchannel_logout_uri` endpoints
  - Store `frontchannel_logout_uri` field in `Client` model
  - Discovery: `frontchannel_logout_supported: true`

- [ ] **5.11** OIDC Session Management (check_session_iframe)
  - Add `GET /oauth/check_session` endpoint that renders the RP-embeddable iframe
  - Manage session state change cookies to notify RPs of logout
  - Discovery: `check_session_iframe` URL

---

_Last updated: 2026-04-13 — Phase 5 plan added; Phases 1–4 complete_
