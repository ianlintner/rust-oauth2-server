# Claude Code Agent Memory — rust-oauth2-server

This file gives Claude Code (and any AI agent) the persistent context it needs
to work effectively on this codebase. Read it at the start of every session.

---

## Project Overview

A complete OAuth2 / OIDC authorization server written in Rust, using Actix-web
and the Actix actor model. Hosted in a Cargo workspace.

- **Branch for active development:** `claude/oauth2-spec-audit-UheZ5`
- **Authoritative roadmap:** `docs/oauth2-spec-audit.md`
- **Crate version:** `0.0.10`

---

## Repository Layout

```
crates/
  oauth2-actix/       HTTP handlers (actix-web) + Actix actors
  oauth2-core/        Core domain models (Client, Token, User, Claims, …)
  oauth2-config/      Runtime configuration (Config struct)
  oauth2-server/      High-level server wiring + lib.rs
  oauth2-storage-sqlx/  SQLite / PostgreSQL storage backend
  oauth2-storage-mongo/ MongoDB storage backend
  oauth2-storage-factory/ Storage backend selector
  oauth2-ports/       DynStorage trait abstraction
  oauth2-observability/ Metrics / tracing
  oauth2-events/      Event bus (Kafka / RabbitMQ / Redis Streams)
  oauth2-openapi/     OpenAPI spec export
  oauth2-social-login/ GitHub / Google / Microsoft social login

migrations/sql/       Flyway-style versioned SQL migrations (V1__…V12__)
tests/                Root-crate integration tests (see below)
docs/                 Design docs, spec audit
```

---

## Key Actors & Signatures

### `TokenActor` — `crates/oauth2-actix/src/actors/token_actor.rs`

```rust
// Constructor (3 args — issuer was added in Phase 1)
TokenActor::new(storage: DynStorage, jwt_secret: String, issuer: String) -> Self

// Constructor with event bus (4 args)
TokenActor::with_events(storage, jwt_secret, issuer, event_bus) -> Self

// Fluent builder
.with_access_tokens_opaque(bool) -> Self
```

**Every call site must supply `issuer`.** There are currently 4 external call
sites that must be kept in sync whenever the signature changes:

| File | Notes |
|---|---|
| `tests/opaque_tokens.rs` | `"http://localhost"` |
| `tests/security_http.rs` (×2) | `"http://localhost"` |
| `tests/device_flow.rs` | `"http://localhost"` |
| `crates/oauth2-server/src/lib.rs` | uses `issuer.clone()` from config |

### `Claims::new()` — `crates/oauth2-core/src/models/token.rs`

```rust
Claims::new(subject, client_id, scope, duration_seconds, issuer: &str) -> Self
```

Fifth parameter `issuer` was added in Phase 1 (previously hardcoded
`"rust_oauth2_server"`).

### `Client::is_public()` — `crates/oauth2-core/src/models/client.rs`

```rust
pub fn is_public(&self) -> bool {
    self.token_endpoint_auth_method == "none"
}
```

Public clients skip secret validation and must use PKCE.  
`token_endpoint_auth_method` defaults to `"client_secret_basic"` for all
existing clients (migration `V12__add_token_endpoint_auth_method.sql`).

---

## JWT Token Details (RFC 9068 — Phase 1 done)

- **JOSE header:** `typ: "at+JWT"` — set in `Claims::encode()` and
  `Claims::encode_with_key()`.
- **`iss` claim:** populated from the configured issuer URL, not a hardcoded
  string.
- **Introspection response** (`IntrospectionResponse`) now includes:
  `nbf`, `aud`, `jti`, `iss` (RFC 7662 §2.2).

---

## Test Files

| File | Purpose |
|---|---|
| `tests/rfc_compliance.rs` | RFC spec compliance tests (Phase 1) |
| `tests/security_http.rs` | Security / HTTP-level integration tests |
| `tests/device_flow.rs` | RFC 8628 Device Authorization Grant |
| `tests/opaque_tokens.rs` | Opaque access token issuance + introspection |
| `tests/bdd/` | Cucumber BDD feature tests (harness = false) |

### How to Run

```bash
# All integration tests
cargo test --verbose --all-features --locked

# Only RFC compliance tests
cargo test --test rfc_compliance

# Only security tests
cargo test --test security_http
```

---

## RFC Testing Architecture (`tests/rfc_compliance.rs`)

### Pattern

Every test follows this pattern (matches `security_http.rs` — do NOT use a
shared `App`-returning helper because Rust's type system makes that painful):

```rust
#[actix_web::test]
async fn my_rfc_test() {
    // 1. Build clients
    let client = Client::new(...);

    // 2. Set up context (returns raw components, not an App)
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc_context(vec![client], "https://auth.example.com").await;
    let keyset = Arc::new(RwLock::new(KeySet::default()));

    // 3. Build App inline in each test
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(keyset))
            .app_data(web::Data::new(false)) // stateless_validation: bool
            .service(web::scope("/oauth").route(...))
    ).await;

    // 4. Make requests and assert
    let resp = test::call_service(&app, ...).await;
    assert_eq!(resp.status(), 200);
}
```

### `setup_rfc_context()` signature

```rust
async fn setup_rfc_context(
    clients: Vec<Client>,
    issuer: &str,
) -> (TokenActorPool, Addr<ClientActor>, Addr<AuthActor>, String, Metrics, OidcConfig)
```

Uses `sqlite::memory:` — no temp files needed.  
Always creates a `user_rfc` / `user_rfc@example.test` user for authorization
code flows.

### `app_data` Required by Each Handler

| Handler | Required `app_data` types |
|---|---|
| `oauth::authorize` | TokenActorPool, ClientActor, AuthActor, String (jwt_secret), Metrics, OidcConfig, Arc<RwLock<KeySet>>, bool (stateless_validation) + **SessionMiddleware** |
| `oauth::token` | (same as above, minus SessionMiddleware for most grants) |
| `token::introspect` | (same) + `Config` |
| `wellknown::openid_configuration` | TokenActorPool, ClientActor, AuthActor, String, Metrics, OidcConfig, Arc<RwLock<KeySet>>, bool |
| `client::register_client` | ClientActor |

If a handler panics with `500` in tests, the most common cause is a missing
`app_data` entry — check this first.

---

## Current Phase 1 Progress

See `docs/oauth2-spec-audit.md` §6 for the full checklist.

| Chunk | Description | Status |
|---|---|---|
| 1.A | Quick wins: `iss` in auth response, `typ: "at+JWT"`, issuer threading, `nbf/jti/aud/iss` in introspection, `login_hint`, `/.well-known/oauth-authorization-server` | **Done** |
| 1.B | Public client support (`token_endpoint_auth_method=none`), DB migration V12, registration validation | **Done** |
| 1.C | Issuer consistency full threading, UserInfo real claims from storage | **Done** |
| 1.D | OIDC `prompt=none/login`, `max_age` enforcement | **Done** |
| 1.E | `id_token_hint` validation in logout, cascade refresh token revocation | **Done** |
| 1.F | Discovery doc cleanup (`authorization_response_iss_parameter_supported`, `prompt_values_supported`, `none` in auth methods) | **Done** |

---

## CI Gate — Must Pass Before Any PR

```bash
cargo fmt --all -- --check     # auto-fix: cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --verbose --all-features --locked
```

---

## Common Pitfalls

1. **New `app_data` parameter** → add it to every test in `tests/security_http.rs`
   (15+ independent `App::new()` builders) AND `tests/rfc_compliance.rs`.

2. **`TokenActor::new()` signature change** → update all 5 call sites (4 test
   files + `crates/oauth2-server/src/lib.rs`).

3. **DB migration** → every column added to `clients` / `tokens` / `users` needs
   a new `migrations/sql/Vn__description.sql` file AND the `save_*` functions in
   `crates/oauth2-storage-sqlx/src/sqlx.rs` (both SQLite and Postgres branches)
   AND the MongoDB equivalent in `crates/oauth2-storage-mongo/`.

4. **RFC test type errors** — do NOT return `impl Service<actix_http::Request>`
   from a helper. Return the raw component tuple and build `App` inline in each
   test function.

5. **`jsonwebtoken` crate** — used in production code by `oauth2-actix`
   (e.g., OIDC logout `id_token_hint` validation), so do **not** remove it
   or move it to dev-dependencies only. Tests also use it for header/claims
   inspection (`decode_header()`, `Validation`).

6. **`sqlite::memory:`** — preferred for RFC tests (no temp files, faster).
   Use a file path (`/tmp/oauth2_*.db`) only when the test needs to persist
   across actor restarts.

---

## RFC Reference Map

| RFC | Feature | Implementation Location |
|---|---|---|
| RFC 6749 | Core OAuth2 flows | `crates/oauth2-actix/src/handlers/oauth.rs` |
| RFC 7009 | Token Revocation | `crates/oauth2-actix/src/handlers/token.rs` |
| RFC 7519 | JWT | `crates/oauth2-core/src/models/token.rs` |
| RFC 7591 | Dynamic Client Registration | `crates/oauth2-actix/src/handlers/client.rs` |
| RFC 7636 | PKCE | `crates/oauth2-actix/src/handlers/oauth.rs` |
| RFC 7662 | Introspection | `crates/oauth2-actix/src/handlers/token.rs` + `crates/oauth2-core/src/models/token.rs` |
| RFC 8414 | AS Metadata | `crates/oauth2-actix/src/handlers/wellknown.rs` |
| RFC 8628 | Device Flow | `crates/oauth2-actix/src/handlers/device.rs` |
| RFC 9068 | JWT Profile for Access Tokens | `crates/oauth2-core/src/models/token.rs` |
| RFC 9207 | AS Issuer Identification | `crates/oauth2-actix/src/handlers/oauth.rs` (authorize redirect) |
| RFC 9700 | Security BCP | `crates/oauth2-actix/src/handlers/oauth.rs` + middleware |
| OIDC Core | ID tokens, UserInfo | `crates/oauth2-actix/src/handlers/wellknown.rs` + `oauth.rs` |
