# Copilot Instructions — rust-oauth2-server

## CI Gate Checklist

Before considering any code change complete, **always** run the full CI
gate sequence locally and fix any failures:

```bash
# 1. Formatting (must exit 0)
cargo fmt --all -- --check

# 2. Lints — warnings are errors (must exit 0)
cargo clippy --all-targets --all-features -- -D warnings

# 3. Tests (must exit 0)
cargo test --verbose --all-features --locked
```

If `cargo fmt` fails, run `cargo fmt --all` to auto-fix, then re-check.

## Common Pitfalls

- **Long lines**: `tracing::debug!(...)` with multiple fields and chained
  `.map_err(|e| ...)` calls frequently exceed the line-length limit.
  Always verify formatting after adding tracing or error-mapping code.
- **Conditional compilation**: Variables mutated only inside
  `#[cfg(feature = "...")]` blocks produce `unused_mut` warnings when
  the feature is off. Annotate them with `#[allow(unused_mut)]`.
- **Test app_data**: Any new `web::Data<T>` parameter added to a handler
  must also be injected in every test setup in `tests/security_http.rs`
  (there are 15+ test functions with independent `App::new()` builders).

## Project Structure

- Workspace with multiple crates under `crates/`.
- Feature flags: `redis-cache`, `mongo`, `sqlx` (default).
- Actix-web 4 + Actix actors for the HTTP/actor layer.
- Tests live in `tests/` (integration) and inline `#[cfg(test)]` modules.

## RFC Compliance Testing

See `CLAUDE.md` for full agent memory and `docs/oauth2-spec-audit.md` for the
authoritative roadmap. Key points for Copilot:

### Test Files

| File | Purpose |
|---|---|
| `tests/rfc_compliance.rs` | Phase 1 RFC spec compliance tests |
| `tests/security_http.rs` | Security / HTTP integration tests |
| `tests/device_flow.rs` | RFC 8628 device flow |
| `tests/opaque_tokens.rs` | Opaque token issuance + introspection |

### Invariants — Never Break These

- **`TokenActor::new(storage, jwt_secret, issuer)`** takes 3 args.
  The `issuer: String` was added for RFC 9068/9207 compliance. All 5 call
  sites must stay in sync (`tests/` ×4, `crates/oauth2-server/src/lib.rs`).

- **`Claims::new(subject, client_id, scope, duration_seconds, issuer: &str)`** takes
  5 args. The issuer is passed from `TokenActor.issuer`.

- **`Client::is_public()`** returns `true` when
  `token_endpoint_auth_method == "none"`. Public clients skip secret checks and
  rely on PKCE.

- **JWT access tokens** must carry `typ: "at+JWT"` in the JOSE header
  (RFC 9068). Both `Claims::encode()` and `Claims::encode_with_key()` set this.

- **Introspection responses** must include `nbf`, `jti`, `aud`, `iss`
  (RFC 7662 §2.2). These fields are in `IntrospectionResponse` in
  `crates/oauth2-core/src/models/token.rs`.

- **Authorization responses** must include `iss` query parameter (RFC 9207).
  Set in `authorize()` in `crates/oauth2-actix/src/handlers/oauth.rs`.

### Adding a New RFC Test

1. Add a `#[actix_web::test]` function to `tests/rfc_compliance.rs`.
2. Call `setup_rfc_context(clients, issuer)` — returns
   `(TokenActorPool, Addr<ClientActor>, Addr<AuthActor>, String, Metrics, OidcConfig)`.
3. Build the `App` inline (do NOT use a helper returning `impl Service`).
4. Add `Arc<RwLock<KeySet>>` and `web::Data::new(false)` (stateless_validation)
   to every `App::new()` for handlers under `oauth::` or `wellknown::`.
5. Annotate the test with a comment citing the exact RFC section.

### Phase 1 Status (branch `claude/oauth2-spec-audit-UheZ5`)

| Chunk | Items | Status |
|---|---|---|
| 1.A | `iss` in auth response, `typ: "at+JWT"`, issuer threading, RFC 7662 fields, `login_hint`, `/.well-known/oauth-authorization-server` | Done |
| 1.B | Public client `token_endpoint_auth_method=none`, DB migration V12, registration validation | Done |
| 1.C | UserInfo real claims from storage | Done |
| 1.D | `prompt=none/login`, `max_age` | Done |
| 1.E | `id_token_hint` validation, cascade revocation | Done |
| 1.F | Discovery doc cleanup | Done |

## Caretaker

This repo uses the [caretaker](https://github.com/ianlintner/caretaker) autonomous
maintenance system. The orchestrator runs weekly via GitHub Actions and assigns tasks to
`@copilot` via structured issue and PR comments.

Agent instruction files live in `.github/agents/`:
- `maintainer-pr.md` — how to respond to PR fix requests
- `maintainer-issue.md` — how to execute assigned issues
- `maintainer-upgrade.md` — how to apply caretaker upgrades

Always check these files when you receive a caretaker assignment.
