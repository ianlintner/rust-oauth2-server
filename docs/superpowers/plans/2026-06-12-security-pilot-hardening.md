# Security Pilot Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the four high-confidence vulnerabilities found in the pre-pilot security review: an unauthenticated-to-admin privilege-escalation chain (Critical) and three reflected-XSS / token-lifetime bugs (High).

**Architecture:** Each fix is surgical and follows existing patterns. We extract pure, unit-testable helpers for the security-critical predicates (scope allow-list, HTML escaping, admin-client matching) so the core logic is tested fast and deterministically without env mutation or heavy actor harnesses, then wire those helpers into the handlers/middleware. Env-var-driven config reads use the existing `std::env::var` pattern already used by `AdminGuard::is_admin_email` (env values are trusted per the project threat model).

**Tech Stack:** Rust, Actix-web 4 + Actix actors, sqlx/Mongo storage, `serde_json`, `jsonwebtoken`, `url`. Tests use `actix_web::test` integration harnesses and `#[cfg(test)]` unit modules.

---

## Source Findings (the spec)

This plan implements fixes for the four findings that survived adversarial verification at confidence ≥ 8 in the security review:

1. **Critical — Unauthenticated admin escalation chain.** `POST /connect/register` is unauthenticated (`crates/oauth2-server/src/lib.rs:1417-1422`); `validate_registration` never constrains the requested `scope` (`crates/oauth2-actix/src/handlers/client.rs:114-151`), which is persisted verbatim; the `client_credentials` grant mints a token carrying that scope (`crates/oauth2-actix/src/handlers/oauth.rs:2154-2164`); and `AdminGuard`'s bearer path grants admin to *any* valid token whose scope contains `admin` (`crates/oauth2-actix/src/middleware/admin_guard.rs:88-93`).
2. **High — Reflected XSS in device verification page.** `verify_page` interpolates the `user_code` query param into HTML unescaped (`crates/oauth2-actix/src/handlers/device.rs:175,185`).
3. **High — Reflected XSS + open redirect in front-channel logout.** `build_frontchannel_logout_page` injects `post_logout_redirect_uri`/`state` into a `<script>` unescaped, and the front-channel branch skips the registered-URI validation the standard branch performs (`crates/oauth2-actix/src/handlers/oidc_logout.rs:213-222,347-358`).
4. **High — Token exchange accepts expired `subject_token`.** `handle_token_exchange_grant` checks only `subject_tok.revoked`, never expiry, then mints a fresh token (`crates/oauth2-actix/src/handlers/oauth.rs:2238-2281`).

## Design Decisions (confirmed with the user)

- **Critical fix is two layers (defense in depth):**
  - **Layer 1 — registration scope allow-list:** the public `/connect/register` and RFC 7592 update reject privileged scopes (`admin`, `write`). The operator-only `/admin/clients/register` endpoint is unaffected (it does not call `validate_registration`), so operators keep the ability to grant privileged scope deliberately.
  - **Layer 2 — AdminGuard client-id pin:** the bearer path additionally requires the token's `client_id` to be in an operator-configured `OAUTH2_ADMIN_CLIENT_IDS` allow-list. This keeps the documented machine-to-machine (MCP) use case working for the *configured* client while making an attacker-registered client useless even if it somehow holds `admin` scope.
- **Open dynamic registration is gated off by default:** a new `OAUTH2_DYNAMIC_REGISTRATION_ENABLED` env flag (default `false`) makes `POST /connect/register` return `403` unless an operator explicitly opts in. `/admin/clients/register` remains the default registration path.

## File Structure (what changes and why)

| File | Responsibility | Change |
|---|---|---|
| `crates/oauth2-actix/src/handlers/client.rs` | Client registration (RFC 7591/7592) | Add `OAUTH2_DYNAMIC_REGISTRATION_ENABLED` gate to `dynamic_register`; add privileged-scope rejection to `validate_registration`; add pure helpers + unit tests |
| `crates/oauth2-actix/src/middleware/admin_guard.rs` | Admin route gating | Bearer path also requires `client_id ∈ OAUTH2_ADMIN_CLIENT_IDS`; add pure matcher + unit tests |
| `crates/oauth2-actix/src/handlers/login.rs` | Login + shared `html_escape` | Promote `html_escape` from private `fn` to `pub(crate) fn` so device/logout pages can reuse it (DRY) |
| `crates/oauth2-actix/src/handlers/device.rs` | Device verification page | Extract pure `render_device_verify_page` that escapes `user_code`; unit test |
| `crates/oauth2-actix/src/handlers/oidc_logout.rs` | RP-initiated logout | Validate `post_logout_redirect_uri` in the front-channel branch; JSON-encode the redirect URL in the builder; unit test |
| `crates/oauth2-actix/src/handlers/oauth.rs` | Token endpoint grants | Reject expired/revoked `subject_token` in token exchange |
| `tests/security_token_exchange_expiry.rs` | New integration test | Proves expired `subject_token` is rejected |
| `docs/oauth2-spec-audit.md` (or CHANGELOG) | Docs | Note the two new env vars and default-off registration |

---

### Task 1: Gate `POST /connect/register` behind `OAUTH2_DYNAMIC_REGISTRATION_ENABLED`

**Files:**
- Modify: `crates/oauth2-actix/src/handlers/client.rs` (add helpers near `validate_registration` ~line 112; gate inside `dynamic_register` ~line 217)
- Test: `crates/oauth2-actix/src/handlers/client.rs` (new `#[cfg(test)] mod registration_security_tests` at end of file)

- [ ] **Step 1: Write the failing unit test for the pure flag parser**

Add at the very end of `crates/oauth2-actix/src/handlers/client.rs`:

```rust
#[cfg(test)]
mod registration_security_tests {
    use super::*;

    #[test]
    fn registration_disabled_by_default() {
        assert!(!parse_registration_enabled(None));
    }

    #[test]
    fn registration_enabled_only_for_true() {
        assert!(parse_registration_enabled(Some("true")));
        assert!(!parse_registration_enabled(Some("false")));
        assert!(!parse_registration_enabled(Some("1")));
        assert!(!parse_registration_enabled(Some("garbage")));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p oauth2-actix registration_security_tests -- --nocapture`
Expected: FAIL — `cannot find function parse_registration_enabled in this scope`.

- [ ] **Step 3: Add the pure parser and env wrapper**

Insert immediately above `fn validate_registration` (currently line 112) in `crates/oauth2-actix/src/handlers/client.rs`:

```rust
/// Parse the dynamic-registration enable flag. Defaults to `false` (disabled)
/// for any absent or non-`"true"` value, so open registration is opt-in.
fn parse_registration_enabled(val: Option<&str>) -> bool {
    val.and_then(|v| v.parse::<bool>().ok()).unwrap_or(false)
}

/// Whether the public RFC 7591 `POST /connect/register` endpoint is enabled.
/// Controlled by `OAUTH2_DYNAMIC_REGISTRATION_ENABLED` (trusted env var).
fn dynamic_registration_enabled() -> bool {
    parse_registration_enabled(std::env::var("OAUTH2_DYNAMIC_REGISTRATION_ENABLED").ok().as_deref())
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p oauth2-actix registration_security_tests -- --nocapture`
Expected: PASS (2 tests).

- [ ] **Step 5: Gate the handler**

In `crates/oauth2-actix/src/handlers/client.rs`, at the top of `dynamic_register` (currently line 217, immediately after the `{` and before `normalise_registration`), insert:

```rust
    if !dynamic_registration_enabled() {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "access_denied",
            "error_description": "Dynamic client registration is disabled",
        })));
    }
```

- [ ] **Step 6: Verify the crate still builds and tests pass**

Run: `cargo test -p oauth2-actix registration_security_tests` and `cargo build -p oauth2-actix`
Expected: build succeeds; tests PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/oauth2-actix/src/handlers/client.rs
git commit -m "fix(registration): gate public dynamic registration behind OAUTH2_DYNAMIC_REGISTRATION_ENABLED (default off)"
```

---

### Task 2: Reject privileged scopes at registration (scope allow-list)

**Files:**
- Modify: `crates/oauth2-actix/src/handlers/client.rs` (add helper; call it inside `validate_registration` ~line 121)
- Test: `crates/oauth2-actix/src/handlers/client.rs` (extend `registration_security_tests`)

- [ ] **Step 1: Write the failing unit test**

Add these tests inside the existing `registration_security_tests` module in `crates/oauth2-actix/src/handlers/client.rs`:

```rust
    #[test]
    fn rejects_privileged_scopes() {
        assert!(scope_contains_privileged("openid admin"));
        assert!(scope_contains_privileged("write"));
        assert!(scope_contains_privileged("ADMIN")); // case-insensitive
    }

    #[test]
    fn allows_normal_scopes() {
        assert!(!scope_contains_privileged("openid profile email read"));
        assert!(!scope_contains_privileged("")); // empty handled elsewhere
        assert!(!scope_contains_privileged("administrator")); // not an exact token match
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p oauth2-actix registration_security_tests`
Expected: FAIL — `cannot find function scope_contains_privileged in this scope`.

- [ ] **Step 3: Add the privileged-scope helper**

Insert above `fn validate_registration` in `crates/oauth2-actix/src/handlers/client.rs` (next to the Task 1 helpers):

```rust
/// Scopes that confer elevated authority and must never be self-assigned via
/// the public RFC 7591 registration or RFC 7592 update endpoints. Operators can
/// still grant them deliberately through the admin endpoint.
const PRIVILEGED_SCOPES: &[&str] = &["admin", "write"];

/// True if any space-delimited token in `scope` is a privileged scope
/// (case-insensitive, exact-token match — `"administrator"` does not match).
fn scope_contains_privileged(scope: &str) -> bool {
    scope.split_whitespace().any(|s| {
        PRIVILEGED_SCOPES
            .iter()
            .any(|p| p.eq_ignore_ascii_case(s))
    })
}
```

- [ ] **Step 4: Run the unit test to verify it passes**

Run: `cargo test -p oauth2-actix registration_security_tests`
Expected: PASS (4 tests total).

- [ ] **Step 5: Enforce the allow-list in `validate_registration`**

In `crates/oauth2-actix/src/handlers/client.rs`, inside `validate_registration`, immediately after the `validate_token_endpoint_auth_method(...)?;` line (currently line 122) add:

```rust
    if scope_contains_privileged(&reg.scope) {
        return Err(OAuth2Error::invalid_client_metadata(
            "requested scope includes a privileged scope that may not be self-registered",
        ));
    }
```

> Note: if `OAuth2Error::invalid_client_metadata` does not exist, use `OAuth2Error::invalid_request(...)` with the same message — confirm by checking `crates/oauth2-core/src/error.rs` for an `invalid_client_metadata` constructor (RFC 7591 §3.2.2 defines `invalid_client_metadata`). Prefer the RFC-specific constructor if present.

- [ ] **Step 6: Run unit tests and build**

Run: `cargo test -p oauth2-actix registration_security_tests && cargo build -p oauth2-actix`
Expected: build succeeds; tests PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/oauth2-actix/src/handlers/client.rs
git commit -m "fix(registration): reject privileged scopes (admin/write) from public registration and RFC 7592 update"
```

---

### Task 3: Pin AdminGuard bearer path to `OAUTH2_ADMIN_CLIENT_IDS`

**Files:**
- Modify: `crates/oauth2-actix/src/middleware/admin_guard.rs` (add matcher near `is_admin_email` ~line 52; add check in bearer path ~line 90)
- Test: `crates/oauth2-actix/src/middleware/admin_guard.rs` (new `#[cfg(test)] mod tests` at end of file)

- [ ] **Step 1: Write the failing unit test**

Add at the very end of `crates/oauth2-actix/src/middleware/admin_guard.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_allowlist_denies_all() {
        assert!(!client_id_in_allowlist("mcp", ""));
        assert!(!client_id_in_allowlist("mcp", "   "));
    }

    #[test]
    fn matches_exact_trimmed_entry() {
        assert!(client_id_in_allowlist("mcp", "mcp"));
        assert!(client_id_in_allowlist("mcp", " other , mcp , third "));
        assert!(!client_id_in_allowlist("mcp", "mcp_evil,other"));
        assert!(!client_id_in_allowlist("attacker", "mcp,other"));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p oauth2-actix --lib admin_guard::tests`
Expected: FAIL — `cannot find function client_id_in_allowlist in this scope`.

- [ ] **Step 3: Add the matcher and env wrapper**

Insert immediately below `fn is_admin_email` (currently ends line 62) in `crates/oauth2-actix/src/middleware/admin_guard.rs`:

```rust
/// True if `client_id` is an exact, trimmed entry in the comma-separated
/// `allowlist`. Empty/whitespace allowlist denies all (fail-closed).
fn client_id_in_allowlist(client_id: &str, allowlist: &str) -> bool {
    allowlist
        .split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .any(|e| e == client_id)
}

/// Whether the given bearer-token client_id is permitted to assume admin
/// authority. Controlled by `OAUTH2_ADMIN_CLIENT_IDS` (trusted env var).
/// Fail-closed: when the env var is unset, no machine client is admin.
fn is_admin_client(client_id: &str) -> bool {
    match std::env::var("OAUTH2_ADMIN_CLIENT_IDS") {
        Ok(list) => client_id_in_allowlist(client_id, &list),
        Err(_) => false,
    }
}
```

- [ ] **Step 4: Run the unit test to verify it passes**

Run: `cargo test -p oauth2-actix --lib admin_guard::tests`
Expected: PASS (2 tests).

- [ ] **Step 5: Add the client-id check to the bearer path**

In `crates/oauth2-actix/src/middleware/admin_guard.rs`, change the bearer-admin condition. Replace the block currently at lines 88-93:

```rust
                                    let scopes: Vec<&str> =
                                        token.scope.split_whitespace().collect();
                                    if scopes.contains(&"admin") {
                                        let res = svc.call(req).await?;
                                        return Ok(res.map_into_left_body());
                                    }
```

with:

```rust
                                    let scopes: Vec<&str> =
                                        token.scope.split_whitespace().collect();
                                    // Both conditions required: the token must carry the
                                    // `admin` scope AND be issued to a client that the
                                    // operator explicitly trusts for admin (env allow-list).
                                    // This blocks self-registered clients that obtain the
                                    // `admin` scope from reaching admin routes.
                                    if scopes.contains(&"admin") && is_admin_client(&token.client_id) {
                                        let res = svc.call(req).await?;
                                        return Ok(res.map_into_left_body());
                                    }
```

> Note: confirm the field name is `token.client_id` by checking the `Token` struct in `crates/oauth2-core/src/models/token.rs` (it is `client_id: String`, used throughout the codebase).

- [ ] **Step 6: Build and run all admin_guard tests**

Run: `cargo test -p oauth2-actix --lib admin_guard && cargo build -p oauth2-actix`
Expected: build succeeds; tests PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/oauth2-actix/src/middleware/admin_guard.rs
git commit -m "fix(admin): require bearer client_id in OAUTH2_ADMIN_CLIENT_IDS allow-list for admin access"
```

---

### Task 4: Escape `user_code` in the device verification page (reflected XSS)

**Files:**
- Modify: `crates/oauth2-actix/src/handlers/login.rs` (promote `html_escape` to `pub(crate)` ~line 286)
- Modify: `crates/oauth2-actix/src/handlers/device.rs` (extract `render_device_verify_page`; call it in `verify_page` ~line 176)
- Test: `crates/oauth2-actix/src/handlers/device.rs` (new `#[cfg(test)] mod tests`)

- [ ] **Step 1: Promote the shared escaper**

In `crates/oauth2-actix/src/handlers/login.rs`, change line 286 from:

```rust
fn html_escape(s: &str) -> String {
```

to:

```rust
pub(crate) fn html_escape(s: &str) -> String {
```

- [ ] **Step 2: Write the failing unit test for the device page renderer**

Add at the end of `crates/oauth2-actix/src/handlers/device.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_code_is_html_escaped() {
        let html = render_device_verify_page(r#""><script>alert(1)</script>"#);
        // The raw breakout sequence must not appear.
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(!html.contains(r#"value=""><"#));
        // The escaped form must appear inside the value attribute.
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("&quot;&gt;"));
    }

    #[test]
    fn normal_user_code_is_preserved() {
        let html = render_device_verify_page("WDJB-MJHT");
        assert!(html.contains(r#"value="WDJB-MJHT""#));
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test -p oauth2-actix --lib device::tests`
Expected: FAIL — `cannot find function render_device_verify_page in this scope`.

- [ ] **Step 4: Add the pure renderer and route the handler through it**

In `crates/oauth2-actix/src/handlers/device.rs`, add this import near the top (after the existing `use crate::handlers::...` lines, around line 7):

```rust
use crate::handlers::login::html_escape;
```

Add this function just above `pub async fn verify_page` (currently line 152):

```rust
/// Render the device verification page, HTML-escaping the user-controlled
/// `user_code` to prevent reflected XSS.
fn render_device_verify_page(user_code: &str) -> String {
    let value = html_escape(user_code);
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Device Verification</title></head>
<body>
  <h1>Authorize Device</h1>
  <p>Enter the code shown on your device.</p>
  <form method="post" action="/oauth/device/verify">
    <label for="user_code">User code</label>
    <input id="user_code" name="user_code" value="{value}" required />
    <button type="submit" name="action" value="approve">Approve</button>
    <button type="submit" name="action" value="deny">Deny</button>
  </form>
</body>
</html>"#
    )
}
```

Then replace the body-building block in `verify_page` (currently lines 175-191) with:

```rust
    let value = query.user_code.clone().unwrap_or_default();
    let html = render_device_verify_page(&value);
```

- [ ] **Step 5: Run the unit test to verify it passes**

Run: `cargo test -p oauth2-actix --lib device::tests`
Expected: PASS (2 tests).

- [ ] **Step 6: Build the crate**

Run: `cargo build -p oauth2-actix`
Expected: build succeeds (no unused-import or visibility errors).

- [ ] **Step 7: Commit**

```bash
git add crates/oauth2-actix/src/handlers/login.rs crates/oauth2-actix/src/handlers/device.rs
git commit -m "fix(device): HTML-escape user_code in verification page to prevent reflected XSS"
```

---

### Task 5: Validate + safely encode the front-channel logout redirect (XSS + open redirect)

**Files:**
- Modify: `crates/oauth2-actix/src/handlers/oidc_logout.rs` (drop `state` param from `build_frontchannel_logout_page` and JSON-encode the URL ~line 183-225; validate the redirect in the front-channel branch ~line 347-358)
- Test: `crates/oauth2-actix/src/handlers/oidc_logout.rs` (new `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing unit test for the builder**

Add at the end of `crates/oauth2-actix/src/handlers/oidc_logout.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn client_with_frontchannel(uri: &str) -> oauth2_core::Client {
        let mut c = oauth2_core::Client::new(
            "rp".to_string(),
            "secret".to_string(),
            vec!["https://rp.example/cb".to_string()],
            vec!["authorization_code".to_string()],
            "openid".to_string(),
            "test".to_string(),
        );
        c.frontchannel_logout_uri = uri.to_string();
        c
    }

    #[test]
    fn redirect_url_is_json_encoded_not_raw() {
        let clients = vec![client_with_frontchannel("https://rp.example/fc")];
        // A value containing a double-quote must not break out of the JS string.
        let html = build_frontchannel_logout_page(
            &clients,
            "https://issuer.example",
            None,
            Some(r#"https://rp.example/done?x="+alert(1)+""#),
        );
        // No raw breakout: the quote must be backslash-escaped by JSON encoding.
        assert!(!html.contains(r#"href = "https://rp.example/done?x="+alert(1)+"";"#));
        assert!(html.contains(r#"\"+alert(1)+\""#));
    }

    #[test]
    fn no_redirect_script_when_absent() {
        let clients = vec![client_with_frontchannel("https://rp.example/fc")];
        let html = build_frontchannel_logout_page(&clients, "https://issuer.example", None, None);
        assert!(!html.contains("window.location.href"));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p oauth2-actix --lib oidc_logout::tests`
Expected: FAIL — `build_frontchannel_logout_page` takes 5 args (signature mismatch: the test calls it with 4), and the raw-quote assertion fails on the current unescaped builder.

- [ ] **Step 3: Change the builder to drop `state` and JSON-encode the URL**

In `crates/oauth2-actix/src/handlers/oidc_logout.rs`, replace the function signature and the `redirect_script` block. Change the signature (currently lines 183-189) from:

```rust
fn build_frontchannel_logout_page(
    storage_clients: &[oauth2_core::Client],
    issuer: &str,
    sid: Option<&str>,
    post_logout_redirect: Option<&str>,
    state: Option<&str>,
) -> String {
```

to:

```rust
fn build_frontchannel_logout_page(
    storage_clients: &[oauth2_core::Client],
    issuer: &str,
    sid: Option<&str>,
    post_logout_redirect: Option<&str>,
) -> String {
```

Then replace the `redirect_script` block (currently lines 213-225) with:

```rust
    let redirect_script = if let Some(redirect_uri) = post_logout_redirect {
        // The caller has already validated this URI against registered values and
        // appended any `state`. JSON-encode it into a safe JS string literal so a
        // quote/backslash cannot break out of the <script> context.
        let url_js = serde_json::to_string(redirect_uri).unwrap_or_else(|_| "\"\"".to_string());
        format!(
            r#"<script>setTimeout(function(){{ window.location.href = {}; }}, 2000);</script>"#,
            url_js
        )
    } else {
        String::new()
    };
```

- [ ] **Step 4: Run the unit test to verify it passes**

Run: `cargo test -p oauth2-actix --lib oidc_logout::tests`
Expected: PASS (2 tests).

- [ ] **Step 5: Validate the redirect in the front-channel branch before rendering**

In `crates/oauth2-actix/src/handlers/oidc_logout.rs`, replace the front-channel branch (currently lines 347-358) with:

```rust
    if has_frontchannel {
        // Validate post_logout_redirect_uri the SAME way the standard branch does,
        // BEFORE rendering it — the previous code skipped this, enabling an open
        // redirect and reflected XSS. Bake any `state` into the validated URL here.
        let redirect_target: Option<String> = match query.post_logout_redirect_uri.as_deref() {
            Some(uri) => {
                let mut parsed = validate_post_logout_redirect_uri_shape(uri)?;
                if !is_registered_post_logout_redirect(storage.get_ref(), uri).await? {
                    return Err(OAuth2Error::invalid_request(
                        "Unregistered post_logout_redirect_uri",
                    ));
                }
                if let Some(state) = query.state.as_deref() {
                    parsed.query_pairs_mut().append_pair("state", state);
                }
                Some(parsed.to_string())
            }
            None => None,
        };

        let html = build_frontchannel_logout_page(
            &clients,
            &oidc.issuer,
            sid.as_deref(),
            redirect_target.as_deref(),
        );
        return Ok(HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(html));
    }
```

- [ ] **Step 6: Build the crate and run the logout tests**

Run: `cargo test -p oauth2-actix --lib oidc_logout && cargo build -p oauth2-actix`
Expected: build succeeds; tests PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/oauth2-actix/src/handlers/oidc_logout.rs
git commit -m "fix(logout): validate and JSON-encode front-channel post_logout_redirect_uri (XSS + open redirect)"
```

---

### Task 6: Reject expired `subject_token` in token exchange

**Files:**
- Modify: `crates/oauth2-actix/src/handlers/oauth.rs` (`handle_token_exchange_grant` ~lines 2248-2250)
- Test: `tests/security_token_exchange_expiry.rs` (new integration test)

- [ ] **Step 1: Write the failing integration test**

Create `tests/security_token_exchange_expiry.rs` with:

```rust
//! Security regression: RFC 8693 token exchange must reject an expired
//! subject_token. Previously only `revoked` was checked, so an expired (but
//! still-persisted) access token could be exchanged for a fresh token.

use actix::Actor;
use actix_web::{test, web, App};

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, Token};
use oauth2_observability::Metrics;

const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

#[actix_web::test]
async fn expired_subject_token_is_rejected() {
    let db_path = format!("/tmp/oauth2_tx_expiry_{}.db", uuid::Uuid::new_v4());
    let storage = oauth2_storage_factory::create_storage(&format!("sqlite:{db_path}"))
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");

    // Confidential client allowed to use token-exchange.
    let client = Client::new(
        "tx_client".to_string(),
        "tx_secret".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec![TOKEN_EXCHANGE.to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    storage.save_client(&client).await.expect("save client");

    // An already-expired access token (negative expires_in => expires_at in the past).
    let expired = Token::new(
        "expired_access_token_value".to_string(),
        None,
        "tx_client".to_string(),
        Some("user_123".to_string()),
        "read".to_string(),
        -3600,
        None,
    );
    assert!(expired.is_expired(), "fixture token must be expired");
    storage.save_token(&expired).await.expect("save token");

    let jwt_secret = "test_jwt_secret".to_string();
    let metrics = Metrics::new().expect("metrics");
    let token_actor = oauth2_actix::actors::TokenActor::new(
        storage.clone(),
        jwt_secret.clone(),
        "http://localhost".to_string(),
    )
    .start();
    let token_pool = TokenActorPool::new(vec![token_actor]);
    let client_actor = oauth2_actix::actors::ClientActor::new(storage.clone()).start();

    let oidc_config = OidcConfig {
        issuer: "http://localhost".to_string(),
        jwt_secret: jwt_secret.clone(),
        id_token_alg: "HS256".to_string(),
        id_token_kid: None,
        id_token_private_key_pem: None,
    };

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(storage.clone()))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false))
            .service(
                web::scope("/oauth").route(
                    "/token",
                    web::post().to(oauth2_actix::handlers::oauth::token),
                ),
            ),
    )
    .await;

    // Basic auth: base64("tx_client:tx_secret")
    let basic = format!(
        "Basic {}",
        base64_encode(b"tx_client:tx_secret")
    );
    let body = format!(
        "grant_type={}&subject_token=expired_access_token_value&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
        urlencode(TOKEN_EXCHANGE)
    );

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .insert_header(("Authorization", basic))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(body)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        400,
        "expired subject_token must be rejected with invalid_grant (400), got {}",
        resp.status()
    );
}

// Minimal helpers so the test has no extra dependencies beyond the workspace.
fn base64_encode(input: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(input)
}

fn urlencode(s: &str) -> String {
    s.replace(':', "%3A")
}
```

> Note: confirm the app_data set required by `oauth::token` matches the project's other token tests (model on the `device_app!` macro in `tests/compliance_rfc8628.rs:119-155`, which wires the same `/oauth/token` route). If the token handler also requires `Arc<RwLock<KeySet>>` or a `Config` for the token-exchange path in your tree, add those `app_data` entries exactly as that macro / `tests/security_http.rs` does. The `base64` crate is already a workspace dependency (used across the codebase); if the test crate cannot see it, replace `base64_encode` with a hand-rolled encoder or use `data_encoding`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --test security_token_exchange_expiry`
Expected: FAIL — current code returns `200 OK` (mints a fresh token) because only `revoked` is checked, so the `assert_eq!(resp.status(), 400)` fails.

- [ ] **Step 3: Add the expiry check**

In `crates/oauth2-actix/src/handlers/oauth.rs`, replace the revoked-only check in `handle_token_exchange_grant` (currently lines 2248-2250):

```rust
    if subject_tok.revoked {
        return Err(OAuth2Error::invalid_grant("subject_token has been revoked"));
    }
```

with:

```rust
    // Reject revoked OR expired subject tokens. The previous code checked only
    // `revoked`, so an expired (but still-persisted) token could be exchanged
    // for a fresh one. `is_valid()` mirrors the ValidateToken path.
    if !subject_tok.is_valid() {
        return Err(OAuth2Error::invalid_grant(
            "subject_token is expired or revoked",
        ));
    }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --test security_token_exchange_expiry`
Expected: PASS — status is now `400`.

- [ ] **Step 5: Commit**

```bash
git add crates/oauth2-actix/src/handlers/oauth.rs tests/security_token_exchange_expiry.rs
git commit -m "fix(token-exchange): reject expired subject_token (RFC 8693), not only revoked"
```

---

### Task 7: Document the new env vars and run the full CI gate

**Files:**
- Modify: `docs/oauth2-spec-audit.md` (or `CHANGELOG.md` / `README.md` — whichever documents config) to record the two new env vars
- No code change beyond docs

- [ ] **Step 1: Document the new configuration**

Add a short note (in the config/env section of `README.md` or `docs/oauth2-spec-audit.md`) capturing:

```markdown
### Security configuration (added 2026-06-12)

- `OAUTH2_DYNAMIC_REGISTRATION_ENABLED` (default `false`): when not `true`,
  the public RFC 7591 endpoint `POST /connect/register` returns `403`. Use the
  admin endpoint `POST /admin/clients/register` to create clients otherwise.
- `OAUTH2_ADMIN_CLIENT_IDS` (comma-separated, default empty): client_ids whose
  bearer tokens (with `admin` scope) may access `/admin/*`. Empty = no machine
  client is admin. Set this to your MCP/automation client_id for m2m admin access.
- Privileged scopes (`admin`, `write`) can no longer be requested through public
  registration or RFC 7592 update; grant them via the admin endpoint only.
```

- [ ] **Step 2: Commit the docs**

```bash
git add docs/oauth2-spec-audit.md README.md
git commit -m "docs: document OAUTH2_DYNAMIC_REGISTRATION_ENABLED and OAUTH2_ADMIN_CLIENT_IDS"
```

- [ ] **Step 3: Run the full CI gate (must pass before any PR)**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --verbose --all-features --locked
```

Expected: `fmt` clean (run `cargo fmt --all` to auto-fix if not), `clippy` zero warnings, all tests PASS including the new `security_token_exchange_expiry` integration test and the new unit tests in `client.rs`, `admin_guard.rs`, `device.rs`, and `oidc_logout.rs`.

- [ ] **Step 4: Final commit (only if fmt made changes)**

```bash
git add -A
git commit -m "style: cargo fmt after security hardening"
```

---

## Self-Review

**Spec coverage:**
- Finding 1 (Critical admin chain) → Task 1 (gate registration), Task 2 (scope allow-list), Task 3 (AdminGuard client-id pin) — all three legs of the chain are broken; either Task 2 or Task 3 alone is sufficient, both implemented for defense in depth per the user's choice.
- Finding 2 (device XSS) → Task 4.
- Finding 3 (front-channel logout XSS + open redirect) → Task 5 (both the validation gap and the unescaped sink).
- Finding 4 (token-exchange expiry) → Task 6.
- Operability/rollout (new env vars) → Task 7.

**Placeholder scan:** No `TODO`/`TBD`/"handle edge cases" left. Two `> Note:` callouts flag genuine cross-tree verification points (the exact `OAuth2Error` constructor name and the token handler's full `app_data` set) with a concrete fallback for each — these are verification instructions, not placeholders, because the engineer cannot know the exact local symbol without checking, and a wrong guess would not compile.

**Type/name consistency:** Helper names are unique and consistent across tasks: `parse_registration_enabled`/`dynamic_registration_enabled` (Task 1), `scope_contains_privileged`/`PRIVILEGED_SCOPES` (Task 2), `client_id_in_allowlist`/`is_admin_client` (Task 3), `render_device_verify_page` + `pub(crate) html_escape` (Task 4), `build_frontchannel_logout_page` 4-arg form (Task 5). `Token::is_valid()`/`is_expired()` (Task 6) match `crates/oauth2-core/src/models/token.rs:509-515`. `Token::new` argument order in the Task 6 fixture matches the constructor at `token.rs:481-507`.
