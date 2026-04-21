//! RFC 8252 — native-app redirect URI handling.
//!
//! RFC 8252 §7.3 grants the loopback port-wildcard exception: an AS MUST
//! accept any port on a loopback redirect URI at request time, even if the
//! registered URI used a different (or zero) port. RFC 8252 §8.3 then
//! narrows that exception to the IP literal forms only — `127.0.0.1` and
//! `[::1]` — because the `localhost` hostname is non-deterministic
//! (Windows `hosts` overrides, split-horizon DNS, IPv4-vs-IPv6 resolution).
//!
//! These tests lock in both rules at the `Client::validate_redirect_uri`
//! level so regressions surface in the core crate's own test suite, not
//! just in end-to-end flows.

use oauth2_core::Client;

fn client_registered_for(redirect: &str) -> Client {
    Client::new(
        "c_native".to_string(),
        "s".to_string(),
        vec![redirect.to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "native".to_string(),
    )
}

/// §7.3 — registered `127.0.0.1:3000`, request arrives on a different
/// ephemeral port. Must be accepted.
#[test]
fn rfc8252_ipv4_loopback_any_port_accepted() {
    let c = client_registered_for("http://127.0.0.1:3000/cb");
    assert!(c.validate_redirect_uri("http://127.0.0.1:54321/cb"));
    assert!(c.validate_redirect_uri("http://127.0.0.1:1/cb"));
}

/// §7.3 — same for IPv6 literal.
#[test]
fn rfc8252_ipv6_loopback_any_port_accepted() {
    let c = client_registered_for("http://[::1]:3000/cb");
    assert!(c.validate_redirect_uri("http://[::1]:54321/cb"));
}

/// §8.3 — `localhost` hostname MUST NOT benefit from the port-wildcard
/// exception. A client registered for `http://localhost:3000/cb` that
/// requests `http://localhost:4000/cb` is rejected; the same client
/// requesting the literal registered URI is still accepted via the
/// exact-match fast path.
#[test]
fn rfc8252_localhost_hostname_does_not_wildcard_port() {
    let c = client_registered_for("http://localhost:3000/cb");
    assert!(
        c.validate_redirect_uri("http://localhost:3000/cb"),
        "exact match on localhost must still work"
    );
    assert!(
        !c.validate_redirect_uri("http://localhost:4000/cb"),
        "RFC 8252 §8.3: localhost hostname MUST NOT wildcard the port"
    );
}

/// IPv4-registered clients MUST NOT be able to redirect to `[::1]` and
/// vice versa. Each loopback family is treated as a distinct host.
#[test]
fn rfc8252_loopback_families_do_not_cross() {
    let v4 = client_registered_for("http://127.0.0.1:3000/cb");
    assert!(!v4.validate_redirect_uri("http://[::1]:3000/cb"));
    let v6 = client_registered_for("http://[::1]:3000/cb");
    assert!(!v6.validate_redirect_uri("http://127.0.0.1:3000/cb"));
}

/// The loopback exception is scoped to loopback hosts only. A client
/// registered for `http://example.com/cb` MUST NOT benefit from any
/// port-wildcard leniency.
#[test]
fn rfc8252_non_loopback_host_requires_exact_match() {
    let c = client_registered_for("http://example.com:3000/cb");
    assert!(c.validate_redirect_uri("http://example.com:3000/cb"));
    assert!(!c.validate_redirect_uri("http://example.com:4000/cb"));
}

/// Path must still match; only the port is wildcarded under §7.3.
#[test]
fn rfc8252_loopback_exception_still_requires_path_match() {
    let c = client_registered_for("http://127.0.0.1:3000/cb");
    assert!(!c.validate_redirect_uri("http://127.0.0.1:3000/different"));
    assert!(!c.validate_redirect_uri("http://127.0.0.1:54321/different"));
}

/// Scheme must match; only the port is wildcarded under §7.3. An HTTP
/// registration does not authorize an HTTPS request to a loopback port.
#[test]
fn rfc8252_loopback_exception_still_requires_scheme_match() {
    let c = client_registered_for("http://127.0.0.1:3000/cb");
    assert!(!c.validate_redirect_uri("https://127.0.0.1:3000/cb"));
}

/// Exact-match fallback still honors custom URI schemes — RFC 8252 §7.1.
/// No wildcarding is applied; claimed-scheme redirects must match byte
/// for byte.
#[test]
fn rfc8252_custom_scheme_exact_match_only() {
    let c = client_registered_for("com.example.app://oauth/callback");
    assert!(c.validate_redirect_uri("com.example.app://oauth/callback"));
    assert!(!c.validate_redirect_uri("com.example.app://oauth/other"));
}
