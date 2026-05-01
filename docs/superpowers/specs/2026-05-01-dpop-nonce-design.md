# DPoP Server-Issued Nonces — Design

**Status:** Approved
**Date:** 2026-05-01
**RFC:** 9449 §§4.3, 8, 9
**Closes:** Phase 6.2 enforcement gap (per `docs/oauth2-spec-audit.md` §9.2)

## Background

`crates/oauth2-actix/src/handlers/dpop.rs` already implements full DPoP proof
validation: `typ: dpop+jwt`, JWT signature verification, `htm`/`htu` binding,
`iat` ±5 min freshness, and `jti` replay prevention via an in-memory store.
The proof's `nonce` claim is parsed but unused (`#[allow(dead_code)]`).

RFC 9449 §8 defines server-issued nonces as defense-in-depth against
proof pre-computation and replay across instances/restarts. §9 specifies
the `use_dpop_nonce` error handshake.

## Goal

Per-client opt-in nonce requirement. When a client has
`dpop_nonce_required = true`, the AS rejects DPoP proofs that lack a valid
server-issued nonce and replies with a fresh nonce in the `DPoP-Nonce`
response header.

## Non-Goals

- Global config flag (per-client follows existing `require_state` /
  `require_pushed_authorization_requests` pattern)
- Stateful nonce store (stateless HMAC works across instances; no Redis dep)
- Resource-server-issued nonces (out of scope; AS-only for this PR)
- Discovery field — RFC 9449 doesn't define one

## Approach: Stateless Time-Bucketed HMAC Nonce

```
nonce      = base64url( bucket_id_be(8) || HMAC-SHA256(secret, bucket_id_be)[..16] )
bucket_id  = floor(unix_now / lifetime_secs)
```

Verification accepts the **current** and **one previous** bucket — covers
clock skew and grace during rotation. No persistent storage; nonces
self-validate from a server secret.

### Trade-offs

| Property | Stateless HMAC (chosen) | Stateful (Redis) |
|---|---|---|
| Multi-instance | Works trivially | Requires shared store |
| Revocation | Bucket rotation | Per-nonce delete |
| Storage | None | Redis dep |
| Forge resistance | HMAC-SHA256 secret | Random 256-bit |
| Existing fit | Matches stateless JWT philosophy | Adds infrastructure |

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `OAUTH2_DPOP_NONCE_LIFETIME_SECS` | `300` | Bucket size (5 min) |
| `OAUTH2_DPOP_NONCE_SECRET` | auto-generated 32-byte random at startup | HMAC key |

Per-client opt-in via new `clients.dpop_nonce_required` column (default `false`).

## Files Touched

| File | Change |
|---|---|
| `migrations/sql/V21__add_dpop_nonce_required_to_clients.sql` | new column |
| `crates/oauth2-core/src/models/client.rs` | add field + default |
| `crates/oauth2-storage-sqlx/src/sqlx.rs` | INSERT + SELECT (sqlite + pg) |
| `crates/oauth2-storage-mongo/` | bson serde |
| `crates/oauth2-config/src/lib.rs` | nonce lifetime + secret config |
| `crates/oauth2-actix/src/handlers/dpop_nonce.rs` | new — issuer + verifier |
| `crates/oauth2-actix/src/handlers/dpop.rs` | wire nonce verification |
| `crates/oauth2-actix/src/handlers/oauth.rs` | DPoP-Nonce header + use_dpop_nonce |
| `crates/oauth2-actix/src/handlers/token.rs` | same |
| `crates/oauth2-server/src/lib.rs` | construct issuer, register `app_data` |
| `tests/rfc9700_dpop_nonce.rs` | new — 6 conformance vectors |

## Test Vectors (TDD)

1. Client with `dpop_nonce_required=true`, proof without `nonce` →
   `400` body `error: use_dpop_nonce`, response header `DPoP-Nonce: <fresh>`
2. Same client, retry with the issued nonce → `200`, response header
   `DPoP-Nonce: <fresh>` (lets clients pre-rotate)
3. Forged nonce (wrong HMAC) → `400 invalid_dpop_proof`
4. Stale nonce (3 buckets old) → `400 invalid_dpop_proof`
5. Client with `dpop_nonce_required=false`, proof without `nonce` →
   `200` (back-compat preserved)
6. Previous-bucket nonce still valid (grace window)

## API: `DpopNonceIssuer`

```rust
pub struct DpopNonceIssuer {
    secret: [u8; 32],
    lifetime_secs: u64,
}
impl DpopNonceIssuer {
    pub fn new(secret: [u8; 32], lifetime_secs: u64) -> Self;
    pub fn issue(&self) -> String;
    pub fn verify(&self, nonce: &str) -> Result<(), OAuth2Error>;
}
```

`validate_dpop_proof` gains optional `nonce_issuer: Option<&DpopNonceIssuer>`
parameter. When `Some`, the proof's `nonce` claim must verify; when `None`,
the existing behaviour is preserved.

## Security Notes

- Constant-time comparison via `subtle::ConstantTimeEq`
- HMAC truncated to 16 bytes — forgery resistance only
- Secret rotated independently of JWT signing key; default auto-generated
  per process means restarting invalidates outstanding nonces (acceptable —
  client just retries and gets a fresh one)
- For multi-instance deploys, operators set
  `OAUTH2_DPOP_NONCE_SECRET` explicitly

## Roll-out

1. Land migration + per-client field + nonce module (default off)
2. Existing clients unaffected (`dpop_nonce_required = false`)
3. Operators opt high-security clients in via dynamic registration update
