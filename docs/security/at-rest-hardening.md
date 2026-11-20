# Credential storage at rest (format v1)

Breaking change with an explicit, operator-run cutover.

## What is stored

| Credential | Stored as | Recoverable? |
|---|---|---|
| Access / refresh tokens, authorization codes, device codes, registration access tokens | `h1$<SHA-256 digest>` (domain-separated) | No. Lookups hash the presented value; a stored value is never accepted as a credential. |
| Client secret | `c1$<salt>$<verifier>$<sealed>` | Verifier: no. `sealed`: AES-256-GCM key material, see below. |

Device `user_code` stays as-is: it is short, human-typed and rate limited, not a high-entropy bearer.

### Symmetric key material (not a verifier)

`client_secret_jwt` and HS256 request objects (JAR) need the secret itself as an HMAC key, so a pure
hash cannot support them. The record therefore also carries the secret sealed under a key derived from
`jwt.secret`. Consequences:

* `client_secret_basic` / `client_secret_post` / PAR secret checks use only the salted verifier.
* Changing `jwt.secret` makes sealed keys unreadable: HMAC-based methods fail closed for those clients
  until their secret is rotated; basic/post authentication keeps working.
* Protect `jwt.secret` like a signing key; a database dump alone does not reveal client secrets.

### Behavior notes

* Client secrets and registration access tokens are shown once, at issuance. RFC 7592 read/update echo the
  token the caller authenticated with; a stored secret is never echoed.
* Refresh-token DPoP/mTLS binding is read from the persisted `cnf` column (the stored access token is no
  longer a JWT).
* The Redis token cache is keyed by the verifier and holds verifiers only. Cache
  lookup/insert keys hash the presented value unconditionally, so a stored verifier presented as a bearer
  never matches a live entry; eviction (on revoke/rotation) instead maps a raw value or an already-stored
  verifier back to the same key.

## Cutover (operator-initiated)

The server never deletes or rewrites data at startup; legacy values are simply not accepted.

1. Schedule a window. Deploy of the new build is a separate, owner-approved step.
2. Back up the database (this is the rollback point).
3. Run `scripts/at_rest_cutover.sql` (SQLite/PostgreSQL) or `scripts/at_rest_cutover.mongo.js`.
   It removes legacy tokens/codes/device codes (all sessions and grants reset), replaces legacy client
   secrets with an unusable marker and clears legacy registration tokens. Re-runnable.
4. Start the new build; rotate each confidential client's secret via the admin path and distribute the new
   value. Clients must re-register or use the rotated secret; previously issued refresh tokens are gone.

Credentials are sealed only at issuance or explicit rotation. A metadata-only client update
(`update_client`, admin PATCH, CIMD refresh) never seals a legacy plaintext secret or registration
token, and never overwrites the stored credential columns at all (SQLx `UPDATE` and the Mongo `$set`
omit `client_secret` and `registration_access_token`). So a stale snapshot cannot restore an old secret
after a rotation, and the pre-cutover window stays closed. Credentials change only at issuance and
via `set_client_secret`.

Order matters: running the new build before the script is safe (legacy rows are rejected) but leaves
unusable legacy rows in place.

### Partial-failure recovery

The MongoDB script runs in a single transaction (replica set or sharded cluster required): on any error it
aborts and nothing changes, so fix the cause and re-run. On a standalone `mongod` it aborts before changing
anything; convert to a single-node replica set first. Every step is idempotent, so
if the script was interrupted in some other way (e.g. client killed mid-commit), check the outcome and simply
re-run it. A cluster left half-migrated is still safe: legacy rows are rejected by the server, and the
`legacy-invalidated` marker is never accepted or re-sealed (cached or stored). If in doubt, restore the backup.

### Rollback

The old build cannot read v1 rows. Roll back by stopping the service, restoring the pre-cutover backup and
redeploying the previous build. Credentials issued after the cutover are lost by that restore.

## Already-issued stateless tokens

JWT access tokens are self-contained and are not affected by storage format. After the cutover they
keep validating by signature until `exp` when stateless validation is enabled; with database-backed
validation (default) the lookup finds no row and they are rejected. To invalidate stateless tokens
immediately, rotate the signing key (JWKS) or use the denylist. ID tokens are unaffected.

## Notes

- `transaction_authorizations.id` (a UUIDv4) is stored as-is. It is a handle, not a bearer credential: use of it always requires client authentication or an authenticated session, so it is intentionally not hashed.
- The validation caches (in-process LRU and Redis) are keyed by the storage verifier, so revoking by either the raw value or the stored verifier (as refresh rotation does) evicts the entry immediately.
