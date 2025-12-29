# Service-to-service (Client Credentials + Introspection)

This cookbook demonstrates a common **machine-to-machine** pattern:

1. **Service A** (client) obtains an access token using the **Client Credentials**
  grant.
2. **Service B** (resource server) validates incoming requests by calling **RFC
  7662 token introspection** (`POST /oauth/introspect`).
3. Service B enforces a required scope (e.g. `read`).

In this repository, Service B is a tiny example app located at
`examples/resource-server-node/` and is deployed in KIND via
`k8s/components/resource-server/`.

---

## Architecture

```mermaid
flowchart LR
  A[Service A\n(client)] -->|POST /oauth/token\nclient_credentials| AS[OAuth2 Server]
  A -->|GET /protected\nAuthorization: Bearer ...| B[Service B\n(resource server)]
  B -->|POST /oauth/introspect| AS
```

**Why introspection?**

- It’s straightforward to implement.
- It works even when the access token is opaque (or when you want revocation to
  take effect immediately).
- It centralizes validation rules in the authorization server.

---

## Run it on KIND (automated)

The extended KIND E2E script provisions:

- Postgres + migrations
- `oauth2-server`
- `resource-server` (example)

It then:

- registers a test OAuth2 client
- mints an access token (`grant_type=client_credentials`)
- verifies that `resource-server`:
  - returns **401** without a token
  - returns **200** with a valid token
  - returns **401** again after revocation

Run:

```bash
bash scripts/e2e_kind_extended.sh
```

If you want to keep the cluster around for debugging:

```bash
bash scripts/e2e_kind_extended.sh --keep-cluster --keep-namespace
```

---

## How the resource server validates tokens

At a high level, Service B does:

1. Parse the `Authorization: Bearer <token>` header
2. Call:

```http
POST /oauth/introspect
Content-Type: application/x-www-form-urlencoded

token=<token>&client_id=<id>&client_secret=<secret>
```

1. Require `active=true`
2. Require a scope (defaults to `read`)

See `examples/resource-server-node/server.js` for the full implementation.

---

## Notes and production guidance

- **Cache introspection responses** for a short TTL to reduce load on the auth
  server (but consider revocation requirements).
- Use sensible timeouts and retries when calling `/oauth/introspect`.
- If you need maximum performance, consider **local JWT validation** (but ensure
  your key distribution / rotation story is solid).
