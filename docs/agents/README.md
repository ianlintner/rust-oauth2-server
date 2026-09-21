# Agent & A2A OAuth (Phase 7)

This page covers the agent / agent-to-agent (A2A) OAuth extensions added on
top of the standard flows described in
[`docs/usage/oauth2-oidc.md`](../usage/oauth2-oidc.md). It is the
operator/integrator guide: how to turn each feature on, and worked `curl`
examples for the new grants and endpoints.

Everything here is **off by default**. Discovery
(`GET /.well-known/openid-configuration`) only advertises a capability once
its flag is enabled, and every flag can be set independently — you do not
need CIMD to use token-exchange delegation, or transaction tokens to use
ID-JAG.

Background reading: [`docs/superpowers/specs/2026-09-21-agent-a2a-oauth-roadmap-design.md`](../superpowers/specs/2026-09-21-agent-a2a-oauth-roadmap-design.md)
(the research + design rationale) and
[`docs/oauth2-spec-audit.md`](../oauth2-spec-audit.md#10-phase-7--agent--a2a-authorization)
§10 (the implementation tracker).

## Contents

- [Feature flags](#feature-flags)
- [The delegation chain (`act`)](#the-delegation-chain-act)
- [Token exchange with an actor token](#token-exchange-with-an-actor-token)
- [Named-agent consent (`requested_actor`)](#named-agent-consent-requested_actor)
- [Cross-domain chaining: JWT-bearer grant + ID-JAG](#cross-domain-chaining-jwt-bearer-grant--id-jag)
- [Transaction tokens (+ A2A profile)](#transaction-tokens--a2a-profile)
- [Transaction Authorization Challenge (human-in-the-loop)](#transaction-authorization-challenge-human-in-the-loop)
- [Client ID Metadata Documents (CIMD)](#client-id-metadata-documents-cimd)
- [Workload identity](#workload-identity)
- [Registries and admin APIs](#registries-and-admin-apis)
- [DPoP: `ath` and replay](#dpop-ath-and-replay)
- [Security considerations](#security-considerations)

## Feature flags

All of these live in `AgentConfig` (`crates/oauth2-config/src/lib.rs`) and are
read from environment variables at startup.

| Env var | Default | Enables |
|---|---|---|
| `OAUTH2_MAX_DELEGATION_DEPTH` | `4` | Maximum `act` nesting depth accepted anywhere (token exchange, ID-JAG, txn tokens). Not a feature switch — always enforced. |
| `OAUTH2_TRUST_DOMAIN` | unset | The audience value transaction tokens are scoped to. Required for `OAUTH2_TXN_TOKENS_ENABLED`. |
| `OAUTH2_CIMD_ENABLED` | `false` | Resolving URL-shaped `client_id`s (Client ID Metadata Documents) at `/authorize`, `/oauth/par` and `/oauth/token`. |
| `OAUTH2_CIMD_ALLOWED_HOSTS` | empty (any public host) | Comma-separated host allowlist for CIMD fetches. |
| `OAUTH2_CIMD_DENIED_HOSTS` | empty | Comma-separated host denylist for CIMD fetches; checked in addition to the SSRF guard. |
| `OAUTH2_CIMD_MAX_CLIENTS` | `1000` | Cap on how many CIMD-materialized `clients` rows may exist; fails new (not refreshed) documents closed once reached. |
| `OAUTH2_AGENT_OBO_ENABLED` | `false` | The `requested_actor` parameter on `/authorize` (named-agent consent). |
| `OAUTH2_A2A_PROFILE_ENABLED` | `false` | The draft-liu A2A claims (`purp`, immutable `tctx`) on transaction tokens. |
| `OAUTH2_TXN_TOKENS_ENABLED` | `false` | `requested_token_type=urn:ietf:params:oauth:token-type:txn_token` at the token-exchange grant. |
| `OAUTH2_TXN_TOKEN_TTL_SECS` | `300` | Transaction token lifetime, in seconds. |
| `OAUTH2_TAC_ENABLED` | `false` | `POST /oauth/transaction_authorization` and the polling grant. |
| `OAUTH2_ID_JAG_ENABLED` | `false` | ID-JAG issuance (`requested_token_type=id-jag`) and acceptance (`typ: oauth-id-jag+jwt` assertions on the jwt-bearer grant). |
| `OAUTH2_CHAINING_TARGETS` | empty | Comma-separated list of issuer URLs this server may mint identity-chaining JWTs for. |
| `OAUTH2_AI_AGENT_ACCESS_TOKEN_TTL_SECS` | unset | Overrides the access-token TTL for client-credentials tokens issued to clients classified as AI agents (see [Workload identity](#workload-identity)). |

Booleans accept `1`, `true`, `yes` (case-insensitive); anything else is
`false`. List values are comma-separated, trimmed, with empty entries dropped.

## The delegation chain (`act`)

Every agent flow in this document composes on one shape, defined in
`oauth2_core::models::actor::Actor`:

```json
{ "sub": "agent-client-id", "iss": "https://auth.example.com", "sub_profile": "ai_agent", "act": { "sub": "...", "iss": "..." } }
```

- `sub`/`iss` identify who is acting.
- `sub_profile` is one of `"user"`, `"service"`, `"ai_agent"`.
- `act` nests the *next* actor out, so a chain of delegations reads
  outermost-in. Depth is capped by `OAUTH2_MAX_DELEGATION_DEPTH`.

`act` is only ever placed on a token when there's a validated basis for it —
either the subject token's `may_act` claim names the actor, or the subject
token's issuing client has registered the actor in its `allowed_actors` list
(see [Registries and admin APIs](#registries-and-admin-apis)). It is never
accepted from an unauthenticated request. `act` is carried inside the issued
JWT and echoed by introspection (`POST /oauth/introspect`); it is never a
top-level member of the token response body.

## Token exchange with an actor token

RFC 8693, `POST /oauth/token`, `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`.
This is the primitive every other agent flow builds on: a client presents a
`subject_token` it holds (the identity being acted for) and, optionally, an
`actor_token` (the identity doing the acting), and receives a new,
narrower-or-equal token.

```bash
curl -s https://auth.example.com/oauth/token \
  -u "agent-service:agent-secret" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$USER_ACCESS_TOKEN" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d actor_token="$AGENT_ACCESS_TOKEN" \
  -d actor_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d resource=https://api.example.com/mcp \
  -d scope="mcp.read"
```

```json
{
  "access_token": "eyJhbGciOi...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "mcp.read"
}
```

Introspecting the returned token shows the delegation:

```bash
curl -s https://auth.example.com/oauth/introspect \
  -u "agent-service:agent-secret" -d token=eyJhbGciOi...
```

```json
{
  "active": true,
  "sub": "user-123",
  "act": { "sub": "agent-service", "iss": "https://auth.example.com", "sub_profile": "service" }
}
```

Key rules (see `crates/oauth2-actix/src/handlers/token_exchange.rs` for the
full algorithm):

- `subject_token`/`subject_token_type` are required. Accepted subject types:
  `access_token`, `jwt`, `id_token`, and (only for ID-JAG/chaining issuance)
  `refresh_token`. `refresh_token`/`saml2` are rejected elsewhere with
  `invalid_request`.
- An `actor_token` from a different client than the authenticated one is
  authorized only via `may_act` or the subject client's `allowed_actors` —
  otherwise `invalid_grant`.
- `resource`/`audience` values must validate against `ProtectedResource::validate_uri`
  and, if the resources registry is non-empty, must be registered
  (`GET/POST /admin/resources`) — otherwise `invalid_target`. Requested
  audience must be a subset of the subject token's audience (no widening).
- `authorization_details` (RFC 9396) must be a subset of the subject's — a
  superset is `invalid_authorization_details`.
- `requested_token_type` defaults to `access_token`; also accepts `jwt`,
  `id-jag` (§ [ID-JAG](#cross-domain-chaining-jwt-bearer-grant--id-jag)) and
  `txn_token` (§ [Transaction tokens](#transaction-tokens--a2a-profile)).
- A DPoP proof presented at the exchange rebinds `cnf.jkt` to the new proof;
  otherwise the subject's `cnf` is inherited only when the subject token
  belongs to the requesting client.

## Named-agent consent (`requested_actor`)

Flag: `OAUTH2_AGENT_OBO_ENABLED`. Lets a user see *which agent* will act for
them on the login page when login is required, per draft-oauth-ai-agents-on-behalf-of-user. With the
flag off, `requested_actor` is ignored as an unknown parameter (RFC 6749).

```
GET /oauth/authorize?response_type=code&client_id=chat-app&redirect_uri=...
    &requested_actor=research-agent&code_challenge=...&code_challenge_method=S256
```

`requested_actor` must name a registered client (or a resolvable CIMD URL);
otherwise the authorize request redirects with `invalid_request` /
`"unknown requested_actor"`. It is persisted on the authorization code. When
the authorize request needs the user to log in, the login page names both
clients — "*chat-app* wants *research-agent* to access …". An already
authenticated user is not shown a separate consent page; the server has none.

At code exchange, a code carrying `requested_actor` requires `actor_token` +
`actor_token_type` (`access_token` or `jwt`):

```bash
curl -s https://auth.example.com/oauth/token \
  -u "chat-app:chat-app-secret" \
  -d grant_type=authorization_code \
  -d code="$CODE" \
  -d redirect_uri=https://chat-app.example.com/callback \
  -d code_verifier="$VERIFIER" \
  -d actor_token="$RESEARCH_AGENT_TOKEN" \
  -d actor_token_type=urn:ietf:params:oauth:token-type:access_token
```

The actor token's `client_id` must equal `requested_actor`
(`invalid_grant` otherwise). The issued token carries
`act = { "sub": "research-agent", "iss": "<issuer>", "sub_profile": "ai_agent" }`,
and a subsequent refresh-token grant preserves it.

## Cross-domain chaining: JWT-bearer grant + ID-JAG

### Accepting an external assertion (RFC 7523 §2.1 grant)

An external IdP signs a JWT about a subject; a client redeems it here with
`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`. The assertion's
`iss` must name an enabled entry in the
[trusted issuers registry](#registries-and-admin-apis).

```bash
curl -s https://auth.example.com/oauth/token \
  -u "agent-service:agent-secret" \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  -d assertion="$EXTERNAL_IDP_JWT"
```

Requirements: signature verified against the trusted issuer's `jwks_uri`
(RS256/ES256/PS256 only); `aud` equal to this server's issuer or token
endpoint (or in the issuer's `allowed_audiences`); `jti` replay rejected;
`exp` in the future. The subject is resolved per the issuer's
`subject_mapping` (`"sub"` or `"email"`), with just-in-time user provisioning
when `jit_provision` is set. Only an access token is issued — never a refresh
token.

### ID-JAG acceptance

When the assertion's JOSE header carries `typ: "oauth-id-jag+jwt"`, it is
treated as an Identity Assertion Authorization Grant
(draft-ietf-oauth-identity-assertion-authz-grant): requires
`OAUTH2_ID_JAG_ENABLED`; the assertion's `client_id` claim must equal the
authenticated client; `scope`/`resource`/`authorization_details` in the
assertion are a ceiling the request may only narrow; a `cnf.jkt` in the
assertion requires a matching DPoP proof on the request.

### ID-JAG / identity-chaining issuing

This server can also *mint* an ID-JAG for a downstream authorization server,
via token exchange:

```bash
curl -s https://auth.example.com/oauth/token \
  -u "agent-service:agent-secret" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$ID_TOKEN" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:id_token \
  -d requested_token_type=urn:ietf:params:oauth:token-type:id-jag \
  -d audience=https://downstream-as.example.com
```

```json
{
  "access_token": "eyJhbGciOi...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
  "token_type": "N_A",
  "expires_in": 300,
  "scope": "openid"
}
```

Requires `OAUTH2_ID_JAG_ENABLED`; the single `audience` value must be listed
in `OAUTH2_CHAINING_TARGETS` (otherwise `invalid_target`). The response is a
signed JWT authorization grant (header `typ: "oauth-id-jag+jwt"`) meant to be
redeemed at the downstream AS's own jwt-bearer endpoint — `token_type: "N_A"`
signals it is not itself a usable access token, and it is never persisted.
`requested_token_type=urn:ietf:params:oauth:token-type:jwt` with a single
`audience` in `OAUTH2_CHAINING_TARGETS` triggers the same issuing path
(plain identity-chaining, without the ID-JAG-specific claims ceiling).

## Transaction tokens (+ A2A profile)

Flags: `OAUTH2_TXN_TOKENS_ENABLED` and a non-empty `OAUTH2_TRUST_DOMAIN`.
Short-lived, trust-domain-scoped tokens for intra-domain agent call chains
(draft-ietf-oauth-transaction-tokens), requested via token exchange:

```bash
curl -s https://auth.example.com/oauth/token \
  --cert workload.pem --key workload.key \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d client_id=order-service \
  -d subject_token="$INBOUND_ACCESS_TOKEN" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d requested_token_type=urn:ietf:params:oauth:token-type:txn_token \
  -d audience=example.com \
  -d request_details='{"order_id":"o-123"}' \
  -d purp=task-42
```

```json
{
  "token_type": "N_A",
  "access_token": "eyJhbGciOi...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:txn_token",
  "expires_in": 300
}
```

- The requesting client MUST authenticate asymmetrically
  (`private_key_jwt`, `tls_client_auth`, or `self_signed_tls_client_auth`) —
  a `client_secret_*` client gets `invalid_client`.
- `audience` is required and must equal `OAUTH2_TRUST_DOMAIN` exactly, or
  `invalid_target`.
- Claims: header `typ: "txntoken+jwt"`; body `txn` (a new UUID, or preserved
  when replacing an existing txn token), `sub`, `aud` (the trust domain),
  `scope` (narrow-only), `req_wl` (the authenticated client), `tctx` ←
  `request_details`, `rctx` ← `request_context`.
- **Replacement**: presenting a `txn_token` as the *subject* token preserves
  `txn`/`sub`/`aud`, only narrows scope, and rejects an expired token.
- **A2A profile** (`OAUTH2_A2A_PROFILE_ENABLED`): `purp` is set from the
  request; `tctx` (`request_details`) must be byte-identical across every
  replacement in the same transaction — supplying a different value is
  `invalid_request` (immutability, per draft-liu-oauth-a2a-profile). When the
  subject carries an `act` chain, `actor` (outermost `act.sub`) and
  `principal` (`sub`) are also set for draft-araut compatibility.
- Introspecting a txn token additionally returns `txn`, `purp`, `req_wl`.

## Transaction Authorization Challenge (human-in-the-loop)

Flag: `OAUTH2_TAC_ENABLED`. Lets an agent hit a sensitive operation, get a
signed challenge from the resource server, and have a human approve it out of
band (draft-rosomakho-oauth-txn-challenge), without the resource server ever
seeing the user's credentials.

1. A protected resource refuses an operation and returns a signed
   `transaction_challenge` JWT. Its `iss` must name a
   [registered `ProtectedResource`](#registries-and-admin-apis) that
   publishes a `txn_challenge_jwks_uri`.
2. The client submits it:

   ```bash
   curl -s https://auth.example.com/oauth/transaction_authorization \
     -u "agent-service:agent-secret" \
     -d transaction_challenge="$CHALLENGE_JWT"
   ```

   ```json
   { "transaction_authorization_id": "8e6f...", "expires_in": 600, "interval": 5 }
   ```
3. A human opens
   `GET /oauth/transaction_authorization/approve?transaction_authorization_id=8e6f...`,
   reviews the `reason` and `authorization_details` (and, if the challenge
   carried one, the acting agent's identity), and approves or denies.
4. The client polls the token endpoint:

   ```bash
   curl -s https://auth.example.com/oauth/token \
     -u "agent-service:agent-secret" \
     -d grant_type=urn:ietf:params:oauth:grant-type:transaction-authorization \
     -d transaction_authorization_id=8e6f...
   ```

   Returns `authorization_pending` while unresolved, `access_denied` if
   denied, `expired_token` past `expires_in`, or (once approved, on first
   use) a short-lived access token — capped at 300 seconds — carrying the
   challenge's `txn` claim and the approved `authorization_details`.

RFC 9470 step-up (`acr_values`/`max_age` on the challenge) is documented but
**not yet enforced** — see
[Security considerations](#security-considerations).

## Client ID Metadata Documents (CIMD)

Flag: `OAUTH2_CIMD_ENABLED`. Lets a client identify itself with an HTTPS URL
instead of pre-registering — the MCP authorization spec's preferred
onboarding path, per draft-ietf-oauth-client-id-metadata-document.

```bash
curl -s https://auth.example.com/oauth/authorize \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=https://app.example.com/oauth-client.json" \
  --data-urlencode "redirect_uri=https://app.example.com/callback" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" \
  -G
```

The server fetches `https://app.example.com/oauth-client.json` (HTTPS only,
no redirects, ≤5 KB, `application/json`, SSRF-guarded against loopback and
private/link-local/CGNAT ranges) and validates: the document's `client_id`
equals the fetch URL, `redirect_uris` is a non-empty array with no dangerous
schemes, `token_endpoint_auth_method` is `none` or `private_key_jwt` (never a
shared secret), and it does not request a privileged scope or an
unsupported grant type. A resolved client is displayed on the login/consent
surface as its `client_name` next to the request's hostname, e.g.
"*Example MCP Client (app.example.com)*".

Discovery advertises `client_id_metadata_document_supported: true` when
enabled. `OAUTH2_CIMD_MAX_CLIENTS` (default 1000) bounds how many CIMD
documents may be materialized into `clients` rows; see
[Security considerations](#security-considerations) for why materialization
happens at all and what it does and does not overwrite on re-fetch.

## Workload identity

- **SAN-based mTLS** (`token_endpoint_auth_method` = `tls_client_auth_san_uri`
  or `tls_client_auth_san_dns`): the reverse proxy supplies
  `X-SSL-Client-SAN-URI` / `X-SSL-Client-SAN-DNS`; the client's registered
  `tls_client_auth_san` value must match exactly (in addition to the usual
  certificate thumbprint check). Useful for SPIFFE-identified workloads.
  Discovery's `mtls_endpoint_aliases` mirrors `token_endpoint`,
  `introspection_endpoint`, `revocation_endpoint`.
- **Software statements** (RFC 7591 §2.3): a `software_statement` that is a
  JWT signed by a registered trusted issuer has its claims override the
  request body; an unsigned or unknown-issuer statement is rejected with
  `invalid_software_statement`. On the self-service paths that is the *only*
  way to set `software_id`/`software_version`: body-supplied values are
  stripped first.
- **`sub_profile` classification**: a client is treated as an AI agent
  (`sub_profile: "ai_agent"` on its client-credentials tokens) when its
  `software_id` starts with `agent:` or it has a non-empty `allowed_actors`
  list. `OAUTH2_AI_AGENT_ACCESS_TOKEN_TTL_SECS`, when set, caps that token's
  lifetime.

## Registries and admin APIs

Both registries sit under the existing `/admin` scope, behind the same
`AdminGuard` as the rest of the admin API.

### Protected resources — `/admin/resources`

Drives `resource`/`audience` validation in token exchange and per-resource
`GET /.well-known/oauth-protected-resource/{id}` (RFC 9728 §3.1).

```bash
curl -s https://auth.example.com/admin/resources \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "resource_uri": "https://api.example.com/mcp",
    "name": "Example MCP server",
    "scopes": ["mcp.read", "mcp.write"]
  }'
```

`GET /admin/resources` lists, `DELETE /admin/resources/{id}` removes. A
resource's `txn_challenge_jwks_uri`, when set, is what makes it eligible to
issue [Transaction Authorization Challenges](#transaction-authorization-challenge-human-in-the-loop).

### Trusted issuers — `/admin/trusted-issuers`

Drives the [jwt-bearer grant](#cross-domain-chaining-jwt-bearer-grant--id-jag)
and ID-JAG/TAC challenge signature verification.

```bash
curl -s https://auth.example.com/admin/trusted-issuers \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "issuer": "https://idp.example.com",
    "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
    "subject_mapping": "email",
    "jit_provision": true
  }'
```

`subject_mapping` is `"sub"` (default) or `"email"`. `allowed_client_ids`
(empty = any) restricts which of your clients may redeem this issuer's
assertions. `jwks_uri` must be `https://` with a host and no fragment.

### Client `allowed_actors`

Per-client policy for cross-client token-exchange delegation: a client
registration (or admin edit) may set `allowed_actors: ["agent-client-id"]` so
that `agent-client-id` may exchange tokens originally issued to this client
without needing a `may_act` claim in the subject token itself.

## DPoP: `ath` and replay

RFC 9449's `ath` claim (hash of the presented access token) is enforced on
introspection when a DPoP proof accompanies the request, closing the gap
where a stolen access token + a self-generated proof could pass DPoP
validation. The `jti` replay guard is storage-backed (`dpop_jtis` table /
collection) rather than in-memory, so it is correct across multiple server
instances sharing one database.

## Security considerations

- **Trusted issuers may assert any local email.** With
  `subject_mapping = "email"`, the jwt-bearer grant maps the assertion's
  `email` claim directly to a local account. This is an explicit,
  admin-controlled trust decision per issuer — but a compromised or
  misconfigured trusted issuer can impersonate any local user by email.
  Prefer `subject_mapping = "sub"` with JIT provisioning unless you need
  email-based federation.
- **CIMD rows are capped, not garbage-collected.** `OAUTH2_CIMD_MAX_CLIENTS`
  fails new documents closed once the cap is reached, but nothing removes a
  `cimd_managed` client row once its document stops being used. Plan for
  periodic cleanup in busy multi-tenant deployments; there is no built-in
  sweeper yet.
- **TAC step-up (RFC 9470) is a documented follow-up, not enforced.** A
  transaction challenge's `acr_values`/`max_age` are not yet checked against
  the approving session before showing the approval page.
- **Transaction-token introspection is not per-caller scoped.** Any
  authenticated client that can call `POST /oauth/introspect` sees a txn
  token's `sub`, `act`, `txn`, `purp`, `req_wl` — the same trust model as
  introspection of any other token type in this server.
- **`software_id` self-declaration is never accepted unattested.** On the
  self-service registration paths a body-supplied
  `software_id`/`software_version` is stripped before the request is
  processed; only values carried by a `software_statement` signed by a
  registered trusted issuer survive. (The admin registration endpoint is
  exempt: an operator setting them deliberately is the intended way to
  register an agent without a statement.) They matter because they select the
  `ai_agent` `sub_profile` and its shorter access-token TTL.
- **CIMD materializes a `clients` row on first use.** `tokens`,
  `authorization_codes` and `device_authorizations` all foreign-key to
  `clients(client_id)`, so a URL client_id needs a row before it can be
  granted anything. The row is written only after redirect-URI, PKCE,
  privileged-scope and grant-type validation pass, is capped by
  `OAUTH2_CIMD_MAX_CLIENTS`, and never overwrites operator-set fields
  (`enabled`, `allowed_actors`, `dpop_nonce_required`, …) when the document
  is re-fetched later.
