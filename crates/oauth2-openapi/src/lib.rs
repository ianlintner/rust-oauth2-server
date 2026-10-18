//! OpenAPI document generator.
//!
//! Kept in its own crate so it can be reused by:
//! - the main server binary (Swagger UI + `/api-docs/openapi.json`)
//! - tooling binaries (exporting a static spec for MkDocs)
//!
//! Path stubs are intentionally never called; they exist only to anchor
//! `#[utoipa::path]` metadata for the OpenAPI spec generator.
#![allow(dead_code)]
use utoipa::OpenApi;

// ---------------------------------------------------------------------------
// Path stubs – these functions exist only to anchor #[utoipa::path] metadata.
// They are never called at runtime.
// ---------------------------------------------------------------------------

/// `GET /oauth/authorize`
///
/// Authorization Code flow entry point (RFC 6749 §4.1.1).
#[utoipa::path(
    get,
    path = "/oauth/authorize",
    tag = "OAuth2",
    summary = "Authorization endpoint",
    description = "Initiates the Authorization Code flow. On success, redirects to the registered `redirect_uri` with an authorization code.",
    params(
        ("response_type" = String, Query, description = "Must be `code`"),
        ("client_id" = String, Query, description = "Registered client identifier"),
        ("redirect_uri" = Option<String>, Query, description = "Registered redirect URI"),
        ("scope" = Option<String>, Query, description = "Space-separated list of requested scopes"),
        ("state" = Option<String>, Query, description = "Opaque value used to maintain state between request and callback"),
        ("nonce" = Option<String>, Query, description = "OIDC nonce – bound into the id_token"),
        ("code_challenge" = Option<String>, Query, description = "PKCE code challenge (RFC 7636)"),
        ("code_challenge_method" = Option<String>, Query, description = "PKCE method: `S256` (only; `plain` is rejected)"),
    ),
    responses(
        (status = 302, description = "Redirect to redirect_uri with `code` parameter"),
        (status = 400, description = "Invalid request", body = oauth2_core::OAuth2Error),
        (status = 401, description = "Unauthorized – user not authenticated"),
    )
)]
async fn authorize_stub() {}

/// `POST /oauth/token`
///
/// Token endpoint (RFC 6749 §3.2).  Supports `authorization_code`,
/// `client_credentials`, `refresh_token`, and
/// `urn:ietf:params:oauth:grant-type:device_code`.
#[utoipa::path(
    post,
    path = "/oauth/token",
    tag = "OAuth2",
    summary = "Token endpoint",
    description = "Issues access tokens.  Accepts `application/x-www-form-urlencoded` bodies.",
    request_body(
        content_type = "application/x-www-form-urlencoded",
        description = "Token request parameters",
        content = inline(oauth2_core::TokenResponse)
    ),
    responses(
        (status = 200, description = "Token issued", body = oauth2_core::TokenResponse),
        (status = 400, description = "Invalid request", body = oauth2_core::OAuth2Error),
        (status = 401, description = "Client authentication failed", body = oauth2_core::OAuth2Error),
    )
)]
async fn token_stub() {}

/// `GET /oauth/logout`
///
/// OIDC RP-Initiated Logout (OpenID Connect RP-Initiated Logout 1.0).
#[utoipa::path(
    get,
    path = "/oauth/logout",
    tag = "OAuth2",
    summary = "OIDC RP-Initiated Logout",
    description = "Terminates the user's local session. If `post_logout_redirect_uri` is provided and matches a registered redirect URI, redirects there after logout.",
    params(
        ("id_token_hint" = Option<String>, Query, description = "Previously issued ID token; used to identify the session/client"),
        ("post_logout_redirect_uri" = Option<String>, Query, description = "URI to redirect to after logout; must match a registered redirect URI"),
        ("state" = Option<String>, Query, description = "Opaque state value passed back on redirect"),
    ),
    responses(
        (status = 200, description = "Session terminated; no redirect requested"),
        (status = 302, description = "Redirect to post_logout_redirect_uri"),
        (status = 400, description = "Invalid or unregistered post_logout_redirect_uri", body = oauth2_core::OAuth2Error),
    )
)]
async fn logout_stub() {}

/// `POST /oauth/introspect`
///
/// Token Introspection (RFC 7662).
#[utoipa::path(
    post,
    path = "/oauth/introspect",
    tag = "Token Management",
    summary = "Token introspection",
    description = "Returns metadata about an access or refresh token. Requires client authentication.",
    request_body(
        content_type = "application/x-www-form-urlencoded",
        description = "Form field `token` containing the token to introspect; optional `token_type_hint`",
        content = String
    ),
    security(
        ("client_secret_basic" = []),
        ("client_secret_post" = []),
    ),
    responses(
        (status = 200, description = "Introspection result", body = oauth2_core::IntrospectionResponse),
        (status = 400, description = "Invalid request", body = oauth2_core::OAuth2Error),
        (status = 401, description = "Client authentication failed", body = oauth2_core::OAuth2Error),
    )
)]
async fn introspect_stub() {}

/// `POST /oauth/revoke`
///
/// Token Revocation (RFC 7009).
#[utoipa::path(
    post,
    path = "/oauth/revoke",
    tag = "Token Management",
    summary = "Token revocation",
    description = "Revokes an access or refresh token. Requires client authentication.",
    request_body(
        content_type = "application/x-www-form-urlencoded",
        description = "Form field `token` to revoke; optional `token_type_hint`",
        content = String
    ),
    security(
        ("client_secret_basic" = []),
        ("client_secret_post" = []),
    ),
    responses(
        (status = 200, description = "Token revoked (or already invalid; per RFC 7009 always 200)"),
        (status = 400, description = "Invalid request", body = oauth2_core::OAuth2Error),
        (status = 401, description = "Client authentication failed", body = oauth2_core::OAuth2Error),
    )
)]
async fn revoke_stub() {}

/// `GET /oauth/userinfo` and `POST /oauth/userinfo`
///
/// OIDC UserInfo endpoint (OpenID Connect Core §5.3).
#[utoipa::path(
    get,
    path = "/oauth/userinfo",
    tag = "OAuth2",
    summary = "OIDC UserInfo endpoint",
    description = "Returns claims about the authenticated user. Requires a Bearer access token with the `openid` scope.",
    security(
        ("bearer_auth" = ["openid"]),
    ),
    responses(
        (status = 200, description = "UserInfo claims as JSON"),
        (status = 401, description = "Missing or invalid token", body = oauth2_core::OAuth2Error),
    )
)]
async fn userinfo_stub() {}

/// `POST /oauth/device_authorization`
///
/// Device Authorization (RFC 8628 §3.1).
#[utoipa::path(
    post,
    path = "/oauth/device_authorization",
    tag = "OAuth2",
    summary = "Device authorization endpoint",
    description = "Initiates the Device Authorization Grant. Returns `device_code`, `user_code`, `verification_uri`, and `interval`.",
    request_body(
        content_type = "application/x-www-form-urlencoded",
        description = "`client_id` and optional `scope`",
        content = String
    ),
    responses(
        (status = 200, description = "Device authorization response"),
        (status = 400, description = "Invalid request", body = oauth2_core::OAuth2Error),
    )
)]
async fn device_authorization_stub() {}

/// `GET /.well-known/openid-configuration`
///
/// OIDC Discovery (OpenID Connect Discovery 1.0 + RFC 8414).
#[utoipa::path(
    get,
    path = "/.well-known/openid-configuration",
    tag = "OAuth2",
    summary = "OIDC Discovery document",
    description = "Returns server metadata: supported endpoints, grant types, algorithms, etc.",
    responses(
        (status = 200, description = "OIDC Provider Metadata"),
    )
)]
async fn openid_configuration_stub() {}

/// `GET /.well-known/jwks.json`
///
/// JSON Web Key Set (RFC 7517).
#[utoipa::path(
    get,
    path = "/.well-known/jwks.json",
    tag = "OAuth2",
    summary = "JSON Web Key Set",
    description = "Returns the public keys used to verify tokens issued by this server.",
    responses(
        (status = 200, description = "JWKS document"),
    )
)]
async fn jwks_stub() {}

/// `POST /admin/clients/register`
///
/// Dynamic Client Registration (RFC 7591-inspired).
#[utoipa::path(
    post,
    path = "/admin/clients/register",
    tag = "Client Management",
    summary = "Register a new client",
    description = "Registers a new OAuth2 client application. Requires admin session.",
    request_body(
        content_type = "application/json",
        description = "Client registration metadata",
        content = oauth2_core::ClientRegistration
    ),
    responses(
        (status = 201, description = "Client registered", body = oauth2_core::ClientCredentials),
        (status = 400, description = "Invalid registration request", body = oauth2_core::OAuth2Error),
        (status = 401, description = "Authentication required", body = oauth2_core::OAuth2Error),
    )
)]
async fn register_client_stub() {}

/// `GET /health`
#[utoipa::path(
    get,
    path = "/health",
    tag = "Observability",
    summary = "Liveness probe",
    description = "Returns 200 OK when the server process is running.",
    responses(
        (status = 200, description = "Server is alive"),
    )
)]
async fn health_stub() {}

/// `GET /ready`
#[utoipa::path(
    get,
    path = "/ready",
    tag = "Observability",
    summary = "Readiness probe",
    description = "Returns 200 OK when the server is ready to accept traffic (database connection healthy).",
    responses(
        (status = 200, description = "Server is ready"),
        (status = 503, description = "Not ready – storage unavailable"),
    )
)]
async fn readiness_stub() {}

#[derive(OpenApi)]
#[openapi(
    paths(
        authorize_stub,
        token_stub,
        logout_stub,
        introspect_stub,
        revoke_stub,
        userinfo_stub,
        device_authorization_stub,
        openid_configuration_stub,
        jwks_stub,
        register_client_stub,
        health_stub,
        readiness_stub,
    ),
    components(
        schemas(
            oauth2_core::TokenResponse,
            oauth2_core::IntrospectionResponse,
            oauth2_core::ClientRegistration,
            oauth2_core::ClientCredentials,
            oauth2_core::OAuth2Error,
        )
    ),
    tags(
        (name = "OAuth2", description = "OAuth2 authentication and authorization endpoints"),
        (name = "Client Management", description = "Client registration and management"),
        (name = "Token Management", description = "Token introspection and revocation"),
        (name = "Admin", description = "Administrative and monitoring endpoints"),
        (name = "Observability", description = "Health checks and metrics"),
    ),
    info(
        title = "OAuth2 Server API",
        version = "0.1.0",
        description = "A complete OAuth2 server implementation with Actix-web, featuring social logins and OIDC support",
        contact(
            name = "API Support",
            email = "support@example.com"
        ),
        license(
            name = "MIT OR Apache-2.0"
        )
    )
)]
pub struct ApiDoc;
