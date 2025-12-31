use actix_web::{HttpResponse, Result};
use serde_json::json;

/// OAuth2 discovery endpoint
/// Returns server metadata according to RFC 8414
pub async fn openid_configuration() -> Result<HttpResponse> {
    let config = json!({
        "issuer": "http://localhost:8080",
        "authorization_endpoint": "http://localhost:8080/oauth/authorize",
        "token_endpoint": "http://localhost:8080/oauth/token",
        "token_introspection_endpoint": "http://localhost:8080/oauth/introspect",
        "token_revocation_endpoint": "http://localhost:8080/oauth/revoke",
        "registration_endpoint": "http://localhost:8080/clients/register",
        "scopes_supported": ["read", "write", "admin"],
        "response_types_supported": ["code", "token"],
        "grant_types_supported": [
            "authorization_code",
            "client_credentials",
            "password",
            "refresh_token"
        ],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post"
        ],
        "code_challenge_methods_supported": ["plain", "S256"],
        "service_documentation": "http://localhost:8080/docs"
    });

    Ok(HttpResponse::Ok().json(config))
}
