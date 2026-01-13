use actix_web::{web, HttpRequest, HttpResponse, Result};
use oauth2_config::ServerConfig;
use serde_json::json;

fn normalize_base_url(base: &str) -> String {
    base.trim().trim_end_matches('/').to_string()
}

fn join_url(base: &str, path: &str) -> String {
    let base = normalize_base_url(base);
    if path.is_empty() {
        return base;
    }
    if path.starts_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    }
}

fn strip_quotes(s: &str) -> &str {
    s.trim().trim_matches('"')
}

fn first_list_value(s: &str) -> &str {
    // X-Forwarded-* headers frequently carry comma-separated lists.
    s.split(',').next().unwrap_or("").trim()
}

fn forwarded_proto_host(req: &HttpRequest) -> (Option<String>, Option<String>) {
    // Parse RFC 7239 Forwarded header (best-effort).
    // Example: Forwarded: proto=https;host=example.com
    let Some(fwd) = req.headers().get("forwarded") else {
        return (None, None);
    };
    let Ok(fwd) = fwd.to_str() else {
        return (None, None);
    };
    let first = first_list_value(fwd);
    let mut proto: Option<String> = None;
    let mut host: Option<String> = None;
    for part in first.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            match k.trim().to_ascii_lowercase().as_str() {
                "proto" => proto = Some(strip_quotes(v).to_string()),
                "host" => host = Some(strip_quotes(v).to_string()),
                _ => {}
            }
        }
    }
    (proto, host)
}

fn effective_base_url(req: &HttpRequest, server: Option<&ServerConfig>) -> String {
    // 1) Explicit config override.
    if let Some(server) = server {
        if let Some(ref base) = server.public_base_url {
            let b = base.trim();
            if !b.is_empty() {
                return normalize_base_url(b);
            }
        }
    }

    // 2) Proxy headers (only if explicitly enabled).
    if server.map(|s| s.trust_proxy_headers).unwrap_or(false) {
        let (mut proto, mut host) = forwarded_proto_host(req);

        if proto.is_none() {
            proto = req
                .headers()
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .map(first_list_value)
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string());
        }

        if host.is_none() {
            host = req
                .headers()
                .get("x-forwarded-host")
                .and_then(|v| v.to_str().ok())
                .map(first_list_value)
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string());
        }

        // Optional prefix (common with ingress controllers).
        let prefix = req
            .headers()
            .get("x-forwarded-prefix")
            .and_then(|v| v.to_str().ok())
            .map(first_list_value)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("");

        if let (Some(proto), Some(host)) = (proto, host) {
            let prefix = if prefix.is_empty() {
                "".to_string()
            } else if prefix.starts_with('/') {
                prefix.trim_end_matches('/').to_string()
            } else {
                format!("/{}", prefix.trim_end_matches('/'))
            };

            return normalize_base_url(&format!("{}://{}{}", proto, host, prefix));
        }
    }

    // 3) Fall back to request connection info.
    // Note: This reflects the bind address unless proxy headers are enabled.
    let conn = req.connection_info();
    format!("{}://{}", conn.scheme(), conn.host())
}

/// OAuth2 discovery endpoint
/// Returns server metadata according to RFC 8414
pub async fn openid_configuration(
    req: HttpRequest,
    server: Option<web::Data<ServerConfig>>,
) -> Result<HttpResponse> {
    let server_ref = server.as_ref().map(|d| d.get_ref());
    let base = effective_base_url(&req, server_ref);

    let config = json!({
        "issuer": base.clone(),
        "authorization_endpoint": join_url(&base, "/oauth/authorize"),
        "token_endpoint": join_url(&base, "/oauth/token"),
        "token_introspection_endpoint": join_url(&base, "/oauth/introspect"),
        "token_revocation_endpoint": join_url(&base, "/oauth/revoke"),
        "registration_endpoint": join_url(&base, "/clients/register"),
        "scopes_supported": ["read", "write", "admin"],
        // The server supports Authorization Code + Client Credentials.
        // Implicit, Password, and Refresh Token grants are intentionally disabled by default
        // (OAuth 2.0 Security Best Current Practice).
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "client_credentials"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post"
        ],
        "code_challenge_methods_supported": ["S256"],
        "service_documentation": join_url(&base, "/docs")
    });

    Ok(HttpResponse::Ok().json(config))
}
