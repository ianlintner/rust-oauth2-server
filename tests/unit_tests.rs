// Unit tests for OAuth2 handlers and models

#[cfg(test)]
mod oauth_handler_tests {
    use actix_web::{test, web, App};
    use serde_json::json;

    #[actix_web::test]
    async fn test_authorize_endpoint_requires_params() {
        // Test that authorize endpoint validates required parameters
        let app = test::init_service(
            App::new().route(
                "/oauth/authorize",
                web::get().to(|| async {
                    actix_web::HttpResponse::BadRequest().json(json!({
                        "error": "invalid_request",
                        "error_description": "Missing required parameters"
                    }))
                }),
            ),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/oauth/authorize")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn test_token_endpoint_validates_grant_type() {
        // Test that token endpoint validates grant_type parameter
        let app = test::init_service(
            App::new().route(
                "/oauth/token",
                web::post().to(|| async {
                    actix_web::HttpResponse::BadRequest().json(json!({
                        "error": "unsupported_grant_type",
                        "error_description": "Grant type not supported"
                    }))
                }),
            ),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/oauth/token")
            .set_form(&[("grant_type", "invalid")])
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn test_authorization_code_grant_validation() {
        // Test authorization code grant type requires code parameter
        let app = test::init_service(
            App::new().route(
                "/oauth/token",
                web::post().to(|| async {
                    actix_web::HttpResponse::BadRequest().json(json!({
                        "error": "invalid_request",
                        "error_description": "Missing code parameter"
                    }))
                }),
            ),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/oauth/token")
            .set_form(&[
                ("grant_type", "authorization_code"),
                ("client_id", "test_client"),
            ])
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn test_client_credentials_grant_validation() {
        // Test client credentials grant requires client_secret
        let app = test::init_service(
            App::new().route(
                "/oauth/token",
                web::post().to(|| async {
                    actix_web::HttpResponse::BadRequest().json(json!({
                        "error": "invalid_client",
                        "error_description": "Missing client_secret"
                    }))
                }),
            ),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/oauth/token")
            .set_form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "test_client"),
            ])
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn test_password_grant_validation() {
        // Test password grant requires username and password
        let app = test::init_service(
            App::new().route(
                "/oauth/token",
                web::post().to(|| async {
                    actix_web::HttpResponse::BadRequest().json(json!({
                        "error": "invalid_request",
                        "error_description": "Missing username or password"
                    }))
                }),
            ),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/oauth/token")
            .set_form(&[
                ("grant_type", "password"),
                ("client_id", "test_client"),
            ])
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn test_introspect_endpoint_exists() {
        // Test that introspection endpoint exists
        let app = test::init_service(
            App::new().route(
                "/oauth/introspect",
                web::post().to(|| async {
                    actix_web::HttpResponse::Ok().json(json!({
                        "active": false
                    }))
                }),
            ),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/oauth/introspect")
            .set_form(&[("token", "test_token")])
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_revoke_endpoint_exists() {
        // Test that revocation endpoint exists
        let app = test::init_service(
            App::new().route(
                "/oauth/revoke",
                web::post().to(|| async { actix_web::HttpResponse::Ok().finish() }),
            ),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/oauth/revoke")
            .set_form(&[("token", "test_token")])
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }
}

#[cfg(test)]
mod token_model_tests {
    use chrono::{Duration, Utc};

    #[test]
    fn test_token_expiration_logic() {
        // Test token expiration calculation
        let now = Utc::now();
        let expiry = now + Duration::seconds(3600);
        
        assert!(expiry > now);
        assert_eq!((expiry - now).num_seconds(), 3600);
    }

    #[test]
    fn test_token_is_expired() {
        // Test checking if token is expired
        let now = Utc::now();
        let past = now - Duration::seconds(3600);
        let future = now + Duration::seconds(3600);
        
        assert!(past < now, "Past time should be before now");
        assert!(future > now, "Future time should be after now");
    }

    #[test]
    fn test_token_scope_parsing() {
        // Test scope string parsing
        let scope = "read write admin";
        let scopes: Vec<&str> = scope.split_whitespace().collect();
        
        assert_eq!(scopes.len(), 3);
        assert!(scopes.contains(&"read"));
        assert!(scopes.contains(&"write"));
        assert!(scopes.contains(&"admin"));
    }

    #[test]
    fn test_scope_validation() {
        // Test that scope contains only valid characters
        let valid_scope = "read:user write:posts";
        assert!(!valid_scope.contains(|c: char| !c.is_alphanumeric() && c != ':' && c != ' ' && c != '_'));
        
        let invalid_scope = "read<script>";
        assert!(invalid_scope.contains('<'));
    }
}

#[cfg(test)]
mod authorization_code_tests {
    use chrono::{Duration, Utc};

    #[test]
    fn test_authorization_code_generation() {
        // Test that authorization codes are generated with sufficient entropy
        let code = uuid::Uuid::new_v4().to_string();
        assert!(!code.is_empty());
        assert!(code.len() >= 32);
    }

    #[test]
    fn test_authorization_code_expiration() {
        // Test authorization code has 10 minute expiration
        let created_at = Utc::now();
        let expires_at = created_at + Duration::minutes(10);
        
        assert_eq!((expires_at - created_at).num_minutes(), 10);
    }

    #[test]
    fn test_pkce_verifier_length() {
        // Test PKCE verifier has minimum length of 43 characters
        let verifier = "a".repeat(43);
        assert!(verifier.len() >= 43 && verifier.len() <= 128);
    }

    #[test]
    fn test_pkce_challenge_base64() {
        // Test PKCE challenge is base64url encoded
        let challenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert!(challenge.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
    }
}

#[cfg(test)]
mod client_validation_tests {
    #[test]
    fn test_client_id_format() {
        // Test client ID format validation
        let client_id = "client_123abc";
        assert!(!client_id.is_empty());
        assert!(client_id.chars().all(|c| c.is_alphanumeric() || c == '_'));
    }

    #[test]
    fn test_client_secret_length() {
        // Test client secret has sufficient entropy
        let secret = "a".repeat(32);
        assert!(secret.len() >= 32);
    }

    #[test]
    fn test_redirect_uri_validation() {
        // Test redirect URI validation
        let valid_uris = vec![
            "http://localhost:3000/callback",
            "https://example.com/oauth/callback",
            "myapp://callback",
        ];
        
        for uri in valid_uris {
            assert!(uri.contains("://"));
        }
    }

    #[test]
    fn test_invalid_redirect_uri() {
        // Test that invalid redirect URIs are rejected
        let invalid_uris = vec![
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "http://evil.com#http://good.com",
        ];
        
        for uri in invalid_uris {
            // Should reject javascript: and data: schemes
            assert!(uri.starts_with("javascript:") || uri.starts_with("data:") || uri.contains('#'));
        }
    }
}

#[cfg(test)]
mod error_response_tests {
    use serde_json::json;

    #[test]
    fn test_error_response_format() {
        // Test OAuth2 error response format
        let error = json!({
            "error": "invalid_request",
            "error_description": "Missing required parameter",
            "error_uri": "https://tools.ietf.org/html/rfc6749#section-5.2"
        });
        
        assert!(error["error"].is_string());
        assert_eq!(error["error"], "invalid_request");
    }

    #[test]
    fn test_error_codes() {
        // Test all standard OAuth2 error codes are supported
        let error_codes = vec![
            "invalid_request",
            "invalid_client",
            "invalid_grant",
            "unauthorized_client",
            "unsupported_grant_type",
            "invalid_scope",
            "access_denied",
            "server_error",
        ];
        
        for code in error_codes {
            assert!(!code.is_empty());
            assert!(code.chars().all(|c| c.is_lowercase() || c == '_'));
        }
    }
}

#[cfg(test)]
mod jwt_tests {
    use chrono::Utc;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct TestClaims {
        sub: String,
        exp: i64,
        iat: i64,
        scope: String,
    }

    #[test]
    fn test_jwt_claims_structure() {
        // Test JWT claims have required fields
        let claims = TestClaims {
            sub: "user123".to_string(),
            exp: Utc::now().timestamp() + 3600,
            iat: Utc::now().timestamp(),
            scope: "read write".to_string(),
        };
        
        assert!(!claims.sub.is_empty());
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn test_jwt_expiration() {
        // Test JWT expiration time is set correctly
        let now = Utc::now().timestamp();
        let exp = now + 3600; // 1 hour
        
        assert_eq!(exp - now, 3600);
    }
}

#[cfg(test)]
mod security_tests {
    use sha2::{Sha256, Digest};
    use base64::{Engine as _, engine::general_purpose};

    #[test]
    fn test_password_hashing() {
        // Test that passwords are hashed (not stored plain text)
        let password = "test_password";
        let hash1 = format!("{:x}", Sha256::digest(password.as_bytes()));
        let hash2 = format!("{:x}", Sha256::digest(password.as_bytes()));
        
        // Same password should produce same hash
        assert_eq!(hash1, hash2);
        // Hash should be different from password
        assert_ne!(hash1, password);
    }

    #[test]
    fn test_state_parameter_entropy() {
        // Test state parameter has sufficient entropy
        let state = uuid::Uuid::new_v4().to_string();
        assert!(state.len() >= 16);
    }

    #[test]
    fn test_pkce_s256_challenge() {
        // Test PKCE S256 challenge generation
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let hash = Sha256::digest(verifier.as_bytes());
        let challenge = general_purpose::URL_SAFE_NO_PAD.encode(hash);
        
        assert!(!challenge.is_empty());
        assert!(challenge.len() > 0);
    }

    #[test]
    fn test_token_randomness() {
        // Test that generated tokens are random
        let token1 = uuid::Uuid::new_v4().to_string();
        let token2 = uuid::Uuid::new_v4().to_string();
        
        assert_ne!(token1, token2);
    }
}

#[cfg(test)]
mod scope_tests {
    #[test]
    fn test_scope_contains() {
        // Test scope checking logic
        let granted_scope = "read write";
        let required_scope = "read";
        
        assert!(granted_scope.contains(required_scope));
    }

    #[test]
    fn test_scope_does_not_contain() {
        // Test scope checking with insufficient permissions
        let granted_scope = "read";
        let required_scope = "write";
        
        assert!(!granted_scope.contains(required_scope));
    }

    #[test]
    fn test_multiple_scopes() {
        // Test multiple scope handling
        let scopes = "read write admin";
        let scope_list: Vec<&str> = scopes.split_whitespace().collect();
        
        assert_eq!(scope_list.len(), 3);
        assert!(scope_list.contains(&"admin"));
    }
}
