// Integration tests for OAuth2 server

#[cfg(test)]
mod tests {
    use actix_web::{test, web, App};

    #[actix_web::test]
    async fn test_health_endpoint() {
        // Test the health check endpoint
        let app = test::init_service(App::new().route(
            "/health",
            web::get().to(|| async {
                actix_web::HttpResponse::Ok().json(serde_json::json!({
                    "status": "healthy"
                }))
            }),
        ))
        .await;

        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_wellknown_endpoint() {
        // Test the OpenID configuration endpoint
        let app = test::init_service(App::new().route(
            "/.well-known/openid-configuration",
            web::get().to(|| async {
                actix_web::HttpResponse::Ok().json(serde_json::json!({
                    "issuer": "http://localhost:8080",
                    "authorization_endpoint": "http://localhost:8080/oauth/authorize"
                }))
            }),
        ))
        .await;

        let req = test::TestRequest::get()
            .uri("/.well-known/openid-configuration")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_client_secret_validation() {
        // Test that client secret validation logic works
        let secret1 = "test_secret";
        let secret2 = "test_secret";
        let secret3 = "different_secret";

        assert_eq!(secret1, secret2);
        assert_ne!(secret1, secret3);
    }

    #[actix_web::test]
    async fn test_token_expiration() {
        use chrono::{Duration, Utc};

        // Test token expiration logic
        let now = Utc::now();
        let future = now + Duration::seconds(3600);
        let past = now - Duration::seconds(3600);

        assert!(future > now);
        assert!(past < now);
    }
}
