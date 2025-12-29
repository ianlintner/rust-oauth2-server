use utoipa::OpenApi;

/// OpenAPI document generator.
///
/// Kept in the library crate so it can be reused by:
/// - the main server binary (Swagger UI + `/api-docs/openapi.json`)
/// - tooling binaries (exporting a static spec for MkDocs)
#[derive(OpenApi)]
#[openapi(
    components(
        schemas(
            crate::models::TokenResponse,
            crate::models::IntrospectionResponse,
            crate::models::ClientRegistration,
            crate::models::ClientCredentials,
            crate::models::OAuth2Error,
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
