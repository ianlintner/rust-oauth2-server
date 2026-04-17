# Add Endpoint Skill

**Purpose**: Add a new HTTP endpoint to the OAuth2 server with proper handler, routing, tests, and documentation.

**When to Use**:
- Implementing new OAuth2/OIDC features
- Adding admin API endpoints
- Creating custom endpoints for specific use cases
- Extending server functionality

## Parameters

- `endpoint_path`: URL path for the endpoint (e.g., "/oauth/device", "/admin/users")
- `http_method`: HTTP method (GET, POST, PUT, DELETE)
- `handler_name`: Name for the handler function (e.g., "device_authorization")
- `purpose`: Brief description of endpoint purpose
- `authentication_required`: Whether endpoint requires authentication (true/false)

## Prerequisites

- Understanding of Actix-web framework
- Knowledge of OAuth2/OIDC specifications (if applicable)
- Familiarity with project structure and patterns
- Local development environment set up

## Prompt

Add a new HTTP endpoint with:
- Path: {{endpoint_path}}
- Method: {{http_method}}
- Handler name: {{handler_name}}
- Purpose: {{purpose}}
- Authentication required: {{authentication_required}}

Please perform these implementation steps following the project's patterns:

1. **Planning Phase**:
   - Review similar existing endpoints in `crates/oauth2-actix/src/handlers/`
   - Identify required dependencies (actors, storage, configuration)
   - Determine request/response formats
   - Check relevant RFC sections if implementing OAuth2/OIDC feature
   - Review CLAUDE.md for invariants and patterns

2. **Create Handler Function**:
   - Location: `crates/oauth2-actix/src/handlers/{module}.rs`
   - Follow existing pattern:
     ```rust
     use actix_web::{web, HttpResponse, HttpRequest};
     use crate::actors::*;

     pub async fn {{handler_name}}(
         req: HttpRequest,
         data: web::Json<RequestType>,
         // Add required app_data dependencies
         token_actor: web::Data<TokenActorPool>,
         client_actor: web::Data<Addr<ClientActor>>,
         // ... other dependencies
     ) -> HttpResponse {
         // 1. Extract and validate request data
         // 2. Perform authentication if required
         // 3. Call relevant actors or services
         // 4. Build response
         // 5. Return appropriate HTTP status
     }
     ```

3. **Define Request/Response Types** (if needed):
   - Location: `crates/oauth2-core/src/models/{domain}.rs`
   - Add Serde derives for JSON:
     ```rust
     use serde::{Deserialize, Serialize};

     #[derive(Debug, Serialize, Deserialize)]
     pub struct RequestType {
         // Request fields
     }

     #[derive(Debug, Serialize, Deserialize)]
     pub struct ResponseType {
         // Response fields
     }
     ```

4. **Register Route**:
   - Location: `crates/oauth2-server/src/lib.rs` or relevant module
   - Add route to appropriate scope:
     ```rust
     .service(
         web::scope("{{base_path}}")
             .route("{{endpoint_path}}", web::{{http_method}}().to({{handler_name}}))
     )
     ```
   - Ensure required app_data is injected:
     ```rust
     .app_data(web::Data::new(token_actor.clone()))
     .app_data(web::Data::new(client_actor.clone()))
     // ... other app_data
     ```

5. **Add Authentication/Authorization** (if required):
   - Use existing middleware or add checks in handler:
     ```rust
     // Extract session
     let session = Session::from_request(&req, &mut Payload::None).await?;

     // Verify authentication
     if let Some(user_id) = session.get::<String>("user_id")? {
         // User authenticated
     } else {
         return HttpResponse::Unauthorized().finish();
     }
     ```

6. **Create Unit Tests**:
   - Add tests to handler module:
     ```rust
     #[cfg(test)]
     mod tests {
         use super::*;
         use actix_web::test;

         #[actix_web::test]
         async fn test_{{handler_name}}_success() {
             // Setup test data
             // Call handler
             // Assert response
         }

         #[actix_web::test]
         async fn test_{{handler_name}}_invalid_input() {
             // Test error cases
         }
     }
     ```

7. **Create Integration Tests**:
   - Add to `tests/` directory or existing test file:
     ```rust
     #[actix_web::test]
     async fn test_{{endpoint_path}}_integration() {
         // 1. Setup test context (see tests/rfc_compliance.rs for pattern)
         let (token_actor, client_actor, ...) = setup_test_context().await;

         // 2. Build test app inline (do NOT use helper function)
         let app = test::init_service(
             App::new()
                 .app_data(web::Data::new(token_actor))
                 .app_data(web::Data::new(client_actor))
                 // ... all required app_data
                 .service(web::scope("{{base_path}}").route("{{endpoint_path}}", web::{{http_method}}().to({{handler_name}})))
         ).await;

         // 3. Create test request
         let req = test::TestRequest::{{http_method}}()
             .uri("{{endpoint_path}}")
             .set_json(&request_data)
             .to_request();

         // 4. Call service and assert
         let resp = test::call_service(&app, req).await;
         assert_eq!(resp.status(), 200);
         // ... more assertions
     }
     ```

8. **Add OpenAPI Documentation** (if public endpoint):
   - Location: `crates/oauth2-openapi/src/spec.rs`
   - Add endpoint spec following OpenAPI 3.0:
     ```rust
     openapi.paths.add(
         "{{endpoint_path}}",
         PathItem {
             {{http_method}}: Some(Operation {
                 summary: Some("{{purpose}}".to_string()),
                 description: Some("Detailed description".to_string()),
                 parameters: vec![/* ... */],
                 request_body: Some(/* ... */),
                 responses: /* ... */,
                 security: if {{authentication_required}} {
                     vec![/* ... */]
                 } else {
                     vec![]
                 },
                 ..Default::default()
             }),
             ..Default::default()
         },
     );
     ```

9. **Update Documentation**:
   - Add to `docs/usage/` or `docs/api/` as appropriate
   - Include:
     - Endpoint purpose and use case
     - Request format with examples
     - Response format with examples
     - Error responses
     - Authentication requirements
     - Rate limiting (if applicable)
     - RFC references (if implementing standard)

10. **Run CI Gate**:
    ```bash
    # Format code
    cargo fmt --all

    # Check formatting
    cargo fmt --all -- --check

    # Run clippy
    cargo clippy --all-targets --all-features -- -D warnings

    # Run tests
    cargo test --verbose --all-features --locked

    # Run specific tests
    cargo test {{handler_name}}
    cargo test {{endpoint_path}}
    ```

## Success Criteria

- [ ] Handler function created with proper signature
- [ ] Request/response types defined with Serde derives
- [ ] Route registered in server configuration
- [ ] Required app_data injected
- [ ] Authentication/authorization implemented (if required)
- [ ] Unit tests created and passing
- [ ] Integration tests created and passing
- [ ] OpenAPI spec updated
- [ ] Documentation written
- [ ] All CI gate checks pass
- [ ] No clippy warnings
- [ ] Code formatted correctly
- [ ] Endpoint accessible via HTTP

## Common Issues & Solutions

### Issue: Handler panics with "missing app_data"
**Solution**:
- Ensure all handler parameters have corresponding app_data in App::new()
- Check CLAUDE.md §app_data Required by Each Handler for required types
- Add missing types to both production and test app builders

### Issue: Tests fail with type errors
**Solution**:
- Don't return `impl Service<actix_http::Request>` from helpers
- Build App inline in each test function (see CLAUDE.md §RFC Testing Architecture)
- Return raw components tuple from setup functions

### Issue: TokenActor signature mismatch
**Solution**:
- TokenActor::new() takes 3 args: (storage, jwt_secret, issuer)
- Update all 5 call sites if adding new parameter
- See CLAUDE.md §Key Actors & Signatures

### Issue: Long lines in handler
**Solution**:
- Break tracing::debug!() calls across lines
- Split .map_err() chains
- Run `cargo fmt --all` to auto-fix
- See CLAUDE.md §Common Pitfalls

### Issue: Endpoint returns 404
**Solution**:
- Verify route path matches exactly (including leading slash)
- Check route is registered in correct scope
- Test with curl or Swagger UI
- Check server logs for route registration

## Related Resources

- [Development Agent](../.github/agents/development.md) - Coding guidelines
- [CLAUDE.md](../CLAUDE.md) - Agent memory and patterns
- [Actix-web Documentation](https://actix.rs/)
- [Handler Examples](../crates/oauth2-actix/src/handlers/)
- [Testing Patterns](../tests/rfc_compliance.rs)
- [OpenAPI Spec](../crates/oauth2-openapi/src/spec.rs)

## Example Usage

### Add Device Authorization Endpoint

```
Use the add-endpoint skill with:
- endpoint_path: /oauth/device_authorization
- http_method: POST
- handler_name: device_authorization
- purpose: RFC 8628 device authorization endpoint
- authentication_required: false
```

### Add Admin User Management Endpoint

```
Use the add-endpoint skill with:
- endpoint_path: /admin/users/{user_id}
- http_method: GET
- handler_name: get_user
- purpose: Retrieve user details for admin
- authentication_required: true
```

### Add Public Discovery Endpoint

```
Use the add-endpoint skill with:
- endpoint_path: /.well-known/oauth-authorization-server
- http_method: GET
- handler_name: authorization_server_metadata
- purpose: RFC 8414 authorization server metadata
- authentication_required: false
```

## Pattern Examples

### OAuth2 Token Endpoint Pattern

See `crates/oauth2-actix/src/handlers/oauth.rs:token()` for:
- Form-encoded request parsing
- Client authentication
- Multiple grant type handling
- Token generation via TokenActor
- Error responses per RFC 6749

### Admin Endpoint Pattern

See `crates/oauth2-actix/src/handlers/client.rs:register_client()` for:
- JSON request/response
- Session-based authentication
- Actor interaction (ClientActor)
- Validation and error handling

### Public Metadata Endpoint Pattern

See `crates/oauth2-actix/src/handlers/wellknown.rs:openid_configuration()` for:
- No authentication required
- Static or computed response
- JSON serialization
- Caching headers

## Notes

- All new endpoints must pass CI gate checks
- Follow existing patterns in similar handlers
- Write tests before implementation (TDD approach)
- Document as you code, not after
- Consider RFC compliance for OAuth2/OIDC endpoints
- Always inject required app_data in BOTH production and test code
- See CLAUDE.md for project-specific invariants and conventions
