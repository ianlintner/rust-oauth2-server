# Development Agent Instructions

You are a specialized development agent for the Rust OAuth2 Server project. Your role is to assist with code development, debugging, testing, and maintaining code quality.

## Project Overview

This is a production-ready OAuth2 authorization server built with:
- **Language**: Rust 2021 edition
- **Framework**: Actix-web with actor model
- **Database**: SQLx with PostgreSQL/SQLite support
- **Architecture**: Actor-based concurrent processing
- **Observability**: Prometheus metrics, OpenTelemetry tracing

## Core Technologies

### Rust Dependencies
- `actix-web` (4.4) - Web framework
- `actix` (0.13) - Actor system
- `sqlx` (0.8) - Database access
- `jsonwebtoken` (9.2) - JWT handling
- `argon2` (0.5) - Password hashing
- `utoipa` (5.4) - OpenAPI generation
- `opentelemetry` (0.21) - Distributed tracing

### Key Features
- OAuth2 flows: Authorization Code, Client Credentials, Password, Refresh Token
- PKCE support for enhanced security
- Social login integration (Google, Microsoft, GitHub, Azure, Okta, Auth0)
- Token introspection and revocation
- Health checks and metrics
- Swagger UI documentation

## Development Workflow

### Building
```bash
cargo build                    # Development build
cargo build --release          # Production build
cargo check                    # Fast syntax check
```

### Testing
```bash
cargo test                     # Run unit tests
cargo test --test integration  # Run integration tests
cargo test --test bdd          # Run BDD tests
```

### Code Quality
```bash
cargo fmt                      # Format code
cargo clippy --all-targets --all-features -- -D warnings  # Lint
cargo audit                    # Security audit
```

## Project Structure

```
src/
├── main.rs              # Application entry point
├── config/              # Configuration management
├── db/                  # Database layer
├── handlers/            # HTTP request handlers
├── actors/              # Actor system components
├── models/              # Data models
├── services/            # Business logic
├── middleware/          # HTTP middleware
├── metrics.rs           # Prometheus metrics
└── telemetry.rs         # OpenTelemetry setup
```

## Coding Standards

### Style Guidelines
1. **Follow Rust idioms**:
   - Use `Result<T, E>` for error handling
   - Prefer `Option<T>` over null-like patterns
   - Use pattern matching extensively
   - Implement `Display` and `Debug` traits where appropriate

2. **Error Handling**:
   - Use custom error types
   - Propagate errors with `?` operator
   - Provide context with error messages
   - Log errors appropriately

3. **Async/Await**:
   - Use `async`/`await` for I/O operations
   - Prefer `tokio` runtime features
   - Handle actor message passing properly

4. **Database**:
   - Use compile-time checked queries with SQLx
   - Use transactions for multi-step operations
   - Handle database errors gracefully
   - Include migrations for schema changes

### Code Organization
```rust
// Imports grouped and sorted
use actix_web::{web, HttpResponse};
use sqlx::PgPool;
use crate::models::Client;

// Struct with documentation
/// OAuth2 client representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub client_id: String,
    pub client_secret: String,
    // ... fields
}

// Implementation with error handling
pub async fn register_client(
    pool: web::Data<PgPool>,
    data: web::Json<ClientRequest>,
) -> Result<HttpResponse, Error> {
    let client = create_client(&pool, &data).await?;
    Ok(HttpResponse::Created().json(client))
}
```

## Common Tasks

### Adding a New Endpoint

1. **Define the model** in `src/models/`
2. **Create handler** in `src/handlers/`
3. **Add route** in `src/main.rs`
4. **Add OpenAPI docs** with `#[utoipa::path]`
5. **Write tests** in `tests/`
6. **Update documentation** in `docs/api/`

Example:
```rust
#[utoipa::path(
    post,
    path = "/api/resource",
    request_body = ResourceRequest,
    responses(
        (status = 201, description = "Resource created", body = Resource),
        (status = 400, description = "Bad request", body = ErrorResponse)
    ),
    tag = "resources"
)]
pub async fn create_resource(
    pool: web::Data<PgPool>,
    data: web::Json<ResourceRequest>,
) -> Result<HttpResponse, Error> {
    // Implementation
}
```

### Adding Database Migrations

1. Create migration file in `migrations/sql/`:
   ```sql
   -- V5__description.sql
   CREATE TABLE new_table (
       id UUID PRIMARY KEY,
       created_at TIMESTAMP NOT NULL DEFAULT NOW()
   );
   ```

2. Run migration:
   ```bash
   ./scripts/migrate.sh
   ```

3. Update models in `src/models/`

### Adding Metrics

```rust
use crate::metrics::METRICS;

// Increment counter
METRICS.oauth_token_issued_total.inc();

// Record histogram
let start = Instant::now();
// ... operation
METRICS.db_query_duration.observe(start.elapsed().as_secs_f64());
```

### Adding Actor

```rust
use actix::prelude::*;

#[derive(Message)]
#[rtype(result = "Result<Response, Error>")]
pub struct Request {
    // fields
}

pub struct MyActor {
    pool: PgPool,
}

impl Actor for MyActor {
    type Context = Context<Self>;
}

impl Handler<Request> for MyActor {
    type Result = ResponseFuture<Result<Response, Error>>;

    fn handle(&mut self, msg: Request, _ctx: &mut Context<Self>) -> Self::Result {
        let pool = self.pool.clone();
        Box::pin(async move {
            // Handle request
            Ok(Response {})
        })
    }
}
```

## Debugging Tips

### Enable Verbose Logging
```bash
export RUST_LOG=debug,actix_web=debug,sqlx=debug
cargo run
```

### Database Debugging
```rust
// Log query
sqlx::query!("SELECT * FROM clients WHERE client_id = $1", client_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Database query failed: {}", e);
        e
    })?
```

### Actor Debugging
```rust
impl Handler<Message> for Actor {
    fn handle(&mut self, msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        debug!("Handling message: {:?}", msg);
        // ...
    }
}
```

## Testing Guidelines

### Unit Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function() {
        let result = function();
        assert_eq!(result, expected);
    }

    #[actix_rt::test]
    async fn test_async_function() {
        let result = async_function().await;
        assert!(result.is_ok());
    }
}
```

### Integration Tests
Located in `tests/integration.rs`:
```rust
#[actix_rt::test]
async fn test_register_client() {
    let pool = setup_test_db().await;
    // Test implementation
}
```

### BDD Tests
Located in `tests/features/*.feature` and `tests/bdd.rs`:
```gherkin
Feature: Client Registration
  Scenario: Register new client
    Given I have client details
    When I register the client
    Then I should receive client credentials
```

## Security Considerations

1. **Never log sensitive data** (passwords, secrets, tokens)
2. **Use prepared statements** for all SQL queries
3. **Validate all input** with validator crate
4. **Hash passwords** with Argon2
5. **Use constant-time comparison** for secrets
6. **Set appropriate CORS** policies
7. **Implement rate limiting** (planned feature)

## Performance Tips

1. **Use connection pooling** (already configured)
2. **Minimize database queries** (use joins when possible)
3. **Cache frequently accessed data** (consider adding Redis)
4. **Use async/await properly** (don't block)
5. **Profile with criterion** for benchmarks

## Documentation

- **Inline docs**: Use `///` for public APIs
- **Module docs**: Use `//!` at module top
- **Examples**: Include usage examples
- **Update OpenAPI**: Keep Swagger docs current

## Git Workflow

1. Create feature branch: `git checkout -b feature/description`
2. Make changes with atomic commits
3. Run tests and linting: `cargo test && cargo clippy`
4. Update documentation if needed
5. Create pull request with description

## Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Actix Documentation](https://actix.rs/)
- [SQLx Documentation](https://docs.rs/sqlx/)
- [OAuth2 RFC 6749](https://tools.ietf.org/html/rfc6749)
- Project docs: `docs/` directory

## Common Issues

### Database Connection Errors
- Check `OAUTH2_DATABASE_URL` environment variable
- Ensure PostgreSQL is running
- Verify database exists and migrations are applied

### Build Errors
- Update dependencies: `cargo update`
- Clean build: `cargo clean && cargo build`
- Check Rust version: `rustc --version` (need 1.70+)

### Actor Message Errors
- Ensure message types implement `Message` trait
- Check actor is started and address is valid
- Use `.send()` for async, `.do_send()` for fire-and-forget

## Getting Help

- Check project documentation in `docs/`
- Review existing code for patterns
- Search issues on GitHub
- Ask in project discussions
