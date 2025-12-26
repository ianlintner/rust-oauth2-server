# Contributing Guide

Thank you for your interest in contributing to the Rust OAuth2 Server! This guide will help you get started.

## Code of Conduct

Be respectful, inclusive, and professional in all interactions.

## Getting Started

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/rust_oauth2.git
cd rust_oauth2

# Add upstream remote
git remote add upstream https://github.com/ianlintner/rust_oauth2.git
```

### 2. Set Up Development Environment

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install dependencies
rustup component add clippy rustfmt

# Build the project
cargo build

# Run tests
cargo test
```

### 3. Create a Branch

```bash
# Update your fork
git checkout main
git pull upstream main

# Create a feature branch
git checkout -b feature/your-feature-name
```

## Development Workflow

### Code Style

We follow the official Rust style guide. Use `rustfmt` and `clippy`:

```bash
# Format code
cargo fmt

# Run linter
cargo clippy -- -D warnings

# Check all
cargo fmt && cargo clippy -- -D warnings && cargo test
```

### Project Structure

```
rust_oauth2/
├── src/
│   ├── actors/          # Actor implementations
│   ├── handlers/        # HTTP request handlers
│   ├── models/          # Data models
│   ├── middleware/      # Middleware components
│   ├── services/        # Business logic
│   ├── db/              # Database access
│   ├── config/          # Configuration
│   ├── metrics.rs       # Prometheus metrics
│   └── main.rs          # Application entry point
├── tests/               # Integration tests
├── migrations/          # Database migrations
├── docs/                # Documentation
└── Cargo.toml           # Dependencies
```

### Writing Code

#### Follow Rust Best Practices

```rust
// ✅ Good: Use Result for error handling
pub async fn create_token(req: TokenRequest) -> Result<TokenResponse, OAuth2Error> {
    // Implementation
}

// ✅ Good: Use descriptive names
let access_token_expiration = config.access_token_expiration;

// ✅ Good: Document public APIs
/// Creates a new OAuth2 client registration.
///
/// # Arguments
/// * `registration` - Client registration request
///
/// # Returns
/// * `Ok(ClientCredentials)` - Successfully created client
/// * `Err(OAuth2Error)` - Registration failed
pub async fn register_client(
    registration: ClientRegistration
) -> Result<ClientCredentials, OAuth2Error> {
    // Implementation
}
```

#### Error Handling

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum OAuth2Error {
    #[error("Invalid client credentials")]
    InvalidClient,
    
    #[error("Invalid grant: {0}")]
    InvalidGrant(String),
    
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
}
```

#### Async Code

```rust
// ✅ Good: Use async/await
pub async fn fetch_user(id: &str) -> Result<User, Error> {
    let user = db.get_user(id).await?;
    Ok(user)
}

// ✅ Good: Handle concurrent operations
let (tokens, client) = tokio::join!(
    fetch_tokens(&client_id),
    fetch_client(&client_id)
);
```

### Testing

#### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_client_id() {
        let id = generate_client_id();
        assert_eq!(id.len(), 32);
    }
    
    #[tokio::test]
    async fn test_create_token() {
        let token = create_token(&mock_request()).await.unwrap();
        assert!(!token.access_token.is_empty());
    }
}
```

#### Integration Tests

```rust
// tests/integration_test.rs
use actix_web::{test, App};

#[actix_rt::test]
async fn test_token_endpoint() {
    let app = test::init_service(
        App::new().service(token_endpoint)
    ).await;
    
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "test_client"),
            ("client_secret", "test_secret"),
        ])
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}
```

### Documentation

#### Code Comments

```rust
/// Validates an OAuth2 authorization request.
///
/// This function checks:
/// - Client ID is valid and active
/// - Redirect URI matches registered URIs
/// - Requested scopes are allowed
/// - PKCE parameters are valid (if provided)
///
/// # Arguments
/// * `request` - The authorization request to validate
///
/// # Returns
/// * `Ok(())` - Request is valid
/// * `Err(OAuth2Error)` - Request validation failed
///
/// # Examples
/// ```
/// let request = AuthorizationRequest {
///     client_id: "abc123".to_string(),
///     redirect_uri: "http://localhost:3000/callback".to_string(),
///     scope: "read write".to_string(),
///     ..Default::default()
/// };
/// validate_authorization_request(&request).await?;
/// ```
pub async fn validate_authorization_request(
    request: &AuthorizationRequest
) -> Result<(), OAuth2Error> {
    // Implementation
}
```

#### README and Docs

When adding new features, update:
- `README.md` - If it affects usage
- `docs/` - Relevant documentation files
- API documentation comments

### Commit Guidelines

Follow conventional commits:

```bash
# Format: <type>(<scope>): <subject>

# Types:
# - feat: New feature
# - fix: Bug fix
# - docs: Documentation changes
# - style: Code style changes (formatting)
# - refactor: Code refactoring
# - perf: Performance improvements
# - test: Adding or updating tests
# - chore: Maintenance tasks

# Examples:
git commit -m "feat(oauth): add PKCE support for public clients"
git commit -m "fix(token): correct expiration time calculation"
git commit -m "docs(api): add examples for token introspection"
git commit -m "test(auth): add integration tests for auth flow"
```

### Pull Request Process

1. **Update your branch**
   ```bash
   git checkout main
   git pull upstream main
   git checkout your-branch
   git rebase main
   ```

2. **Run checks**
   ```bash
   cargo fmt --check
   cargo clippy -- -D warnings
   cargo test
   cargo doc --no-deps
   ```

3. **Push changes**
   ```bash
   git push origin your-branch
   ```

4. **Create Pull Request**
   - Go to GitHub and create a PR
   - Fill out the PR template
   - Link related issues
   - Request reviews

5. **PR Title Format**
   ```
   feat: Add support for custom token claims
   fix: Resolve token expiration edge case
   docs: Update deployment guide with K8s examples
   ```

6. **PR Description Template**
   ```markdown
   ## Description
   Brief description of changes
   
   ## Motivation and Context
   Why is this change needed? What problem does it solve?
   
   ## Changes Made
   - Change 1
   - Change 2
   - Change 3
   
   ## Testing
   How was this tested?
   
   ## Checklist
   - [ ] Code follows style guidelines
   - [ ] Self-review completed
   - [ ] Comments added for complex code
   - [ ] Documentation updated
   - [ ] Tests added/updated
   - [ ] All tests pass
   - [ ] No new warnings
   ```

## Types of Contributions

### Bug Reports

Create an issue with:
- Clear title
- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment details
- Relevant logs

**Template:**
```markdown
**Describe the bug**
A clear description of what the bug is.

**To Reproduce**
1. Start server with...
2. Call endpoint...
3. See error...

**Expected behavior**
What you expected to happen.

**Actual behavior**
What actually happened.

**Environment:**
- OS: [e.g., Ubuntu 22.04]
- Rust version: [e.g., 1.75]
- Server version: [e.g., 0.1.0]

**Additional context**
Any other relevant information.
```

### Feature Requests

Create an issue with:
- Clear description
- Use case
- Proposed solution
- Alternatives considered

### Documentation

- Fix typos and errors
- Improve clarity
- Add examples
- Update outdated information

### Code Contributions

- Bug fixes
- New features
- Performance improvements
- Refactoring

## Development Tools

### Recommended VS Code Extensions

```json
{
  "recommendations": [
    "rust-lang.rust-analyzer",
    "vadimcn.vscode-lldb",
    "serayuzgur.crates",
    "tamasfe.even-better-toml"
  ]
}
```

### Useful Commands

```bash
# Watch for changes and rebuild
cargo watch -x build

# Run specific test
cargo test test_name

# Generate documentation
cargo doc --open --no-deps

# Check without building
cargo check

# Bench marks
cargo bench

# Coverage (with tarpaulin)
cargo tarpaulin --out Html
```

## Architecture Decisions

When making significant changes:

1. Open an issue for discussion
2. Get consensus on approach
3. Document architecture decisions
4. Consider backward compatibility

## Performance Considerations

- Profile code for bottlenecks
- Use appropriate data structures
- Minimize allocations
- Leverage async/await effectively
- Consider database query efficiency

## Security Considerations

- Never commit secrets
- Validate all inputs
- Use parameterized queries
- Follow OWASP guidelines
- Document security implications

## Release Process

1. Version bump in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Create release tag
4. Build release binaries
5. Publish to crates.io (if applicable)
6. Create GitHub release

## Getting Help

- **Documentation**: Read the [docs](https://github.com/ianlintner/rust_oauth2/tree/main/docs)
- **Issues**: Search existing issues
- **Discussions**: Use GitHub Discussions
- **Questions**: Open a Q&A discussion

## Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Credited in release notes
- Acknowledged in project README

## License

By contributing, you agree that your contributions will be licensed under the project's MIT OR Apache-2.0 license.

---

Thank you for contributing to Rust OAuth2 Server! 🚀
