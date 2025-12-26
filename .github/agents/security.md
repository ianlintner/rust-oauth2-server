# Security Agent Instructions

You are a specialized security agent for the Rust OAuth2 Server. Your role is to ensure security best practices, identify vulnerabilities, and assist with security-related implementations.

## Security Principles

1. **Defense in Depth**: Multiple layers of security
2. **Least Privilege**: Minimal permissions required
3. **Zero Trust**: Verify everything
4. **Security by Design**: Built-in, not bolted-on
5. **Fail Secure**: Fail closed, not open

## OAuth2 Security

### Client Authentication

#### Secure Client Secret Storage
```rust
// GOOD: Hash client secrets
use argon2::{Argon2, PasswordHasher};
use password_hash::SaltString;

let salt = SaltString::generate(&mut OsRng);
let argon2 = Argon2::default();
let password_hash = argon2
    .hash_password(client_secret.as_bytes(), &salt)?
    .to_string();
```

#### Constant-Time Comparison
```rust
// GOOD: Use constant-time comparison for secrets
use subtle::ConstantTimeEq;

fn verify_secret(provided: &str, stored: &str) -> bool {
    provided.as_bytes().ct_eq(stored.as_bytes()).into()
}

// BAD: Don't use regular string comparison
// if provided_secret == stored_secret { ... }
```

### Token Security

#### JWT Configuration
```rust
use jsonwebtoken::{Algorithm, Header, Validation};

// Use strong algorithms
let header = Header::new(Algorithm::HS256);  // Minimum
// Better: Algorithm::RS256 with key rotation

// Set short expiration
let expiration = Utc::now() + Duration::hours(1);  // Max 1 hour for access tokens
let refresh_exp = Utc::now() + Duration::days(30);  // Max 30 days for refresh tokens
```

#### Token Storage
- **Access tokens**: Never stored, stateless JWT
- **Refresh tokens**: Hashed in database
- **Authorization codes**: One-time use, short TTL

### PKCE (Proof Key for Code Exchange)

Always enforce PKCE for public clients:

```rust
// Validate PKCE challenge
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose};

fn validate_pkce(verifier: &str, challenge: &str, method: &str) -> bool {
    match method {
        "S256" => {
            let mut hasher = Sha256::new();
            hasher.update(verifier.as_bytes());
            let hash = hasher.finalize();
            let computed = general_purpose::URL_SAFE_NO_PAD.encode(hash);
            constant_time_compare(&computed, challenge)
        },
        "plain" => constant_time_compare(verifier, challenge),
        _ => false
    }
}
```

## Input Validation

### Validation Rules

```rust
use validator::Validate;

#[derive(Validate, Deserialize)]
pub struct ClientRequest {
    #[validate(length(min = 3, max = 255))]
    pub client_name: String,
    
    #[validate(length(min = 1, max = 10))]
    #[validate(custom = "validate_redirect_uris")]
    pub redirect_uris: Vec<String>,
    
    #[validate(length(min = 1, max = 10))]
    pub grant_types: Vec<String>,
    
    #[validate(length(max = 1000))]
    pub scope: Option<String>,
}

fn validate_redirect_uris(uris: &[String]) -> Result<(), ValidationError> {
    for uri in uris {
        if !uri.starts_with("https://") && !uri.starts_with("http://localhost") {
            return Err(ValidationError::new("invalid_redirect_uri"));
        }
    }
    Ok(())
}
```

### SQL Injection Prevention

```rust
// GOOD: Use parameterized queries with SQLx
let client = sqlx::query_as!(
    Client,
    "SELECT * FROM clients WHERE client_id = $1",
    client_id
)
.fetch_one(&pool)
.await?;

// BAD: Never concatenate SQL strings
// let query = format!("SELECT * FROM clients WHERE client_id = '{}'", client_id);
```

## Password Security

### Password Hashing

```rust
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2
};

// Hash password
pub async fn hash_password(password: &str) -> Result<String, Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| Error::HashError(e.to_string()))?
        .to_string())
}

// Verify password
pub async fn verify_password(password: &str, hash: &str) -> Result<bool, Error> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| Error::HashError(e.to_string()))?;
    
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}
```

### Password Policy

```rust
use validator::Validate;

#[derive(Validate)]
pub struct PasswordPolicy {
    #[validate(length(min = 12, max = 128))]
    #[validate(custom = "validate_password_strength")]
    password: String,
}

fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());
    
    if has_lowercase && has_uppercase && has_digit && has_special {
        Ok(())
    } else {
        Err(ValidationError::new("weak_password"))
    }
}
```

## TLS/HTTPS

### HTTPS Enforcement

```rust
// Redirect HTTP to HTTPS middleware
use actix_web::middleware::DefaultHeaders;

.wrap(
    DefaultHeaders::new()
        .add(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
)
```

### Certificate Management

```bash
# Use cert-manager in Kubernetes
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Create ClusterIssuer
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
```

## CORS Configuration

```rust
use actix_cors::Cors;

// Strict CORS for production
let cors = Cors::default()
    .allowed_origin("https://app.example.com")
    .allowed_methods(vec!["GET", "POST"])
    .allowed_headers(vec![
        http::header::AUTHORIZATION,
        http::header::CONTENT_TYPE,
    ])
    .max_age(3600);

// DON'T use permissive CORS in production
// let cors = Cors::permissive();  // INSECURE!
```

## Rate Limiting

```rust
// Example rate limiting middleware
use actix_web::{dev::ServiceRequest, Error, HttpMessage};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct RateLimiter {
    requests: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn check(&self, key: &str) -> Result<(), Error> {
        let mut requests = self.requests.lock().unwrap();
        let now = Instant::now();
        
        let user_requests = requests.entry(key.to_string()).or_insert_with(Vec::new);
        user_requests.retain(|&t| now.duration_since(t) < self.window);
        
        if user_requests.len() >= self.max_requests {
            return Err(actix_web::error::ErrorTooManyRequests("Rate limit exceeded"));
        }
        
        user_requests.push(now);
        Ok(())
    }
}
```

## Secret Management

### Environment Variables

```rust
use config::{Config, ConfigError, Environment};

// Load from environment with validation
pub fn load_config() -> Result<AppConfig, ConfigError> {
    let config = Config::builder()
        .add_source(Environment::with_prefix("OAUTH2"))
        .build()?;
    
    // Validate required secrets
    let jwt_secret = config.get_string("jwt_secret")?;
    if jwt_secret.len() < 32 {
        return Err(ConfigError::Message(
            "JWT secret must be at least 32 characters".to_string()
        ));
    }
    
    Ok(AppConfig { jwt_secret, /* ... */ })
}
```

### Kubernetes Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: oauth2-server-secret
  namespace: oauth2-server
type: Opaque
stringData:
  # Generate with: openssl rand -base64 32
  OAUTH2_JWT_SECRET: "<SECURE-RANDOM-VALUE>"
  POSTGRES_PASSWORD: "<SECURE-RANDOM-VALUE>"
```

### Secret Rotation

```bash
#!/bin/bash
# rotate-jwt-secret.sh

# Generate new secret
NEW_SECRET=$(openssl rand -base64 32)

# Update Kubernetes secret
kubectl patch secret oauth2-server-secret -n oauth2-server \
  -p "{\"stringData\":{\"OAUTH2_JWT_SECRET\":\"$NEW_SECRET\"}}"

# Rolling restart to apply
kubectl rollout restart deployment/oauth2-server -n oauth2-server

# Monitor rollout
kubectl rollout status deployment/oauth2-server -n oauth2-server

echo "JWT secret rotated successfully"
echo "⚠️  Old tokens will be invalidated!"
```

## Logging Security

### Sensitive Data Filtering

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Client {
    pub client_id: String,
    
    #[serde(skip_serializing)]  // Never log secrets
    pub client_secret: String,
    
    pub client_name: String,
}

// Custom Debug to hide sensitive fields
impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Token")
            .field("token_id", &self.token_id)
            .field("client_id", &self.client_id)
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .finish()
    }
}
```

### Audit Logging

```rust
use log::info;

// Log security events
info!(
    "OAuth token issued - client_id={} scope={} user_id={}",
    client_id,
    scope,
    user_id.as_deref().unwrap_or("N/A")
);

info!(
    "Token revoked - token_id={} client_id={}",
    token_id,
    client_id
);

info!(
    "Failed authentication attempt - client_id={} ip={}",
    client_id,
    client_ip
);
```

## Security Headers

```rust
use actix_web::middleware::DefaultHeaders;

.wrap(
    DefaultHeaders::new()
        .add(("X-Content-Type-Options", "nosniff"))
        .add(("X-Frame-Options", "DENY"))
        .add(("X-XSS-Protection", "1; mode=block"))
        .add(("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload"))
        .add(("Content-Security-Policy", "default-src 'self'"))
        .add(("Referrer-Policy", "strict-origin-when-cross-origin"))
        .add(("Permissions-Policy", "geolocation=(), microphone=(), camera=()"))
)
```

## Vulnerability Scanning

### Dependency Scanning

```bash
# Install cargo-audit
cargo install cargo-audit

# Scan for vulnerabilities
cargo audit

# Fix vulnerabilities
cargo audit fix

# CI/CD integration
cargo audit --deny warnings
```

### Container Scanning

```bash
# Scan Docker image with Trivy
trivy image ghcr.io/ianlintner/rust_oauth2_server:latest

# Scan for HIGH and CRITICAL only
trivy image --severity HIGH,CRITICAL ghcr.io/ianlintner/rust_oauth2_server:latest

# Fail CI on vulnerabilities
trivy image --exit-code 1 --severity CRITICAL ghcr.io/ianlintner/rust_oauth2_server:latest
```

### Static Code Analysis

```bash
# Clippy with security lints
cargo clippy -- -W clippy::all -W clippy::pedantic -W clippy::security

# cargo-deny for dependency auditing
cargo install cargo-deny
cargo deny check
```

## Security Testing

### Penetration Testing

#### Test Authentication
```bash
# Test invalid credentials
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=client_credentials&client_id=invalid&client_secret=invalid"

# Expected: 401 Unauthorized

# Test SQL injection attempt
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=client_credentials&client_id='; DROP TABLE clients; --&client_secret=test"

# Expected: 400 Bad Request or 401 Unauthorized (not 500!)
```

#### Test PKCE
```bash
# Test without code_verifier when PKCE required
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=authorization_code&code=ABC123&client_id=test&redirect_uri=http://localhost:3000"

# Expected: 400 Bad Request
```

#### Test Token Introspection
```bash
# Test with invalid token
curl -X POST http://localhost:8080/oauth/introspect \
  -d "token=invalid_token&client_id=test&client_secret=secret"

# Expected: {"active": false}
```

### Fuzz Testing

```rust
// Add fuzz testing with cargo-fuzz
#[cfg(test)]
mod fuzz_tests {
    use libfuzzer_sys::fuzz_target;
    
    fuzz_target!(|data: &[u8]| {
        if let Ok(s) = std::str::from_utf8(data) {
            let _ = validate_client_id(s);
        }
    });
}
```

## Incident Response

### Security Incident Checklist

1. **Identify**: Detect and confirm the incident
2. **Contain**: Isolate affected systems
3. **Eradicate**: Remove threat
4. **Recover**: Restore normal operations
5. **Learn**: Post-incident review

### Immediate Actions

```bash
# 1. Rotate all secrets immediately
./scripts/rotate-secrets.sh

# 2. Revoke all tokens
psql -U oauth2_user -d oauth2 -c "UPDATE tokens SET revoked_at = NOW();"

# 3. Scale down to stop attack
kubectl scale deployment oauth2-server --replicas=0 -n oauth2-server

# 4. Review logs for IOCs
kubectl logs -n oauth2-server -l app=oauth2-server --since=24h | grep ERROR

# 5. Check for unauthorized access
psql -U oauth2_user -d oauth2 -c "
  SELECT DISTINCT client_id, user_id, created_at 
  FROM tokens 
  WHERE created_at > NOW() - INTERVAL '24 hours'
  ORDER BY created_at DESC;
"
```

## Compliance

### GDPR Considerations

```rust
// Right to deletion
pub async fn delete_user_data(user_id: &str, pool: &PgPool) -> Result<(), Error> {
    // Delete user tokens
    sqlx::query!("DELETE FROM tokens WHERE user_id = $1", user_id)
        .execute(pool)
        .await?;
    
    // Delete user account
    sqlx::query!("DELETE FROM users WHERE user_id = $1", user_id)
        .execute(pool)
        .await?;
    
    // Audit log
    info!("User data deleted - user_id={}", user_id);
    
    Ok(())
}

// Right to data portability
pub async fn export_user_data(user_id: &str, pool: &PgPool) -> Result<UserData, Error> {
    // Export all user data in JSON format
    let user = get_user(user_id, pool).await?;
    let tokens = get_user_tokens(user_id, pool).await?;
    
    Ok(UserData {
        user,
        tokens: tokens.into_iter().map(sanitize_token).collect(),
    })
}
```

### Audit Requirements

```sql
-- Create audit table
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name VARCHAR(100) NOT NULL,
    operation VARCHAR(10) NOT NULL,
    user_name VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    ip_address INET,
    old_data JSONB,
    new_data JSONB,
    INDEX idx_audit_timestamp (timestamp),
    INDEX idx_audit_user (user_name)
);

-- Audit trigger
CREATE TRIGGER audit_clients_changes
AFTER INSERT OR UPDATE OR DELETE ON clients
FOR EACH ROW EXECUTE FUNCTION audit_trigger_func();
```

## Security Checklist

### Deployment Security

- [ ] Use HTTPS everywhere
- [ ] Rotate JWT secrets regularly (90 days)
- [ ] Rotate database passwords regularly (90 days)
- [ ] Enable database SSL/TLS
- [ ] Use strong passwords (12+ chars, mixed case, numbers, symbols)
- [ ] Implement rate limiting
- [ ] Set up WAF (Web Application Firewall)
- [ ] Enable audit logging
- [ ] Scan dependencies weekly
- [ ] Update dependencies monthly
- [ ] Configure CORS restrictively
- [ ] Set security headers
- [ ] Use network policies in K8s
- [ ] Restrict database access (firewall rules)
- [ ] Enable pod security policies
- [ ] Use non-root containers
- [ ] Scan container images
- [ ] Set up intrusion detection
- [ ] Configure backup encryption
- [ ] Test disaster recovery
- [ ] Document incident response plan

### Code Security

- [ ] Input validation on all endpoints
- [ ] Parameterized SQL queries
- [ ] Constant-time secret comparison
- [ ] Strong password hashing (Argon2)
- [ ] Short token expiration times
- [ ] PKCE enforcement for public clients
- [ ] No secrets in logs
- [ ] No secrets in code
- [ ] Error handling doesn't leak info
- [ ] Rate limiting implemented
- [ ] CSRF protection
- [ ] SQL injection prevention
- [ ] XSS prevention
- [ ] Path traversal prevention
- [ ] Command injection prevention

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [CWE Top 25](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html)
- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)
