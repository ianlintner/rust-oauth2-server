Run security checks and scans.

## Security Checks

**Dependency audit**:
```bash
cargo audit
```

**Security tests**:
```bash
cargo test --test security_http
```

**Clippy security lints**:
```bash
cargo clippy --all-targets --all-features -- -W clippy::all
```

**Check for secrets in code**:
```bash
git secrets --scan
```

**Container security scan** (if image built):
```bash
trivy image ianlintner068/oauth2-server:latest
```

## Security Review Areas

- Token validation and signature verification
- Client authentication
- PKCE implementation for public clients
- SQL injection prevention (SQLx compile-time checks)
- Input validation and sanitization
- Secret management (no hardcoded secrets)
- TLS/HTTPS enforcement
- Rate limiting
- Session security

See `.github/agents/security.md` for comprehensive security guidelines.

Which security check would you like to run?
