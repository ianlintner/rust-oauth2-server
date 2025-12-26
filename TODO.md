# TODO List - Future Enhancements

This document tracks planned enhancements for the OAuth2 server.

## High Priority

### Testing & Quality

- [ ] **Complete BDD test scenarios**
  - Add Cucumber scenarios for all OAuth2 flows
  - Test authorization code flow with PKCE
  - Test client credentials flow
  - Test password grant flow
  - Test refresh token flow
  - Test token introspection and revocation
  - Test social login flows for each provider
  - Test error cases and edge conditions

- [ ] **Add comprehensive unit tests**
  - Actor tests (TokenActor, ClientActor, AuthActor)
  - Model validation tests
  - Handler tests with mocked dependencies
  - Service layer tests

### Security & Compliance

- [ ] **Add rate limiting middleware**
  - Per-IP rate limiting
  - Per-client rate limiting
  - Configurable limits per endpoint
  - Rate limit headers in responses
  - Redis-backed rate limiting for distributed deployments

- [ ] **Add 2FA/MFA support**
  - TOTP (Time-based One-Time Password)
  - SMS-based OTP
  - Email-based OTP
  - Recovery codes
  - Backup methods

- [ ] **WebAuthn/Passkey support**
  - Hardware security key support
  - Platform authenticator support
  - Passwordless authentication
  - Multi-device credentials

- [ ] **JWT key rotation**
  - Automatic key rotation schedule
  - Multiple active keys support
  - Key revocation
  - JWKS endpoint for public keys

## Medium Priority

### User Interface & Management

- [ ] **Implement user consent management UI**
  - Consent screen for authorization
  - List of authorized applications
  - Revoke application access
  - Scope approval/denial
  - Remember consent option

- [ ] **Admin user management UI**
  - List all users
  - Create/edit/delete users
  - Reset passwords
  - Enable/disable users
  - View user's active sessions
  - View user's authorized clients
  - User role management

- [ ] **Audit log viewer**
  - Real-time audit log stream
  - Filter by user, client, event type
  - Export audit logs
  - Retention policy configuration
  - Compliance reporting

### OAuth2 Features

- [ ] **OAuth2 device flow**
  - Device authorization grant
  - User code input UI
  - Device polling endpoint
  - Device registration

### Storage & Performance

- [ ] **Redis session store option**
  - Redis-backed sessions
  - Distributed session support
  - Session replication
  - High availability

- [ ] **Database query optimization**
  - Add missing indexes
  - Query performance monitoring
  - Connection pooling optimization
  - Read replicas support

## Low Priority

### Monitoring & Observability

- [ ] **Enhanced metrics**
  - Business metrics (MAU, DAU)
  - Token lifecycle metrics
  - Social login conversion rates
  - Error rate by endpoint

- [ ] **Alerting**
  - Integration with Alertmanager
  - Slack/PagerDuty notifications
  - Custom alert rules
  - SLA monitoring

### Advanced Features

- [ ] **Multi-tenancy support**
  - Tenant isolation
  - Per-tenant configuration
  - Tenant-specific branding
  - Tenant analytics

- [ ] **Custom scopes and claims**
  - Dynamic scope registration
  - Custom JWT claims
  - Scope inheritance
  - Conditional claims

- [ ] **Token exchange**
  - RFC 8693 implementation
  - Impersonation flows
  - Delegation scenarios

- [ ] **Pushed Authorization Requests (PAR)**
  - RFC 9126 implementation
  - Enhanced security
  - Large request support

- [ ] **JWT Secured Authorization Request (JAR)**
  - RFC 9101 implementation
  - Signed request objects
  - Encrypted request objects

### Integration & Extensibility

- [ ] **Plugin system**
  - Custom authentication plugins
  - Custom authorization plugins
  - Event hooks
  - Middleware plugins

- [ ] **LDAP/Active Directory integration**
  - LDAP authentication backend
  - Group/role mapping
  - User synchronization

- [ ] **SAML support**
  - SAML 2.0 SSO
  - Service Provider role
  - Identity Provider role

### Documentation & Developer Experience

- [ ] **Interactive API playground**
  - Try API endpoints directly
  - Example requests/responses
  - SDK code generation

- [ ] **SDK generation**
  - JavaScript/TypeScript SDK
  - Python SDK
  - Go SDK
  - Java SDK

- [ ] **Migration guides**
  - From Keycloak
  - From Auth0
  - From Okta

### Performance & Scalability

- [ ] **Caching layer**
  - Client metadata caching
  - User profile caching
  - Token validation caching
  - Cache invalidation strategies

- [ ] **Horizontal scaling support**
  - Stateless operation mode
  - Distributed locks
  - Event sourcing
  - CQRS pattern

## Completed ✅

- [x] Core OAuth2 flows (Authorization Code, Client Credentials, Password, Refresh Token)
- [x] PKCE support
- [x] JWT tokens
- [x] Token introspection and revocation
- [x] Social login (Google, Microsoft, GitHub, Azure, Okta, Auth0)
- [x] OpenAPI documentation
- [x] Admin dashboard
- [x] Prometheus metrics
- [x] Structured logging
- [x] Health checks
- [x] Flyway database migrations
- [x] Docker support
- [x] CI/CD pipeline
- [x] Modern UI with Material Tailwind

## Notes

### Priority Definitions

- **High Priority**: Security-critical or essential for production readiness
- **Medium Priority**: Improves usability and management capabilities
- **Low Priority**: Nice-to-have features for advanced use cases

### Contributing

When implementing items from this TODO list:

1. Create a feature branch
2. Add tests for new functionality
3. Update documentation
4. Submit a PR with a clear description
5. Link to the relevant TODO item

### Versioning

Track which version each feature is planned for:

- v0.2.0: BDD tests, rate limiting, user consent UI
- v0.3.0: 2FA/MFA, WebAuthn, JWT key rotation
- v0.4.0: Device flow, Redis sessions, admin user management
- v1.0.0: Production-ready with all high priority items complete
