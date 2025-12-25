# Social Login Setup Guide

This guide walks you through setting up social login providers for the OAuth2 server.

## Google OAuth2 Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Navigate to "APIs & Services" > "Credentials"
4. Click "Create Credentials" > "OAuth client ID"
5. Configure the consent screen if prompted
6. Select "Web application" as the application type
7. Add authorized redirect URIs:
   - `http://localhost:8080/auth/callback/google`
   - Add your production URL when deploying
8. Copy the Client ID and Client Secret
9. Set environment variables:
   ```bash
   export OAUTH2_GOOGLE_CLIENT_ID=your-client-id
   export OAUTH2_GOOGLE_CLIENT_SECRET=your-client-secret
   ```

## Microsoft/Azure AD Setup

1. Go to [Azure Portal](https://portal.azure.com/)
2. Navigate to "Azure Active Directory" > "App registrations"
3. Click "New registration"
4. Enter application name and select account types
5. Add redirect URI: `http://localhost:8080/auth/callback/microsoft`
6. After creation, note the "Application (client) ID"
7. Go to "Certificates & secrets" > "New client secret"
8. Copy the secret value immediately (it won't be shown again)
9. Set environment variables:
   ```bash
   export OAUTH2_MICROSOFT_CLIENT_ID=your-client-id
   export OAUTH2_MICROSOFT_CLIENT_SECRET=your-client-secret
   export OAUTH2_MICROSOFT_TENANT_ID=common  # or specific tenant ID
   ```

## GitHub OAuth Setup

1. Go to [GitHub Settings](https://github.com/settings/developers)
2. Click "OAuth Apps" > "New OAuth App"
3. Fill in application details:
   - Application name: Your OAuth2 Server
   - Homepage URL: `http://localhost:8080`
   - Authorization callback URL: `http://localhost:8080/auth/callback/github`
4. Click "Register application"
5. Generate a new client secret
6. Copy the Client ID and Client Secret
7. Set environment variables:
   ```bash
   export OAUTH2_GITHUB_CLIENT_ID=your-client-id
   export OAUTH2_GITHUB_CLIENT_SECRET=your-client-secret
   ```

## Okta Setup

1. Sign up for [Okta Developer Account](https://developer.okta.com/)
2. Go to "Applications" > "Create App Integration"
3. Select "OIDC - OpenID Connect"
4. Select "Web Application"
5. Configure settings:
   - Sign-in redirect URIs: `http://localhost:8080/auth/callback/okta`
   - Sign-out redirect URIs: `http://localhost:8080`
6. Save and note the Client ID and Client Secret
7. Note your Okta domain (e.g., `dev-12345.okta.com`)
8. Set environment variables:
   ```bash
   export OAUTH2_OKTA_CLIENT_ID=your-client-id
   export OAUTH2_OKTA_CLIENT_SECRET=your-client-secret
   export OAUTH2_OKTA_DOMAIN=dev-12345.okta.com
   ```

## Auth0 Setup

1. Sign up for [Auth0](https://auth0.com/)
2. Go to "Applications" > "Create Application"
3. Select "Regular Web Applications"
4. Go to "Settings" tab
5. Configure:
   - Allowed Callback URLs: `http://localhost:8080/auth/callback/auth0`
   - Allowed Logout URLs: `http://localhost:8080`
6. Copy the Domain, Client ID, and Client Secret
7. Set environment variables:
   ```bash
   export OAUTH2_AUTH0_CLIENT_ID=your-client-id
   export OAUTH2_AUTH0_CLIENT_SECRET=your-client-secret
   export OAUTH2_AUTH0_DOMAIN=your-tenant.auth0.com
   ```

## Testing Social Login

1. Start the OAuth2 server:
   ```bash
   cargo run
   ```

2. Navigate to the login page:
   ```
   http://localhost:8080/auth/login
   ```

3. Click on any social login button to test the integration

4. After successful authentication, you'll be redirected to the success page

## Production Considerations

### Security

- Always use HTTPS in production
- Store client secrets securely (use secret management services)
- Implement rate limiting
- Add CSRF protection (already included via session tokens)
- Validate redirect URIs strictly

### Environment Variables

Create a `.env` file for local development (DO NOT commit this file):

```bash
# Server Configuration
OAUTH2_SERVER_HOST=127.0.0.1
OAUTH2_SERVER_PORT=8080
OAUTH2_DATABASE_URL=sqlite:oauth2.db
OAUTH2_JWT_SECRET=your-super-secret-jwt-key-minimum-32-characters

# Google
OAUTH2_GOOGLE_CLIENT_ID=your-google-client-id
OAUTH2_GOOGLE_CLIENT_SECRET=your-google-client-secret

# Microsoft
OAUTH2_MICROSOFT_CLIENT_ID=your-microsoft-client-id
OAUTH2_MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret
OAUTH2_MICROSOFT_TENANT_ID=common

# GitHub
OAUTH2_GITHUB_CLIENT_ID=your-github-client-id
OAUTH2_GITHUB_CLIENT_SECRET=your-github-client-secret

# Okta
OAUTH2_OKTA_CLIENT_ID=your-okta-client-id
OAUTH2_OKTA_CLIENT_SECRET=your-okta-client-secret
OAUTH2_OKTA_DOMAIN=dev-12345.okta.com

# Auth0
OAUTH2_AUTH0_CLIENT_ID=your-auth0-client-id
OAUTH2_AUTH0_CLIENT_SECRET=your-auth0-client-secret
OAUTH2_AUTH0_DOMAIN=your-tenant.auth0.com
```

### Docker Deployment

Update the `docker-compose.yml` to include environment variables:

```yaml
oauth2_server:
  environment:
    - OAUTH2_GOOGLE_CLIENT_ID=${OAUTH2_GOOGLE_CLIENT_ID}
    - OAUTH2_GOOGLE_CLIENT_SECRET=${OAUTH2_GOOGLE_CLIENT_SECRET}
    # Add other providers as needed
```

## Troubleshooting

### Common Issues

1. **Redirect URI Mismatch**
   - Ensure the redirect URI configured in the provider matches exactly
   - Check for trailing slashes and protocol (http vs https)

2. **CSRF Token Mismatch**
   - Clear browser cookies
   - Check session middleware configuration

3. **Invalid Client Credentials**
   - Verify client ID and secret are correct
   - Check if credentials have expired or been revoked

4. **Scope Errors**
   - Ensure required scopes are requested
   - Check provider-specific scope requirements

### Debug Logging

Enable debug logging to troubleshoot issues:

```bash
export RUST_LOG=debug
cargo run
```

## Support

For issues or questions:
- Check the [documentation](https://github.com/ianlintner/rust_oauth2)
- Open an issue on GitHub
- Review provider-specific documentation
