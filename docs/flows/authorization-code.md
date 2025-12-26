# Authorization Code Flow

The Authorization Code Flow is the most secure and commonly used OAuth2 flow. It's recommended for web applications, mobile apps, and any scenario where the client can securely store credentials.

## Overview

The Authorization Code Flow is a two-step process:
1. **Authorization Step**: User grants permission, receives authorization code
2. **Token Exchange Step**: Application exchanges code for access token

This separation ensures the access token is never exposed to the user's browser, making it more secure than implicit flows.

## Flow Diagram

```mermaid
sequenceDiagram
    autonumber
    participant User as Resource Owner<br/>(User)
    participant Client as Client Application
    participant Browser as User Agent<br/>(Browser)
    participant AuthServer as Authorization Server<br/>(OAuth2 Server)
    participant ResourceServer as Resource Server<br/>(API)
    
    User->>Client: 1. Initiate Login
    Client->>Browser: 2. Redirect to authorization endpoint
    Note over Client,Browser: With client_id, redirect_uri,<br/>scope, state parameters
    
    Browser->>AuthServer: 3. GET /oauth/authorize
    AuthServer->>User: 4. Display login & consent page
    
    User->>AuthServer: 5. Authenticate & approve
    AuthServer->>AuthServer: 6. Generate authorization code
    AuthServer->>Browser: 7. Redirect to redirect_uri with code
    
    Browser->>Client: 8. Return authorization code
    Client->>AuthServer: 9. POST /oauth/token<br/>(exchange code for token)
    Note over Client,AuthServer: Client authenticates with<br/>client_id & client_secret
    
    AuthServer->>AuthServer: 10. Validate code & client
    AuthServer->>Client: 11. Return access_token & refresh_token
    
    Client->>ResourceServer: 12. API Request with access_token
    ResourceServer->>ResourceServer: 13. Validate token
    ResourceServer->>Client: 14. Return protected resource
    
    Client->>User: 15. Display protected resource
```

## Detailed Steps

### Step 1: Initiate Authorization

The client application redirects the user to the authorization endpoint.

**Request:**
```http
GET /oauth/authorize?
    response_type=code&
    client_id=YOUR_CLIENT_ID&
    redirect_uri=https://yourapp.com/callback&
    scope=read%20write&
    state=random_state_string
    HTTP/1.1
Host: oauth2-server.example.com
```

**Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `response_type` | Yes | Must be `code` for authorization code flow |
| `client_id` | Yes | The client identifier |
| `redirect_uri` | Yes | Where to redirect after authorization |
| `scope` | No | Space-separated list of requested permissions |
| `state` | Recommended | Random string for CSRF protection |

**Example cURL:**
```bash
# Build authorization URL
AUTH_URL="http://localhost:8080/oauth/authorize?\
response_type=code&\
client_id=YOUR_CLIENT_ID&\
redirect_uri=http://localhost:3000/callback&\
scope=read%20write&\
state=$(openssl rand -hex 16)"

echo "Navigate to: $AUTH_URL"
```

**Example in JavaScript:**
```javascript
function initiateOAuth() {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: 'YOUR_CLIENT_ID',
    redirect_uri: 'https://yourapp.com/callback',
    scope: 'read write',
    state: generateRandomState()
  });
  
  window.location.href = 
    `https://oauth2-server.example.com/oauth/authorize?${params}`;
}

function generateRandomState() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}
```

### Step 2: User Authentication & Consent

The authorization server presents a login page (if not authenticated) and consent screen.

**Login Page:**
```
┌─────────────────────────────────────┐
│  OAuth2 Server                      │
├─────────────────────────────────────┤
│                                     │
│  Sign in to authorize               │
│  "My Application"                   │
│                                     │
│  Username: [________________]       │
│  Password: [________________]       │
│                                     │
│  [         Sign In         ]        │
│                                     │
└─────────────────────────────────────┘
```

**Consent Screen:**
```
┌─────────────────────────────────────┐
│  OAuth2 Server                      │
├─────────────────────────────────────┤
│                                     │
│  "My Application" is requesting     │
│  access to your account:            │
│                                     │
│  ✓ Read your data                   │
│  ✓ Write to your account            │
│                                     │
│  [ Deny ]      [ Authorize ]        │
│                                     │
└─────────────────────────────────────┘
```

### Step 3: Authorization Code Response

After user approval, the authorization server redirects back to the application.

**Redirect:**
```http
HTTP/1.1 302 Found
Location: https://yourapp.com/callback?
    code=AUTH_CODE_HERE&
    state=random_state_string
```

**Success Response Parameters:**

| Parameter | Description |
|-----------|-------------|
| `code` | The authorization code (single use, short-lived) |
| `state` | The state parameter from the request (must match) |

**Error Response:**
```http
HTTP/1.1 302 Found
Location: https://yourapp.com/callback?
    error=access_denied&
    error_description=The+user+denied+the+request&
    state=random_state_string
```

**Error Codes:**

| Error | Description |
|-------|-------------|
| `invalid_request` | Missing or invalid parameters |
| `unauthorized_client` | Client not authorized for this grant type |
| `access_denied` | User denied the authorization request |
| `unsupported_response_type` | Server doesn't support this response type |
| `invalid_scope` | Requested scope is invalid |
| `server_error` | Internal server error |
| `temporarily_unavailable` | Server is temporarily unavailable |

### Step 4: Handle Callback

The application receives the authorization code and validates the state parameter.

**Node.js Example:**
```javascript
app.get('/callback', async (req, res) => {
  const { code, state, error } = req.query;
  
  // Check for errors
  if (error) {
    return res.status(400).send(`Authorization failed: ${error}`);
  }
  
  // Validate state (CSRF protection)
  const expectedState = req.session.oauthState;
  if (state !== expectedState) {
    return res.status(400).send('Invalid state parameter');
  }
  
  // Exchange code for token (next step)
  try {
    const tokens = await exchangeCodeForToken(code);
    req.session.accessToken = tokens.access_token;
    res.redirect('/dashboard');
  } catch (err) {
    res.status(500).send('Token exchange failed');
  }
});
```

**Python (Flask) Example:**
```python
@app.route('/callback')
def callback():
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')
    
    # Check for errors
    if error:
        return f'Authorization failed: {error}', 400
    
    # Validate state (CSRF protection)
    expected_state = session.get('oauth_state')
    if state != expected_state:
        return 'Invalid state parameter', 400
    
    # Exchange code for token
    try:
        tokens = exchange_code_for_token(code)
        session['access_token'] = tokens['access_token']
        return redirect('/dashboard')
    except Exception as e:
        return f'Token exchange failed: {e}', 500
```

### Step 5: Exchange Code for Access Token

The application makes a back-channel request to exchange the authorization code for an access token.

**Request:**
```http
POST /oauth/token HTTP/1.1
Host: oauth2-server.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTH_CODE_HERE&
redirect_uri=https://yourapp.com/callback&
client_id=YOUR_CLIENT_ID&
client_secret=YOUR_CLIENT_SECRET
```

**Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `grant_type` | Yes | Must be `authorization_code` |
| `code` | Yes | The authorization code from step 3 |
| `redirect_uri` | Yes | Must match the redirect_uri from step 1 |
| `client_id` | Yes | The client identifier |
| `client_secret` | Yes | The client secret |

**cURL Example:**
```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE_HERE" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET"
```

**Success Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_1a2b3c4d5e6f7g8h9i0j",
  "scope": "read write"
}
```

**Response Fields:**

| Field | Description |
|-------|-------------|
| `access_token` | JWT token for API access |
| `token_type` | Always "Bearer" |
| `expires_in` | Token lifetime in seconds |
| `refresh_token` | Token for obtaining new access tokens |
| `scope` | Granted scopes (may differ from requested) |

**Error Response:**
```json
{
  "error": "invalid_grant",
  "error_description": "The authorization code is invalid or expired"
}
```

### Step 6: Use Access Token

Use the access token to make authenticated API requests.

**Request:**
```http
GET /api/resource HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**cURL Example:**
```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     http://api.example.com/api/resource
```

**JavaScript Example:**
```javascript
async function fetchProtectedResource() {
  const response = await fetch('https://api.example.com/api/resource', {
    headers: {
      'Authorization': `Bearer ${accessToken}`
    }
  });
  
  if (!response.ok) {
    throw new Error('Failed to fetch resource');
  }
  
  return await response.json();
}
```

## Authorization Code with PKCE

Proof Key for Code Exchange (PKCE) adds an extra layer of security, especially for mobile and single-page applications.

### PKCE Flow Diagram

```mermaid
sequenceDiagram
    participant Client
    participant AuthServer
    
    Client->>Client: 1. Generate code_verifier
    Client->>Client: 2. Generate code_challenge = SHA256(code_verifier)
    
    Client->>AuthServer: 3. GET /oauth/authorize<br/>with code_challenge
    AuthServer->>Client: 4. Return authorization code
    
    Client->>AuthServer: 5. POST /oauth/token<br/>with code + code_verifier
    AuthServer->>AuthServer: 6. Verify: SHA256(code_verifier) == code_challenge
    AuthServer->>Client: 7. Return access_token
```

### Step 1: Generate Code Verifier and Challenge

**Generate Code Verifier:**
```javascript
// Generate random code verifier (43-128 characters)
function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64URLEncode(array);
}

function base64URLEncode(buffer) {
  return btoa(String.fromCharCode(...buffer))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
```

**Generate Code Challenge:**
```javascript
async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64URLEncode(new Uint8Array(hash));
}
```

**Python Example:**
```python
import hashlib
import base64
import secrets

def generate_code_verifier():
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

def generate_code_challenge(verifier):
    digest = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
```

### Step 2: Authorization Request with PKCE

```http
GET /oauth/authorize?
    response_type=code&
    client_id=YOUR_CLIENT_ID&
    redirect_uri=https://yourapp.com/callback&
    scope=read%20write&
    state=random_state&
    code_challenge=CODE_CHALLENGE_HERE&
    code_challenge_method=S256
    HTTP/1.1
Host: oauth2-server.example.com
```

**Additional PKCE Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `code_challenge` | Yes | SHA256 hash of code_verifier |
| `code_challenge_method` | Yes | `S256` (SHA256) or `plain` |

### Step 3: Token Exchange with Code Verifier

```http
POST /oauth/token HTTP/1.1
Host: oauth2-server.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTH_CODE_HERE&
redirect_uri=https://yourapp.com/callback&
client_id=YOUR_CLIENT_ID&
code_verifier=CODE_VERIFIER_HERE
```

**Note:** With PKCE, `client_secret` may not be required (depending on client type).

## Security Considerations

### 1. State Parameter (CSRF Protection)

Always use and validate the state parameter:

```javascript
// Before redirect
const state = generateRandomString();
sessionStorage.setItem('oauth_state', state);

// In callback
const returnedState = new URLSearchParams(window.location.search).get('state');
const expectedState = sessionStorage.getItem('oauth_state');

if (returnedState !== expectedState) {
  throw new Error('CSRF attack detected');
}
```

### 2. Authorization Code Lifetime

Authorization codes should:
- Be single-use only
- Expire quickly (typically 10 minutes)
- Be securely random

### 3. Redirect URI Validation

The authorization server must:
- Validate redirect_uri against registered URIs
- Use exact string matching (no wildcards)
- Prevent open redirects

### 4. Client Authentication

For confidential clients:
- Always require client_secret
- Store client_secret securely
- Use HTTPS for token exchange
- Never expose client_secret in frontend code

### 5. PKCE for Public Clients

Mobile apps and SPAs should:
- Always use PKCE
- Use S256 code challenge method
- Never use plain method in production

## Common Error Scenarios

### Error: Invalid Authorization Code

**Cause:** Code already used or expired

**Solution:**
```javascript
try {
  const tokens = await exchangeCodeForToken(code);
} catch (error) {
  if (error.error === 'invalid_grant') {
    // Restart authorization flow
    window.location.href = getAuthorizationUrl();
  }
}
```

### Error: Redirect URI Mismatch

**Cause:** redirect_uri in token request doesn't match authorization request

**Solution:**
- Ensure exact match of redirect_uri in both requests
- Check for trailing slashes
- Verify protocol (http vs https)

### Error: Invalid Client

**Cause:** Invalid client_id or client_secret

**Solution:**
- Verify credentials
- Check if client is registered
- Ensure client_secret hasn't expired

## Best Practices

1. **Always use HTTPS** in production
2. **Use PKCE** for mobile and SPA applications
3. **Validate state parameter** to prevent CSRF
4. **Store tokens securely**:
   - Backend: Secure database
   - Frontend: HttpOnly cookies (not localStorage)
5. **Implement token refresh** before expiration
6. **Handle errors gracefully** and provide user feedback
7. **Log authorization attempts** for security monitoring
8. **Rotate client secrets** periodically
9. **Limit authorization code lifetime** to 10 minutes
10. **Rate limit authorization endpoint** to prevent abuse

## Complete Implementation Example

### Frontend (React)

```javascript
import { useEffect, useState } from 'react';

function useOAuth() {
  const [tokens, setTokens] = useState(null);
  
  const initiateLogin = () => {
    const state = generateRandomString();
    const codeVerifier = generateCodeVerifier();
    
    sessionStorage.setItem('oauth_state', state);
    sessionStorage.setItem('code_verifier', codeVerifier);
    
    const codeChallenge = await generateCodeChallenge(codeVerifier);
    
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: process.env.REACT_APP_CLIENT_ID,
      redirect_uri: window.location.origin + '/callback',
      scope: 'read write',
      state: state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256'
    });
    
    window.location.href = 
      `${process.env.REACT_APP_AUTH_SERVER}/oauth/authorize?${params}`;
  };
  
  const handleCallback = async () => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');
    
    // Validate state
    const expectedState = sessionStorage.getItem('oauth_state');
    if (state !== expectedState) {
      throw new Error('Invalid state');
    }
    
    // Exchange code for token
    const codeVerifier = sessionStorage.getItem('code_verifier');
    const response = await fetch('/api/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, code_verifier })
    });
    
    const tokens = await response.json();
    setTokens(tokens);
    
    // Clean up
    sessionStorage.removeItem('oauth_state');
    sessionStorage.removeItem('code_verifier');
  };
  
  return { tokens, initiateLogin, handleCallback };
}
```

### Backend (Node.js/Express)

```javascript
const express = require('express');
const axios = require('axios');

const app = express();

app.post('/api/token', async (req, res) => {
  const { code, code_verifier } = req.body;
  
  try {
    const response = await axios.post(
      `${process.env.AUTH_SERVER}/oauth/token`,
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: process.env.REDIRECT_URI,
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        code_verifier
      }),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      }
    );
    
    res.json(response.data);
  } catch (error) {
    res.status(error.response?.status || 500).json({
      error: error.response?.data || 'Token exchange failed'
    });
  }
});
```

## Next Steps

- [Client Credentials Flow](client-credentials.md) - Service-to-service authentication
- [Refresh Token Flow](refresh-token.md) - Obtain new access tokens
- [API Authentication](../api/authentication.md) - Using access tokens
- [Security Best Practices](../deployment/production.md#security) - Secure your implementation
