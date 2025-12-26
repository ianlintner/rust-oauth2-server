# Client Credentials Flow

The Client Credentials Flow is designed for machine-to-machine (M2M) authentication where applications authenticate directly with the authorization server without user involvement. This is ideal for microservices, backend services, CLIs, and daemons.

## Overview

Unlike flows that involve user authorization, the Client Credentials Flow:
- **No user interaction**: Server-to-server authentication only
- **Client acts as resource owner**: The client is granted access on its own behalf
- **Simple and fast**: Single request to obtain access token
- **Ideal for backend services**: APIs calling other APIs

## Flow Diagram

```mermaid
sequenceDiagram
    autonumber
    participant Client as Client Application<br/>(Service/CLI/Daemon)
    participant AuthServer as Authorization Server<br/>(OAuth2 Server)
    participant ResourceServer as Resource Server<br/>(API)
    
    Client->>AuthServer: 1. POST /oauth/token<br/>(client_credentials grant)
    Note over Client,AuthServer: Authenticate with<br/>client_id & client_secret
    
    AuthServer->>AuthServer: 2. Validate client credentials
    AuthServer->>AuthServer: 3. Check client permissions
    AuthServer->>AuthServer: 4. Generate access token
    
    AuthServer->>Client: 5. Return access_token
    Note over AuthServer,Client: No refresh token<br/>(not needed for M2M)
    
    Client->>ResourceServer: 6. API Request with access_token
    ResourceServer->>ResourceServer: 7. Validate token
    ResourceServer->>Client: 8. Return protected resource
```

## Use Cases

### 1. Microservices Communication

```mermaid
graph LR
    ServiceA[Service A] -->|Request Token| OAuth2[OAuth2 Server]
    OAuth2 -->|Access Token| ServiceA
    ServiceA -->|API Call + Token| ServiceB[Service B]
    ServiceB -->|Validate Token| OAuth2
    ServiceB -->|Response| ServiceA
    
    style ServiceA fill:#4caf50,color:#fff
    style ServiceB fill:#2196f3,color:#fff
    style OAuth2 fill:#ff9800,color:#fff
```

### 2. CLI Tools

```bash
# CLI tool authenticates and calls API
$ my-cli login
Authenticating...
✓ Authenticated successfully

$ my-cli list-resources
Fetching resources...
- Resource 1
- Resource 2
- Resource 3
```

### 3. Batch Jobs / Cron Jobs

```python
# Scheduled job that processes data
def nightly_batch_job():
    # Authenticate
    token = get_client_credentials_token()
    
    # Fetch data
    data = fetch_data_with_token(token)
    
    # Process data
    process_data(data)
```

### 4. Backend Services

```javascript
// Node.js service accessing another API
class APIClient {
  async authenticate() {
    this.token = await getClientCredentialsToken();
  }
  
  async callAPI() {
    const response = await fetch(apiUrl, {
      headers: { 'Authorization': `Bearer ${this.token}` }
    });
    return response.json();
  }
}
```

## Implementation

### Step 1: Request Access Token

**HTTP Request:**
```http
POST /oauth/token HTTP/1.1
Host: oauth2-server.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&
client_id=YOUR_CLIENT_ID&
client_secret=YOUR_CLIENT_SECRET&
scope=read write
```

**Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `grant_type` | Yes | Must be `client_credentials` |
| `client_id` | Yes | The client identifier |
| `client_secret` | Yes | The client secret |
| `scope` | No | Space-separated list of requested scopes |

### Step 2: Receive Access Token

**Success Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

**Response Fields:**

| Field | Description |
|-------|-------------|
| `access_token` | JWT token for API access |
| `token_type` | Always "Bearer" |
| `expires_in` | Token lifetime in seconds |
| `scope` | Granted scopes |

**Note:** No `refresh_token` is returned because the client can request a new access token at any time using its credentials.

**Error Response:**
```json
{
  "error": "invalid_client",
  "error_description": "Client authentication failed"
}
```

## Code Examples

### cURL

```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "scope=read write"
```

### JavaScript/Node.js

```javascript
const axios = require('axios');

async function getClientCredentialsToken() {
  const params = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: process.env.CLIENT_ID,
    client_secret: process.env.CLIENT_SECRET,
    scope: 'read write'
  });
  
  try {
    const response = await axios.post(
      'http://localhost:8080/oauth/token',
      params,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    
    return response.data;
  } catch (error) {
    console.error('Token request failed:', error.response?.data);
    throw error;
  }
}

// Usage
(async () => {
  const tokens = await getClientCredentialsToken();
  console.log('Access Token:', tokens.access_token);
  console.log('Expires in:', tokens.expires_in, 'seconds');
})();
```

### Python

```python
import requests
import os

def get_client_credentials_token():
    url = 'http://localhost:8080/oauth/token'
    
    data = {
        'grant_type': 'client_credentials',
        'client_id': os.environ['CLIENT_ID'],
        'client_secret': os.environ['CLIENT_SECRET'],
        'scope': 'read write'
    }
    
    response = requests.post(url, data=data)
    response.raise_for_status()
    
    return response.json()

# Usage
if __name__ == '__main__':
    tokens = get_client_credentials_token()
    print(f"Access Token: {tokens['access_token']}")
    print(f"Expires in: {tokens['expires_in']} seconds")
```

### Go

```go
package main

import (
    "encoding/json"
    "fmt"
    "net/http"
    "net/url"
    "os"
    "strings"
)

type TokenResponse struct {
    AccessToken string `json:"access_token"`
    TokenType   string `json:"token_type"`
    ExpiresIn   int    `json:"expires_in"`
    Scope       string `json:"scope"`
}

func getClientCredentialsToken() (*TokenResponse, error) {
    data := url.Values{}
    data.Set("grant_type", "client_credentials")
    data.Set("client_id", os.Getenv("CLIENT_ID"))
    data.Set("client_secret", os.Getenv("CLIENT_SECRET"))
    data.Set("scope", "read write")
    
    resp, err := http.Post(
        "http://localhost:8080/oauth/token",
        "application/x-www-form-urlencoded",
        strings.NewReader(data.Encode()),
    )
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("token request failed: %s", resp.Status)
    }
    
    var tokens TokenResponse
    if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
        return nil, err
    }
    
    return &tokens, nil
}

func main() {
    tokens, err := getClientCredentialsToken()
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    
    fmt.Printf("Access Token: %s\n", tokens.AccessToken)
    fmt.Printf("Expires in: %d seconds\n", tokens.ExpiresIn)
}
```

### Rust

```rust
use reqwest;
use serde::{Deserialize, Serialize};
use std::env;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    scope: String,
}

async fn get_client_credentials_token() -> Result<TokenResponse, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    
    let mut params = HashMap::new();
    params.insert("grant_type", "client_credentials");
    params.insert("client_id", &env::var("CLIENT_ID")?);
    params.insert("client_secret", &env::var("CLIENT_SECRET")?);
    params.insert("scope", "read write");
    
    let response = client
        .post("http://localhost:8080/oauth/token")
        .form(&params)
        .send()
        .await?;
    
    if !response.status().is_success() {
        return Err(format!("Token request failed: {}", response.status()).into());
    }
    
    let tokens: TokenResponse = response.json().await?;
    Ok(tokens)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tokens = get_client_credentials_token().await?;
    
    println!("Access Token: {}", tokens.access_token);
    println!("Expires in: {} seconds", tokens.expires_in);
    
    Ok(())
}
```

## Using the Access Token

Once you have an access token, use it to authenticate API requests:

### HTTP Request

```http
GET /api/resource HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### JavaScript

```javascript
async function callProtectedAPI(accessToken) {
  const response = await fetch('https://api.example.com/api/resource', {
    headers: {
      'Authorization': `Bearer ${accessToken}`
    }
  });
  
  if (!response.ok) {
    throw new Error(`API request failed: ${response.status}`);
  }
  
  return await response.json();
}
```

### Python

```python
def call_protected_api(access_token):
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    
    response = requests.get(
        'https://api.example.com/api/resource',
        headers=headers
    )
    response.raise_for_status()
    
    return response.json()
```

## Token Management

### Token Caching

Cache tokens to reduce authorization server load:

```javascript
class TokenCache {
  constructor() {
    this.token = null;
    this.expiresAt = null;
  }
  
  async getToken() {
    // Check if cached token is still valid
    if (this.token && this.expiresAt > Date.now()) {
      return this.token;
    }
    
    // Request new token
    const response = await getClientCredentialsToken();
    
    // Cache with buffer (expire 5 minutes early)
    this.token = response.access_token;
    this.expiresAt = Date.now() + ((response.expires_in - 300) * 1000);
    
    return this.token;
  }
  
  invalidate() {
    this.token = null;
    this.expiresAt = null;
  }
}

// Usage
const tokenCache = new TokenCache();

async function makeAPICall() {
  const token = await tokenCache.getToken();
  return callProtectedAPI(token);
}
```

### Automatic Token Refresh

Implement automatic token refresh before expiration:

```python
import time
import threading
from datetime import datetime, timedelta

class TokenManager:
    def __init__(self):
        self.token = None
        self.expires_at = None
        self.lock = threading.Lock()
        
    def get_token(self):
        with self.lock:
            # Check if token needs refresh (5 min buffer)
            if not self.token or datetime.now() >= self.expires_at - timedelta(minutes=5):
                self._refresh_token()
            
            return self.token
    
    def _refresh_token(self):
        response = get_client_credentials_token()
        self.token = response['access_token']
        self.expires_at = datetime.now() + timedelta(seconds=response['expires_in'])

# Usage
token_manager = TokenManager()

def make_api_call():
    token = token_manager.get_token()
    return call_protected_api(token)
```

## Advanced Patterns

### Retry Logic with Token Refresh

Handle token expiration gracefully:

```javascript
async function apiCallWithRetry(url, maxRetries = 1) {
  let retries = 0;
  
  while (retries <= maxRetries) {
    try {
      const token = await tokenCache.getToken();
      const response = await fetch(url, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (response.status === 401 && retries < maxRetries) {
        // Token might be expired, invalidate cache and retry
        tokenCache.invalidate();
        retries++;
        continue;
      }
      
      if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
      }
      
      return await response.json();
      
    } catch (error) {
      if (retries >= maxRetries) {
        throw error;
      }
      retries++;
    }
  }
}
```

### Parallel Requests

Reuse the same token for parallel requests:

```python
import asyncio
import aiohttp

async def make_parallel_requests(urls, token):
    async with aiohttp.ClientSession() as session:
        tasks = []
        for url in urls:
            headers = {'Authorization': f'Bearer {token}'}
            tasks.append(session.get(url, headers=headers))
        
        responses = await asyncio.gather(*tasks)
        return [await r.json() for r in responses]

# Usage
async def main():
    token = get_client_credentials_token()['access_token']
    urls = [
        'https://api.example.com/resource1',
        'https://api.example.com/resource2',
        'https://api.example.com/resource3'
    ]
    results = await make_parallel_requests(urls, token)
```

## Security Considerations

### 1. Protect Client Credentials

```bash
# ✅ Good: Use environment variables
export CLIENT_ID="my_client_id"
export CLIENT_SECRET="super_secret_value"

# ✅ Good: Use secret management
# AWS Secrets Manager
aws secretsmanager get-secret-value --secret-id oauth2/client-credentials

# HashiCorp Vault
vault kv get secret/oauth2/client-credentials

# ❌ Bad: Hard-coded in source code
const CLIENT_SECRET = "super_secret_value"; // DON'T DO THIS!
```

### 2. Limit Scope

Request only necessary permissions:

```javascript
// ✅ Good: Minimal scopes
const params = {
  grant_type: 'client_credentials',
  client_id: CLIENT_ID,
  client_secret: CLIENT_SECRET,
  scope: 'read:resources'  // Only what's needed
};

// ❌ Bad: Excessive scopes
const params = {
  grant_type: 'client_credentials',
  client_id: CLIENT_ID,
  client_secret: CLIENT_SECRET,
  scope: 'read write delete admin'  // Too broad!
};
```

### 3. Secure Transport

Always use HTTPS in production:

```javascript
// ✅ Good: HTTPS
const TOKEN_URL = 'https://oauth2-server.example.com/oauth/token';

// ❌ Bad: HTTP (only for local development)
const TOKEN_URL = 'http://oauth2-server.example.com/oauth/token';
```

### 4. Token Storage

Store tokens securely:

```javascript
// ✅ Good: In-memory or secure storage
class SecureTokenStorage {
  #token = null;  // Private field
  
  setToken(token) {
    this.#token = token;
  }
  
  getToken() {
    return this.#token;
  }
}

// ❌ Bad: Logging tokens
console.log('Token:', accessToken);  // DON'T DO THIS!
logger.info('Token received:', { token: accessToken });  // DON'T DO THIS!
```

### 5. Rotate Credentials

Regularly rotate client credentials:

```bash
# Schedule credential rotation
# 1. Create new client credentials
# 2. Update applications with new credentials
# 3. Verify applications work with new credentials
# 4. Revoke old credentials
```

## Error Handling

### Common Errors

| Error Code | Description | Resolution |
|------------|-------------|------------|
| `invalid_client` | Invalid client_id or client_secret | Verify credentials |
| `invalid_scope` | Requested scope not allowed | Request valid scopes |
| `unauthorized_client` | Client not authorized for this grant | Check client grant types |
| `server_error` | Internal server error | Retry with exponential backoff |

### Comprehensive Error Handling

```javascript
async function getTokenWithErrorHandling() {
  try {
    const response = await axios.post(tokenUrl, params);
    return response.data;
    
  } catch (error) {
    if (error.response) {
      const { error: code, error_description } = error.response.data;
      
      switch (code) {
        case 'invalid_client':
          throw new Error('Invalid client credentials. Check CLIENT_ID and CLIENT_SECRET.');
          
        case 'invalid_scope':
          throw new Error(`Invalid scope requested: ${error_description}`);
          
        case 'unauthorized_client':
          throw new Error('Client not authorized for client_credentials grant type.');
          
        case 'server_error':
          // Retry with exponential backoff
          return await retryWithBackoff(() => getTokenWithErrorHandling());
          
        default:
          throw new Error(`OAuth2 error: ${code} - ${error_description}`);
      }
    } else {
      throw new Error(`Network error: ${error.message}`);
    }
  }
}
```

## Monitoring and Logging

### Log Token Requests (Safely)

```javascript
// ✅ Good: Log without sensitive data
logger.info('Requesting client credentials token', {
  client_id: CLIENT_ID,
  scope: requestedScope,
  timestamp: new Date().toISOString()
});

// ❌ Bad: Logging secrets
logger.info('Token request', {
  client_id: CLIENT_ID,
  client_secret: CLIENT_SECRET,  // NEVER LOG THIS!
  response: tokenResponse         // DON'T LOG TOKENS!
});
```

### Monitor Token Usage

```javascript
const tokenMetrics = {
  requestCount: 0,
  successCount: 0,
  errorCount: 0,
  avgResponseTime: 0
};

async function getTokenWithMetrics() {
  const startTime = Date.now();
  tokenMetrics.requestCount++;
  
  try {
    const token = await getClientCredentialsToken();
    tokenMetrics.successCount++;
    return token;
  } catch (error) {
    tokenMetrics.errorCount++;
    throw error;
  } finally {
    const duration = Date.now() - startTime;
    tokenMetrics.avgResponseTime = 
      (tokenMetrics.avgResponseTime + duration) / 2;
  }
}
```

## Best Practices

1. **Cache tokens** until near expiration
2. **Use HTTPS** in production
3. **Protect credentials** with secret management
4. **Request minimal scopes** needed
5. **Implement retry logic** with exponential backoff
6. **Log safely** without exposing secrets
7. **Monitor usage** and performance
8. **Rotate credentials** regularly
9. **Handle errors** gracefully
10. **Set reasonable timeouts** for requests

## Complete Example: Microservice

```javascript
const axios = require('axios');

class OAuth2Client {
  constructor(config) {
    this.config = config;
    this.token = null;
    this.expiresAt = null;
  }
  
  async getToken() {
    // Return cached token if still valid
    if (this.token && this.expiresAt > Date.now() + 300000) {
      return this.token;
    }
    
    // Request new token
    const params = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      scope: this.config.scope
    });
    
    const response = await axios.post(
      this.config.tokenUrl,
      params,
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    
    this.token = response.data.access_token;
    this.expiresAt = Date.now() + (response.data.expires_in * 1000);
    
    return this.token;
  }
  
  async makeAuthenticatedRequest(url, options = {}) {
    const token = await this.getToken();
    
    return axios({
      ...options,
      url,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${token}`
      }
    });
  }
}

// Usage
const client = new OAuth2Client({
  tokenUrl: 'http://localhost:8080/oauth/token',
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  scope: 'read write'
});

// Make authenticated requests
async function fetchData() {
  const response = await client.makeAuthenticatedRequest(
    'https://api.example.com/data'
  );
  return response.data;
}
```

## Next Steps

- [Authorization Code Flow](authorization-code.md) - User-based authentication
- [Refresh Token Flow](refresh-token.md) - Refreshing access tokens
- [Password Flow](password.md) - Resource Owner Password Credentials
- [API Authentication](../api/authentication.md) - Using tokens with APIs
