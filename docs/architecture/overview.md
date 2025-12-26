# Architecture Overview

This document provides a comprehensive overview of the Rust OAuth2 Server architecture, design patterns, and implementation details.

## System Architecture

The Rust OAuth2 Server is built using modern architectural patterns that prioritize performance, security, and maintainability.

```mermaid
graph TB
    subgraph "Client Layer"
        WebApp[Web Application]
        MobileApp[Mobile App]
        Service[Backend Service]
    end
    
    subgraph "Load Balancer"
        LB[Load Balancer]
    end
    
    subgraph "OAuth2 Server Instances"
        Server1[OAuth2 Server 1]
        Server2[OAuth2 Server 2]
        Server3[OAuth2 Server 3]
    end
    
    subgraph "Middleware Layer"
        Auth[Auth Middleware]
        Metrics[Metrics Middleware]
        Tracing[Tracing Middleware]
        CORS[CORS Middleware]
    end
    
    subgraph "Handler Layer"
        OAuthHandler[OAuth Handler]
        TokenHandler[Token Handler]
        ClientHandler[Client Handler]
        AdminHandler[Admin Handler]
    end
    
    subgraph "Actor Layer"
        TokenActor[Token Actor]
        ClientActor[Client Actor]
        AuthActor[Auth Actor]
    end
    
    subgraph "Data Layer"
        DB[(PostgreSQL/SQLite)]
        Cache[Redis Cache]
    end
    
    subgraph "Observability"
        Prometheus[Prometheus]
        Jaeger[Jaeger]
        Logs[Log Aggregator]
    end
    
    WebApp --> LB
    MobileApp --> LB
    Service --> LB
    
    LB --> Server1
    LB --> Server2
    LB --> Server3
    
    Server1 --> Auth
    Server2 --> Auth
    Server3 --> Auth
    
    Auth --> Metrics
    Metrics --> Tracing
    Tracing --> CORS
    
    CORS --> OAuthHandler
    CORS --> TokenHandler
    CORS --> ClientHandler
    CORS --> AdminHandler
    
    OAuthHandler --> AuthActor
    TokenHandler --> TokenActor
    ClientHandler --> ClientActor
    AdminHandler --> ClientActor
    
    TokenActor --> DB
    ClientActor --> DB
    AuthActor --> DB
    
    TokenActor -.-> Cache
    ClientActor -.-> Cache
    
    Metrics --> Prometheus
    Tracing --> Jaeger
    Server1 --> Logs
    Server2 --> Logs
    Server3 --> Logs
    
    style WebApp fill:#e1f5ff
    style MobileApp fill:#e1f5ff
    style Service fill:#e1f5ff
    style DB fill:#f3e5f5
    style Prometheus fill:#e8f5e9
    style Jaeger fill:#fff9c4
    style Logs fill:#fff9c4
```

## Core Components

### 1. HTTP Server (Actix-Web)

The foundation of the application is built on **Actix-Web**, a powerful, pragmatic, and extremely fast web framework for Rust.

**Key Features:**
- Asynchronous request handling
- HTTP/1.x and HTTP/2 support
- WebSocket support
- Streaming and pipelining
- SSL/TLS support via OpenSSL or Rustls
- Middleware support

**Configuration:**
```rust
HttpServer::new(move || {
    App::new()
        .wrap(TracingLogger::default())
        .wrap(SessionMiddleware::new(/* ... */))
        .wrap(Cors::default())
        .wrap(MetricsMiddleware)
        // Routes configuration
})
.workers(4)
.bind("0.0.0.0:8080")?
.run()
```

### 2. Actor Model

The server uses the **Actor Model** for concurrent state management, provided by the Actix framework.

```mermaid
graph LR
    subgraph "Actor System"
        Request[HTTP Request] --> Router[Router]
        Router --> Handler[Request Handler]
        
        Handler --> TokenActor
        Handler --> ClientActor
        Handler --> AuthActor
        
        TokenActor --> Message1[Token Message]
        ClientActor --> Message2[Client Message]
        AuthActor --> Message3[Auth Message]
        
        Message1 --> DB[(Database)]
        Message2 --> DB
        Message3 --> DB
        
        DB --> Response1[Response]
        Response1 --> Handler
        Handler --> Response[HTTP Response]
    end
    
    style Request fill:#e1f5ff
    style Response fill:#e8f5e9
    style DB fill:#f3e5f5
```

**Benefits:**
- Isolation: Each actor manages its own state
- Concurrency: Actors process messages concurrently
- Fault Tolerance: Actor failures don't cascade
- Scalability: Easy to scale horizontally

See [Actor Model Documentation](actors.md) for detailed implementation.

### 3. Database Layer

The server uses **SQLx** for database interactions, providing compile-time verified SQL queries.

**Supported Databases:**
- SQLite (development/testing)
- PostgreSQL (production)

**Features:**
- Async database operations
- Connection pooling
- Compile-time query verification
- Automatic SQL migration
- Transaction support

**Schema Overview:**

```mermaid
erDiagram
    CLIENTS ||--o{ TOKENS : issues
    CLIENTS ||--o{ AUTHORIZATION_CODES : creates
    USERS ||--o{ TOKENS : owns
    USERS ||--o{ AUTHORIZATION_CODES : authorizes
    
    CLIENTS {
        uuid id PK
        string client_id UK
        string client_secret
        string client_name
        json redirect_uris
        json grant_types
        string scope
        timestamp created_at
        timestamp updated_at
    }
    
    TOKENS {
        uuid id PK
        string token_value UK
        string token_type
        uuid client_id FK
        uuid user_id FK
        string scope
        timestamp expires_at
        timestamp created_at
        boolean revoked
    }
    
    AUTHORIZATION_CODES {
        uuid id PK
        string code UK
        uuid client_id FK
        uuid user_id FK
        string redirect_uri
        string scope
        string code_challenge
        string code_challenge_method
        timestamp expires_at
        timestamp created_at
        boolean used
    }
    
    USERS {
        uuid id PK
        string email UK
        string username
        string password_hash
        string provider
        string provider_user_id
        json metadata
        timestamp created_at
        timestamp updated_at
    }
```

See [Database Documentation](database.md) for schema details and migrations.

## Request Flow

### Complete Request Flow Diagram

```mermaid
sequenceDiagram
    participant Client
    participant LB as Load Balancer
    participant Server as OAuth2 Server
    participant MW as Middleware Stack
    participant Handler as Request Handler
    participant Actor as Actor System
    participant DB as Database
    participant Telemetry as Observability
    
    Client->>LB: HTTP Request
    LB->>Server: Forward Request
    
    Server->>MW: Process Request
    activate MW
    
    MW->>MW: CORS Check
    MW->>MW: Auth Check
    MW->>MW: Start Trace Span
    MW->>Telemetry: Record Metrics
    
    MW->>Handler: Validated Request
    deactivate MW
    activate Handler
    
    Handler->>Actor: Send Message
    activate Actor
    
    Actor->>DB: Query/Update
    activate DB
    DB-->>Actor: Result
    deactivate DB
    
    Actor-->>Handler: Response
    deactivate Actor
    
    Handler->>MW: HTTP Response
    deactivate Handler
    activate MW
    
    MW->>Telemetry: Record Duration
    MW->>Telemetry: End Trace Span
    MW->>Server: Final Response
    deactivate MW
    
    Server->>LB: HTTP Response
    LB->>Client: Forward Response
```

### OAuth2 Authorization Flow

```mermaid
sequenceDiagram
    participant User
    participant Client as Client App
    participant Browser
    participant OAuth2 as OAuth2 Server
    participant AuthActor as Auth Actor
    participant TokenActor as Token Actor
    participant DB as Database
    
    User->>Client: Initiate Login
    Client->>Browser: Redirect to /oauth/authorize
    Browser->>OAuth2: GET /oauth/authorize
    
    OAuth2->>AuthActor: ValidateAuthRequest
    AuthActor->>DB: Check Client
    DB-->>AuthActor: Client Valid
    
    AuthActor-->>OAuth2: Request Valid
    OAuth2->>User: Show Login/Consent
    
    User->>OAuth2: Approve
    OAuth2->>AuthActor: CreateAuthCode
    AuthActor->>DB: Store Auth Code
    DB-->>AuthActor: Code Stored
    
    AuthActor-->>OAuth2: Authorization Code
    OAuth2->>Browser: Redirect with Code
    Browser->>Client: Return Code
    
    Client->>OAuth2: POST /oauth/token
    OAuth2->>TokenActor: ExchangeCodeForToken
    TokenActor->>DB: Validate & Consume Code
    TokenActor->>DB: Create Token
    DB-->>TokenActor: Token Created
    
    TokenActor-->>OAuth2: Access Token
    OAuth2->>Client: Return Token
    Client->>User: Authentication Complete
```

## Component Details

### Middleware Stack

The middleware stack processes all requests in order:

1. **TracingLogger**: Records request/response with spans
2. **SessionMiddleware**: Manages user sessions
3. **CorsMiddleware**: Handles CORS policies
4. **MetricsMiddleware**: Records metrics
5. **AuthMiddleware**: Validates authentication (selective routes)

```rust
App::new()
    .wrap(TracingLogger::default())           // 1. Tracing
    .wrap(SessionMiddleware::new(/*...*/))    // 2. Sessions
    .wrap(Cors::default())                    // 3. CORS
    .wrap(MetricsMiddleware)                  // 4. Metrics
    .service(
        web::scope("/api")
            .wrap(AuthMiddleware)             // 5. Auth (API only)
            .route("/protected", web::get().to(handler))
    )
```

### Handler Layer

Handlers process HTTP requests and coordinate with actors:

**Handler Responsibilities:**
- Request validation
- Parameter extraction
- Actor coordination
- Response formatting
- Error handling

**Example Handler Flow:**
```rust
async fn token_handler(
    req: TokenRequest,
    token_actor: Data<Addr<TokenActor>>,
) -> Result<HttpResponse, OAuth2Error> {
    // 1. Validate request
    req.validate()?;
    
    // 2. Send message to actor
    let result = token_actor
        .send(CreateTokenMessage { /* ... */ })
        .await??;
    
    // 3. Format response
    Ok(HttpResponse::Ok().json(result))
}
```

### JWT Token Structure

The server issues JWT tokens with the following structure:

```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "user-id",
    "client_id": "client-id",
    "scope": "read write",
    "iss": "rust_oauth2_server",
    "aud": "api.example.com",
    "exp": 1704067200,
    "iat": 1704063600,
    "jti": "token-id"
  }
}
```

**Token Claims:**
- `sub`: Subject (user ID)
- `client_id`: OAuth2 client identifier
- `scope`: Granted scopes
- `iss`: Issuer
- `aud`: Audience
- `exp`: Expiration time
- `iat`: Issued at time
- `jti`: JWT ID (token identifier)

## Security Architecture

### Defense in Depth

```mermaid
graph TD
    subgraph "Layer 1: Network"
        TLS[TLS/HTTPS]
        FW[Firewall]
        DDoS[DDoS Protection]
    end
    
    subgraph "Layer 2: Application"
        CORS[CORS Policy]
        CSRF[CSRF Protection]
        RateLimit[Rate Limiting]
    end
    
    subgraph "Layer 3: Authentication"
        OAuth2Flow[OAuth2 Flows]
        PKCE[PKCE]
        Social[Social Login]
    end
    
    subgraph "Layer 4: Authorization"
        Scopes[Scope-Based Access]
        JWT[JWT Validation]
        TokenIntrospection[Token Introspection]
    end
    
    subgraph "Layer 5: Data"
        Encryption[Data Encryption]
        SecretMgmt[Secret Management]
        Hashing[Password Hashing]
    end
    
    TLS --> CORS
    FW --> CORS
    DDoS --> CORS
    
    CORS --> OAuth2Flow
    CSRF --> OAuth2Flow
    RateLimit --> OAuth2Flow
    
    OAuth2Flow --> Scopes
    PKCE --> Scopes
    Social --> Scopes
    
    Scopes --> Encryption
    JWT --> Encryption
    TokenIntrospection --> Encryption
    
    style TLS fill:#f44336,color:#fff
    style CORS fill:#ff9800,color:#fff
    style OAuth2Flow fill:#ffc107
    style Scopes fill:#8bc34a
    style Encryption fill:#4caf50,color:#fff
```

### Security Features

1. **PKCE Support**: Protects against authorization code interception
2. **Secure Token Storage**: Tokens hashed in database
3. **Scope-Based Authorization**: Fine-grained access control
4. **Token Revocation**: Immediate token invalidation
5. **Session Security**: Secure, HTTP-only cookies
6. **Password Hashing**: Argon2 for password storage
7. **SQL Injection Prevention**: Parameterized queries via SQLx
8. **XSS Prevention**: Input sanitization and CSP headers
9. **CSRF Protection**: State parameter validation

## Performance Characteristics

### Concurrency Model

```mermaid
graph LR
    subgraph "HTTP Server"
        W1[Worker 1]
        W2[Worker 2]
        W3[Worker 3]
        W4[Worker 4]
    end
    
    subgraph "Actor System"
        TA1[Token Actor 1]
        TA2[Token Actor 2]
        CA1[Client Actor 1]
        CA2[Client Actor 2]
    end
    
    subgraph "Database Pool"
        Conn1[Connection 1]
        Conn2[Connection 2]
        Conn3[Connection 3]
        ConnN[Connection N]
    end
    
    W1 --> TA1
    W2 --> TA2
    W3 --> CA1
    W4 --> CA2
    
    TA1 --> Conn1
    TA2 --> Conn2
    CA1 --> Conn3
    CA2 --> ConnN
```

**Performance Benefits:**
- **Async I/O**: Non-blocking operations
- **Worker Threads**: CPU core utilization
- **Connection Pooling**: Database efficiency
- **Actor Isolation**: No lock contention
- **Zero-Copy**: Efficient data handling

### Scalability

**Horizontal Scaling:**
- Stateless server design
- Session stored in database/Redis
- Load balancer compatible
- No inter-server communication required

**Vertical Scaling:**
- Multi-threaded workers
- Efficient memory usage
- Fast request processing
- Database connection pooling

## Technology Stack

### Core Technologies

| Component | Technology | Purpose |
|-----------|------------|---------|
| Language | Rust 2021 | Type safety, performance |
| Web Framework | Actix-Web 4.x | HTTP server |
| Actor Framework | Actix 0.13 | Concurrency |
| Database | SQLx | Database access |
| JWT | jsonwebtoken | Token handling |
| Serialization | Serde | JSON processing |
| OpenAPI | utoipa | API documentation |

### Observability Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Metrics | Prometheus | Metrics collection |
| Tracing | OpenTelemetry | Distributed tracing |
| Logging | tracing-subscriber | Structured logging |
| Monitoring | Grafana | Metrics visualization |

### Infrastructure

| Component | Technology | Purpose |
|-----------|------------|---------|
| Container | Docker | Containerization |
| Orchestration | Kubernetes | Container orchestration |
| Database | PostgreSQL | Production database |
| Migrations | Flyway | Schema management |
| Reverse Proxy | Nginx/Traefik | Load balancing, TLS |

## Design Principles

### 1. Type Safety

Rust's type system prevents entire classes of bugs:
- No null pointer exceptions
- No data races
- Memory safety without garbage collection
- Compile-time error detection

### 2. Actor Model

Benefits of actor-based concurrency:
- Isolated state management
- Message-passing communication
- Fault tolerance
- Scalable design

### 3. Asynchronous I/O

Non-blocking operations for efficiency:
- Efficient resource utilization
- High concurrency support
- Responsive under load
- Scalable architecture

### 4. Security First

Security built into every layer:
- Secure by default configuration
- Principle of least privilege
- Defense in depth
- Regular security audits

### 5. Observability

Comprehensive monitoring and debugging:
- Structured logging
- Distributed tracing
- Prometheus metrics
- Health checks

## Configuration Architecture

Configuration is loaded in this order:
1. Default values (code)
2. Configuration file
3. Environment variables (override)

```mermaid
graph LR
    Defaults[Default Values] --> ConfigFile[Config File]
    ConfigFile --> EnvVars[Environment Variables]
    EnvVars --> FinalConfig[Final Configuration]
    
    FinalConfig --> Validation{Validation}
    Validation -->|Pass| Server[Start Server]
    Validation -->|Fail| Error[Configuration Error]
    
    style Defaults fill:#e3f2fd
    style EnvVars fill:#fff3e0
    style Server fill:#e8f5e9
    style Error fill:#ffebee
```

## Deployment Architecture

### Single Instance Deployment

```mermaid
graph TB
    Internet[Internet] --> ReverseProxy[Nginx/Traefik]
    ReverseProxy --> OAuth2[OAuth2 Server]
    OAuth2 --> DB[(PostgreSQL)]
    OAuth2 --> OTLP[OTLP Collector]
    OTLP --> Jaeger[Jaeger]
    OTLP --> Prometheus[Prometheus]
    
    style Internet fill:#e1f5ff
    style OAuth2 fill:#fff3e0
    style DB fill:#f3e5f5
```

### High Availability Deployment

```mermaid
graph TB
    Internet[Internet] --> LB[Load Balancer]
    
    LB --> OAuth2_1[OAuth2 Server 1]
    LB --> OAuth2_2[OAuth2 Server 2]
    LB --> OAuth2_3[OAuth2 Server 3]
    
    OAuth2_1 --> DB_Primary[(PostgreSQL Primary)]
    OAuth2_2 --> DB_Primary
    OAuth2_3 --> DB_Primary
    
    DB_Primary --> DB_Replica1[(PostgreSQL Replica 1)]
    DB_Primary --> DB_Replica2[(PostgreSQL Replica 2)]
    
    OAuth2_1 --> Redis[(Redis Cache)]
    OAuth2_2 --> Redis
    OAuth2_3 --> Redis
    
    style Internet fill:#e1f5ff
    style LB fill:#fff3e0
    style DB_Primary fill:#c8e6c9
    style DB_Replica1 fill:#f3e5f5
    style DB_Replica2 fill:#f3e5f5
```

## Extension Points

The architecture supports extensions through:

1. **Custom Grant Types**: Add new OAuth2 flows
2. **Token Enhancers**: Add custom token claims
3. **Event Hooks**: React to OAuth2 events
4. **Custom Middleware**: Add request/response processing
5. **Storage Backends**: Implement alternative storage
6. **Social Providers**: Add new login providers

## Next Steps

- [Actor Model Details](actors.md) - Deep dive into the actor system
- [Database Schema](database.md) - Complete schema documentation
- [API Reference](../api/endpoints.md) - Endpoint documentation
- [Deployment Guide](../deployment/production.md) - Production deployment
