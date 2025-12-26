# Event System Examples

This directory contains example configurations for different eventing scenarios.

## Example 1: Development with Console Logging

For local development, log all events to the console:

```bash
export OAUTH2_EVENTS_ENABLED=true
export OAUTH2_EVENTS_BACKEND=console
export OAUTH2_EVENTS_FILTER_MODE=allow_all

cargo run
```

## Example 2: Production with Selective Events

For production, only log critical security events:

```bash
export OAUTH2_EVENTS_ENABLED=true
export OAUTH2_EVENTS_BACKEND=in_memory
export OAUTH2_EVENTS_FILTER_MODE=include
export OAUTH2_EVENTS_TYPES=token_revoked,client_deleted,authorization_code_expired,token_expired

cargo run --release
```

## Example 3: Audit Mode

For compliance auditing, log all events except validations:

```bash
export OAUTH2_EVENTS_ENABLED=true
export OAUTH2_EVENTS_BACKEND=both
export OAUTH2_EVENTS_FILTER_MODE=exclude
export OAUTH2_EVENTS_TYPES=token_validated,client_validated

cargo run --release
```

## Example 4: Disabled Events

For performance-critical scenarios where events aren't needed:

```bash
export OAUTH2_EVENTS_ENABLED=false

cargo run --release
```

## Testing Events Locally

To see events in action, you can use the provided scripts:

### 1. Start the server with console logging:
```bash
export OAUTH2_EVENTS_ENABLED=true
export OAUTH2_EVENTS_BACKEND=console
export OAUTH2_EVENTS_FILTER_MODE=allow_all
cargo run
```

### 2. Register a client:
```bash
curl -X POST http://localhost:8080/clients/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Test Application",
    "redirect_uris": ["http://localhost:3000/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "read write"
  }'
```

You should see a `client_registered` event logged to the console.

### 3. Get an authorization code:
```bash
# Note: Replace CLIENT_ID with the client_id from step 2
curl "http://localhost:8080/oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=http://localhost:3000/callback&scope=read"
```

You should see an `authorization_code_created` event.

### 4. Exchange code for token:
```bash
# Note: Replace CLIENT_ID, CLIENT_SECRET, and CODE with actual values
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=CODE&redirect_uri=http://localhost:3000/callback&client_id=CLIENT_ID&client_secret=CLIENT_SECRET"
```

You should see `authorization_code_validated` and `token_created` events.

## Docker Compose Example

For Docker deployments, add environment variables to your `docker-compose.yml`:

```yaml
services:
  oauth2-server:
    image: rust_oauth2_server:latest
    environment:
      - OAUTH2_EVENTS_ENABLED=true
      - OAUTH2_EVENTS_BACKEND=console
      - OAUTH2_EVENTS_FILTER_MODE=include
      - OAUTH2_EVENTS_TYPES=token_created,token_revoked,client_registered
    ports:
      - "8080:8080"
```

## Kubernetes ConfigMap Example

For Kubernetes deployments:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: oauth2-config
data:
  OAUTH2_EVENTS_ENABLED: "true"
  OAUTH2_EVENTS_BACKEND: "console"
  OAUTH2_EVENTS_FILTER_MODE: "include"
  OAUTH2_EVENTS_TYPES: "token_created,token_revoked,client_registered,client_deleted"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth2-server
spec:
  template:
    spec:
      containers:
      - name: oauth2-server
        image: rust_oauth2_server:latest
        envFrom:
        - configMapRef:
            name: oauth2-config
```

## Event Output Example

When running with `OAUTH2_EVENTS_BACKEND=console`, you'll see events like:

```json
{
  "id": "7f3a8c94-f7e2-4d15-9c7b-8e5d4a1b2c3d",
  "event_type": "token_created",
  "timestamp": "2024-01-15T14:32:45.123456Z",
  "severity": "info",
  "user_id": "user_123",
  "client_id": "client_abc123",
  "metadata": {
    "scope": "read write",
    "has_refresh_token": "true"
  },
  "error": null
}
```

## Future Plugin Examples

Once Redis/Kafka plugins are implemented, you'll be able to use them like:

### Redis Example (Future):
```bash
export OAUTH2_EVENTS_ENABLED=true
export OAUTH2_EVENTS_BACKEND=redis
export OAUTH2_EVENTS_REDIS_URL=redis://localhost:6379
export OAUTH2_EVENTS_REDIS_CHANNEL=oauth2:events
```

### Kafka Example (Future):
```bash
export OAUTH2_EVENTS_ENABLED=true
export OAUTH2_EVENTS_BACKEND=kafka
export OAUTH2_EVENTS_KAFKA_BROKERS=localhost:9092
export OAUTH2_EVENTS_KAFKA_TOPIC=oauth2-events
```
