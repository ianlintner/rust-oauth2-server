# Authentication Eventing System

The OAuth2 server now includes a comprehensive eventing system that emits events for all important authentication, authorization, and client management operations.

## Features

- **Configurable Event Filtering**: Choose which events to emit using inclusion or exclusion lists
- **Pluggable Backends**: Support for multiple event backend plugins (in-memory, console, and extensible for Redis, Kafka, etc.)
- **Actor-Based**: Built using the Actix actor model for concurrent, non-blocking event processing
- **Rich Event Metadata**: Events include timestamps, user/client IDs, severity levels, and custom metadata

## Event Types

The system emits the following event types:

### Authentication Events
- `authorization_code_created` - When an authorization code is generated
- `authorization_code_validated` - When an authorization code is successfully validated
- `authorization_code_expired` - When an expired authorization code is attempted

### Token Events
- `token_created` - When an access token (and optional refresh token) is created
- `token_validated` - When a token is successfully validated
- `token_revoked` - When a token is revoked
- `token_expired` - When an expired token is attempted

### Client Events
- `client_registered` - When a new OAuth2 client is registered
- `client_validated` - When client credentials are validated
- `client_deleted` - When a client is deleted (future implementation)

### User Events
- `user_authenticated` - When a user successfully authenticates (future implementation)
- `user_authentication_failed` - When authentication fails (future implementation)
- `user_logout` - When a user logs out (future implementation)

## Configuration

Configure the eventing system using environment variables:

### Enable/Disable Events

```bash
# Enable or disable the event system (default: true)
export OAUTH2_EVENTS_ENABLED=true
```

### Event Backend

Choose which backend plugin to use:

```bash
# Backend options: in_memory, console, both
# Default: in_memory
export OAUTH2_EVENTS_BACKEND=console
```

- **in_memory**: Stores events in memory (up to 1000 events by default)
- **console**: Logs events to stdout/tracing system
- **both**: Uses both in_memory and console backends

### Event Filtering

Control which events are emitted:

```bash
# Filter mode: allow_all, include, exclude
# Default: allow_all
export OAUTH2_EVENTS_FILTER_MODE=include

# Comma-separated list of event types (used with include or exclude mode)
export OAUTH2_EVENTS_TYPES=token_created,token_revoked,client_registered
```

#### Filter Modes

1. **allow_all**: Emit all events (default)
2. **include**: Only emit events listed in `OAUTH2_EVENTS_TYPES`
3. **exclude**: Emit all events except those listed in `OAUTH2_EVENTS_TYPES`

## Examples

### Example 1: Log All Events to Console

```bash
export OAUTH2_EVENTS_ENABLED=true
export OAUTH2_EVENTS_BACKEND=console
export OAUTH2_EVENTS_FILTER_MODE=allow_all
```

### Example 2: Only Track Token Events

```bash
export OAUTH2_EVENTS_ENABLED=true
export OAUTH2_EVENTS_BACKEND=in_memory
export OAUTH2_EVENTS_FILTER_MODE=include
export OAUTH2_EVENTS_TYPES=token_created,token_revoked,token_validated
```

### Example 3: Exclude Validation Events

```bash
export OAUTH2_EVENTS_ENABLED=true
export OAUTH2_EVENTS_BACKEND=both
export OAUTH2_EVENTS_FILTER_MODE=exclude
export OAUTH2_EVENTS_TYPES=token_validated,client_validated
```

## Event Structure

Each event contains:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "event_type": "token_created",
  "timestamp": "2024-01-15T10:30:00Z",
  "severity": "info",
  "user_id": "user_123",
  "client_id": "client_456",
  "metadata": {
    "scope": "read write",
    "grant_type": "authorization_code",
    "has_refresh_token": "true"
  },
  "error": null
}
```

## Extending with Custom Backends

You can add custom event backend plugins by implementing the `EventPlugin` trait:

```rust
use async_trait::async_trait;
use crate::events::{AuthEvent, EventPlugin};

pub struct RedisEventPlugin {
    // Redis connection details
}

#[async_trait]
impl EventPlugin for RedisEventPlugin {
    async fn emit(&self, event: &AuthEvent) -> Result<(), String> {
        // Publish event to Redis
        Ok(())
    }
    
    fn name(&self) -> &str {
        "redis"
    }
    
    async fn health_check(&self) -> bool {
        // Check Redis connection
        true
    }
}
```

Then register your plugin in `main.rs` when initializing the event system.

## Use Cases

### Audit Logging
Track all authentication and authorization events for compliance and security auditing.

### Monitoring and Alerting
Monitor failed authentication attempts, token revocations, and other security-relevant events.

### Analytics
Analyze user authentication patterns, token usage, and client activity.

### Event-Driven Architecture
Trigger downstream processes based on authentication events (e.g., send welcome emails, update user profiles, etc.).

### Integration with External Systems
Forward events to external systems like:
- **Kafka** - For event streaming and processing
- **Redis** - For real-time event caching
- **RabbitMQ** - For message queuing
- **Elasticsearch** - For search and analytics
- **Datadog/New Relic** - For monitoring and observability

## Architecture

The eventing system uses the Actix actor model:

```
┌─────────────┐
│   Actors    │
│ (Auth,      │
│  Token,     │
│  Client)    │
└──────┬──────┘
       │ EmitEvent
       ▼
┌─────────────┐
│ Event Actor │
└──────┬──────┘
       │ Parallel
       │ Distribution
       ▼
┌─────────────┬─────────────┬─────────────┐
│  In-Memory  │   Console   │   Custom    │
│   Plugin    │   Plugin    │   Plugin    │
└─────────────┴─────────────┴─────────────┘
```

Events are:
1. Created by actors when operations occur
2. Sent to the EventActor asynchronously
3. Filtered based on configuration
4. Distributed to all registered backend plugins in parallel
5. Each plugin processes the event independently

## Performance Considerations

- Events are processed asynchronously and do not block the main request handling
- Event filtering happens before plugin distribution to minimize overhead
- Failed plugin emits do not affect other plugins or the main application
- In-memory plugin has a configurable maximum size to prevent memory issues

## Future Enhancements

Planned features for future releases:

- **Redis Plugin**: Direct integration with Redis pub/sub
- **Kafka Plugin**: Native Kafka event streaming
- **RabbitMQ Plugin**: Message queue integration
- **Webhooks**: HTTP webhook callbacks for events
- **Event Replay**: Ability to replay events from in-memory store
- **Event Persistence**: Optional database storage for event history
- **Rate Limiting**: Per-plugin rate limiting for high-volume scenarios
- **Event Batching**: Batch multiple events for improved performance
