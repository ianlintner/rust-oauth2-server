use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Types of events that can be emitted
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    // Authentication events
    AuthorizationCodeCreated,
    AuthorizationCodeValidated,
    AuthorizationCodeExpired,

    // Token events
    TokenCreated,
    TokenValidated,
    TokenRevoked,
    TokenExpired,

    // Client events
    ClientRegistered,
    ClientValidated,
    ClientDeleted,

    // User events
    UserAuthenticated,
    UserAuthenticationFailed,
    UserLogout,
}

impl EventType {
    /// Get the string representation of the event type
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::AuthorizationCodeCreated => "authorization_code_created",
            EventType::AuthorizationCodeValidated => "authorization_code_validated",
            EventType::AuthorizationCodeExpired => "authorization_code_expired",
            EventType::TokenCreated => "token_created",
            EventType::TokenValidated => "token_validated",
            EventType::TokenRevoked => "token_revoked",
            EventType::TokenExpired => "token_expired",
            EventType::ClientRegistered => "client_registered",
            EventType::ClientValidated => "client_validated",
            EventType::ClientDeleted => "client_deleted",
            EventType::UserAuthenticated => "user_authenticated",
            EventType::UserAuthenticationFailed => "user_authentication_failed",
            EventType::UserLogout => "user_logout",
        }
    }
}

/// Event severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EventSeverity {
    Info,
    Warning,
    Error,
}

/// Authentication event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthEvent {
    /// Unique event ID
    pub id: String,

    /// Event type
    pub event_type: EventType,

    /// When the event occurred
    pub timestamp: DateTime<Utc>,

    /// Event severity
    pub severity: EventSeverity,

    /// User ID associated with the event (if applicable)
    pub user_id: Option<String>,

    /// Client ID associated with the event (if applicable)
    pub client_id: Option<String>,

    /// Additional metadata
    pub metadata: HashMap<String, String>,

    /// Optional error message
    pub error: Option<String>,
}

impl AuthEvent {
    /// Create a new authentication event
    pub fn new(
        event_type: EventType,
        severity: EventSeverity,
        user_id: Option<String>,
        client_id: Option<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            event_type,
            timestamp: Utc::now(),
            severity,
            user_id,
            client_id,
            metadata: HashMap::new(),
            error: None,
        }
    }

    /// Add metadata to the event
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Add an error message to the event
    #[allow(dead_code)]
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }

    /// Convert event to JSON string
    #[allow(dead_code)]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_as_str() {
        assert_eq!(EventType::TokenCreated.as_str(), "token_created");
        assert_eq!(EventType::ClientRegistered.as_str(), "client_registered");
    }

    #[test]
    fn test_auth_event_creation() {
        let event = AuthEvent::new(
            EventType::TokenCreated,
            EventSeverity::Info,
            Some("user_123".to_string()),
            Some("client_456".to_string()),
        );

        assert_eq!(event.event_type, EventType::TokenCreated);
        assert_eq!(event.severity, EventSeverity::Info);
        assert_eq!(event.user_id, Some("user_123".to_string()));
        assert_eq!(event.client_id, Some("client_456".to_string()));
    }

    #[test]
    fn test_auth_event_with_metadata() {
        let event = AuthEvent::new(
            EventType::TokenCreated,
            EventSeverity::Info,
            Some("user_123".to_string()),
            Some("client_456".to_string()),
        )
        .with_metadata("scope", "read write")
        .with_metadata("grant_type", "authorization_code");

        assert_eq!(event.metadata.get("scope"), Some(&"read write".to_string()));
        assert_eq!(
            event.metadata.get("grant_type"),
            Some(&"authorization_code".to_string())
        );
    }

    #[test]
    fn test_auth_event_serialization() {
        let event = AuthEvent::new(
            EventType::TokenCreated,
            EventSeverity::Info,
            Some("user_123".to_string()),
            Some("client_456".to_string()),
        );

        let json = event.to_json().unwrap();
        assert!(json.contains("token_created"));
        assert!(json.contains("user_123"));
        assert!(json.contains("client_456"));
    }
}
