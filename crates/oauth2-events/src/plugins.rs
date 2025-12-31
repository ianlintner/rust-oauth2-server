use crate::{EventEnvelope, EventType};
use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

/// Trait for event backend plugins
#[async_trait]
pub trait EventPlugin: Send + Sync {
    /// Emit an event to the backend
    async fn emit(&self, envelope: &EventEnvelope) -> Result<(), String>;

    /// Get the name of the plugin
    fn name(&self) -> &str;

    /// Check if the plugin is healthy
    async fn health_check(&self) -> bool {
        true
    }
}

/// Configuration for event filtering
#[derive(Debug, Clone)]
pub struct EventFilter {
    /// If true, only emit events in the include list
    /// If false, emit all events except those in the exclude list
    pub use_include_list: bool,

    /// Events to include (when use_include_list is true)
    pub include: HashSet<EventType>,

    /// Events to exclude (when use_include_list is false)
    pub exclude: HashSet<EventType>,
}

impl EventFilter {
    /// Create a new filter that includes all events
    pub fn allow_all() -> Self {
        Self {
            use_include_list: false,
            include: HashSet::new(),
            exclude: HashSet::new(),
        }
    }

    /// Create a new filter with an inclusion list
    pub fn include_only(events: Vec<EventType>) -> Self {
        Self {
            use_include_list: true,
            include: events.into_iter().collect(),
            exclude: HashSet::new(),
        }
    }

    /// Create a new filter with an exclusion list
    pub fn exclude_events(events: Vec<EventType>) -> Self {
        Self {
            use_include_list: false,
            include: HashSet::new(),
            exclude: events.into_iter().collect(),
        }
    }

    /// Check if an event type should be emitted
    pub fn should_emit(&self, event_type: &EventType) -> bool {
        if self.use_include_list {
            self.include.contains(event_type)
        } else {
            !self.exclude.contains(event_type)
        }
    }
}

/// In-memory event logger (default plugin)
pub struct InMemoryEventLogger {
    events: Arc<RwLock<Vec<EventEnvelope>>>,
    max_events: usize,
}

impl InMemoryEventLogger {
    /// Create a new in-memory event logger
    pub fn new(max_events: usize) -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
            max_events,
        }
    }

    /// Get all stored events
    #[allow(dead_code)]
    pub fn get_events(&self) -> Vec<EventEnvelope> {
        self.events.read().unwrap().clone()
    }

    /// Get recent events (up to limit)
    #[allow(dead_code)]
    pub fn get_recent_events(&self, limit: usize) -> Vec<EventEnvelope> {
        let events = self.events.read().unwrap();
        let start = if events.len() > limit { events.len() - limit } else { 0 };
        events[start..].to_vec()
    }

    /// Clear all events
    #[allow(dead_code)]
    pub fn clear(&self) {
        self.events.write().unwrap().clear();
    }
}

#[async_trait]
impl EventPlugin for InMemoryEventLogger {
    async fn emit(&self, envelope: &EventEnvelope) -> Result<(), String> {
        let mut events = self.events.write().unwrap();

        // Add event
        events.push(envelope.clone());

        // Keep only max_events
        if events.len() > self.max_events {
            let excess = events.len() - self.max_events;
            events.drain(0..excess);
        }

        tracing::debug!("Event logged: {:?}", envelope.event.event_type);
        Ok(())
    }

    fn name(&self) -> &str {
        "in_memory"
    }
}

/// Console event logger (logs to stdout)
#[derive(Default)]
pub struct ConsoleEventLogger;

impl ConsoleEventLogger {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl EventPlugin for ConsoleEventLogger {
    async fn emit(&self, envelope: &EventEnvelope) -> Result<(), String> {
        match serde_json::to_string(envelope) {
            Ok(json) => {
                tracing::info!("Event: {}", json);
                Ok(())
            }
            Err(e) => Err(format!("Failed to serialize event: {}", e)),
        }
    }

    fn name(&self) -> &str {
        "console"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthEvent, EventSeverity};

    #[test]
    fn test_event_filter_allow_all() {
        let filter = EventFilter::allow_all();
        assert!(filter.should_emit(&EventType::TokenCreated));
        assert!(filter.should_emit(&EventType::ClientRegistered));
    }

    #[test]
    fn test_event_filter_include_only() {
        let filter = EventFilter::include_only(vec![EventType::TokenCreated, EventType::TokenRevoked]);

        assert!(filter.should_emit(&EventType::TokenCreated));
        assert!(filter.should_emit(&EventType::TokenRevoked));
        assert!(!filter.should_emit(&EventType::ClientRegistered));
    }

    #[test]
    fn test_event_filter_exclude() {
        let filter = EventFilter::exclude_events(vec![EventType::TokenValidated]);

        assert!(filter.should_emit(&EventType::TokenCreated));
        assert!(!filter.should_emit(&EventType::TokenValidated));
        assert!(filter.should_emit(&EventType::ClientRegistered));
    }

    #[tokio::test]
    async fn test_in_memory_logger() {
        let logger = InMemoryEventLogger::new(10);

        let event = AuthEvent::new(
            EventType::TokenCreated,
            EventSeverity::Info,
            Some("user_123".to_string()),
            None,
        );

        let env = EventEnvelope::from_current_span(event, "test");

        logger.emit(&env).await.unwrap();

        let events = logger.get_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event.event_type, EventType::TokenCreated);
    }

    #[tokio::test]
    async fn test_in_memory_logger_max_events() {
        let logger = InMemoryEventLogger::new(3);

        // Add 5 events
        for i in 0..5 {
            let event = AuthEvent::new(
                EventType::TokenCreated,
                EventSeverity::Info,
                Some(format!("user_{}", i)),
                None,
            );
            let env = EventEnvelope::from_current_span(event, "test");
            logger.emit(&env).await.unwrap();
        }

        let events = logger.get_events();
        assert_eq!(events.len(), 3); // Only last 3 events
        assert_eq!(events[0].event.user_id, Some("user_2".to_string()));
        assert_eq!(events[2].event.user_id, Some("user_4".to_string()));
    }
}
