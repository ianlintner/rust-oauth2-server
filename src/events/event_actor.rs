use crate::events::{AuthEvent, EventFilter, EventPlugin};
use actix::prelude::*;
use std::sync::Arc;

/// Event actor that processes and distributes events to plugins
pub struct EventActor {
    plugins: Vec<Arc<dyn EventPlugin>>,
    filter: EventFilter,
}

impl EventActor {
    /// Create a new event actor with the given plugins and filter
    pub fn new(plugins: Vec<Arc<dyn EventPlugin>>, filter: EventFilter) -> Self {
        Self { plugins, filter }
    }

    /// Create a new event actor with default plugins
    #[allow(dead_code)]
    pub fn with_default_plugins(filter: EventFilter) -> Self {
        use crate::events::InMemoryEventLogger;

        let plugins: Vec<Arc<dyn EventPlugin>> = vec![Arc::new(InMemoryEventLogger::new(1000))];

        Self { plugins, filter }
    }
}

impl Actor for EventActor {
    type Context = Context<Self>;

    fn started(&mut self, _ctx: &mut Self::Context) {
        tracing::info!("EventActor started with {} plugin(s)", self.plugins.len());
    }
}

/// Message to emit an event
#[derive(Message)]
#[rtype(result = "()")]
pub struct EmitEvent {
    pub event: AuthEvent,
}

impl Handler<EmitEvent> for EventActor {
    type Result = ResponseFuture<()>;

    fn handle(&mut self, msg: EmitEvent, _: &mut Self::Context) -> Self::Result {
        // Check if event should be emitted based on filter
        if !self.filter.should_emit(&msg.event.event_type) {
            tracing::trace!("Event {:?} filtered out", msg.event.event_type);
            return Box::pin(async {});
        }

        let plugins = self.plugins.clone();
        let event = msg.event;

        Box::pin(async move {
            // Emit to all plugins in parallel
            let futures: Vec<_> = plugins
                .iter()
                .map(|plugin| {
                    let plugin = plugin.clone();
                    let event = event.clone();
                    async move {
                        if let Err(e) = plugin.emit(&event).await {
                            tracing::error!(
                                "Failed to emit event to plugin {}: {}",
                                plugin.name(),
                                e
                            );
                        }
                    }
                })
                .collect();

            futures::future::join_all(futures).await;
        })
    }
}

/// Message to get health status of all plugins
#[derive(Message)]
#[rtype(result = "Vec<(String, bool)>")]
pub struct GetPluginHealth;

impl Handler<GetPluginHealth> for EventActor {
    type Result = ResponseFuture<Vec<(String, bool)>>;

    fn handle(&mut self, _msg: GetPluginHealth, _: &mut Self::Context) -> Self::Result {
        let plugins = self.plugins.clone();

        Box::pin(async move {
            let mut results = Vec::new();

            for plugin in plugins.iter() {
                let name = plugin.name().to_string();
                let healthy = plugin.health_check().await;
                results.push((name, healthy));
            }

            results
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventSeverity, EventType, InMemoryEventLogger};

    #[actix::test]
    async fn test_event_actor_emit() {
        let logger = Arc::new(InMemoryEventLogger::new(10));
        let plugins: Vec<Arc<dyn EventPlugin>> = vec![logger.clone()];
        let filter = EventFilter::allow_all();

        let actor = EventActor::new(plugins, filter).start();

        let event = AuthEvent::new(
            EventType::TokenCreated,
            EventSeverity::Info,
            Some("user_123".to_string()),
            Some("client_456".to_string()),
        );

        actor.send(EmitEvent { event }).await.unwrap();

        // Give actor time to process
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let events = logger.get_events();
        assert_eq!(events.len(), 1);
    }

    #[actix::test]
    async fn test_event_actor_filter() {
        let logger = Arc::new(InMemoryEventLogger::new(10));
        let plugins: Vec<Arc<dyn EventPlugin>> = vec![logger.clone()];
        let filter = EventFilter::include_only(vec![EventType::TokenCreated]);

        let actor = EventActor::new(plugins, filter).start();

        // This should be emitted
        let event1 = AuthEvent::new(
            EventType::TokenCreated,
            EventSeverity::Info,
            Some("user_123".to_string()),
            None,
        );
        actor.send(EmitEvent { event: event1 }).await.unwrap();

        // This should be filtered out
        let event2 = AuthEvent::new(
            EventType::ClientRegistered,
            EventSeverity::Info,
            Some("user_123".to_string()),
            None,
        );
        actor.send(EmitEvent { event: event2 }).await.unwrap();

        // Give actor time to process
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let events = logger.get_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, EventType::TokenCreated);
    }

    #[actix::test]
    async fn test_event_actor_health_check() {
        let logger = Arc::new(InMemoryEventLogger::new(10));
        let plugins: Vec<Arc<dyn EventPlugin>> = vec![logger];
        let filter = EventFilter::allow_all();

        let actor = EventActor::new(plugins, filter).start();

        let health = actor.send(GetPluginHealth).await.unwrap();
        assert_eq!(health.len(), 1);
        assert_eq!(health[0].0, "in_memory");
        assert!(health[0].1);
    }
}
