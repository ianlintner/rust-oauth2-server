use crate::events::{
    bus::{EventBus, EventBusError},
    event_actor::{EmitEvent, EventActor},
    EventEnvelope,
};
use actix::prelude::*;
use async_trait::async_trait;

/// An EventBus implementation backed by the existing Actix `EventActor`.
///
/// Phase 1 behavior:
/// - Best-effort: uses `do_send` (fire-and-forget) so producers never block.
/// - Errors cannot be observed from `do_send`; failures are logged within `EventActor` plugins.
#[derive(Clone)]
pub struct ActixEventBus {
    addr: Addr<EventActor>,
}

impl ActixEventBus {
    pub fn new(addr: Addr<EventActor>) -> Self {
        Self { addr }
    }

    pub fn addr(&self) -> &Addr<EventActor> {
        &self.addr
    }
}

#[async_trait]
impl EventBus for ActixEventBus {
    async fn publish(&self, envelope: EventEnvelope) -> Result<(), EventBusError> {
        // Best-effort and non-blocking.
        self.addr.do_send(EmitEvent { envelope });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{AuthEvent, EventFilter, EventPlugin, EventSeverity, EventType, InMemoryEventLogger};
    use std::sync::Arc;

    #[actix::test]
    async fn actix_event_bus_publishes_to_in_memory_logger() {
        let logger = Arc::new(InMemoryEventLogger::new(10));
        let plugins: Vec<Arc<dyn EventPlugin>> = vec![logger.clone()];
        let filter = EventFilter::allow_all();
        let actor = EventActor::new(plugins, filter).start();

        let bus = ActixEventBus::new(actor);

        let event = AuthEvent::new(
            EventType::TokenCreated,
            EventSeverity::Info,
            Some("user_1".to_string()),
            Some("client_1".to_string()),
        );

        let env = EventEnvelope::from_current_span(event, "test");
        bus.publish(env).await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        assert_eq!(logger.get_events().len(), 1);
    }
}
