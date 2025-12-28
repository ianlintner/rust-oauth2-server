use crate::events::EventEnvelope;
use async_trait::async_trait;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum EventBusError {
    Unavailable,
    Rejected(String),
    Other(String),
}

impl std::fmt::Display for EventBusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventBusError::Unavailable => write!(f, "event bus is not available"),
            EventBusError::Rejected(msg) => write!(f, "event bus rejected publish: {msg}"),
            EventBusError::Other(msg) => write!(f, "event bus failure: {msg}"),
        }
    }
}

impl std::error::Error for EventBusError {}

/// A typesafe, async publishing interface.
///
/// Phase 1 guarantees:
/// - Best-effort: publishing should be non-blocking and should not fail core OAuth flows.
/// - Stable contract: Phase 2+ can introduce persistence/outbox behind this interface.
#[async_trait]
pub trait EventBus: Send + Sync {
    async fn publish(&self, envelope: EventEnvelope) -> Result<(), EventBusError>;
}

pub type DynEventBus = Arc<dyn EventBus>;

/// Cloneable handle for passing a bus into actors/handlers.
#[derive(Clone)]
pub struct EventBusHandle {
    inner: DynEventBus,
}

impl EventBusHandle {
    pub fn new(inner: DynEventBus) -> Self {
        Self { inner }
    }

    pub async fn publish(&self, envelope: EventEnvelope) -> Result<(), EventBusError> {
        self.inner.publish(envelope).await
    }
}
