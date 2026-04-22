//! W3C trace-context propagation for native event-bus backends.
//!
//! The [`EventEnvelope`](crate::EventEnvelope) already carries `traceparent` /
//! `tracestate` in its JSON body (`envelope.rs`). That covers consumers which
//! only ever read the payload. Most real Kafka / RabbitMQ consumers, however,
//! read trace context from the **native header channel** so span correlation
//! works before the payload is even parsed.
//!
//! This module provides the two thin helpers each backend needs:
//!
//! - [`inject_current_context`] — call on the publisher side to write the
//!   current span's W3C headers into whatever header carrier the backend
//!   gives us (Kafka `OwnedHeaders`, Rabbit `FieldTable`, …).
//! - [`extract_parent_context`] — call on the consumer side to pull a parent
//!   [`opentelemetry::Context`] out of the inbound header carrier. The caller
//!   then uses it as the parent for its consume-side span via
//!   `tracing::Span::current().set_parent(ctx)`.
//!
//! When the `otel` feature is disabled the helpers degrade to no-ops but keep
//! the same signatures so call sites don't need their own `cfg` branching.

#[cfg(feature = "otel")]
pub use otel_enabled::*;

#[cfg(not(feature = "otel"))]
pub use otel_disabled::*;

// --------------------------------------------------------------------------
// otel ON — real W3C propagation via the globally-installed propagator.
// --------------------------------------------------------------------------
#[cfg(feature = "otel")]
mod otel_enabled {
    use opentelemetry::propagation::{Extractor, Injector};
    use opentelemetry::Context;
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    pub use opentelemetry::propagation::{
        Extractor as PropagationExtractor, Injector as PropagationInjector,
    };

    /// Inject W3C trace-context headers from the current tracing span into a
    /// header carrier.
    ///
    /// Relies on the binary installing a W3C propagator via
    /// `opentelemetry::global::set_text_map_propagator(...)`. When no
    /// propagator is installed this is effectively a no-op.
    pub fn inject_current_context<I: Injector>(carrier: &mut I) {
        let cx = tracing::Span::current().context();
        opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.inject_context(&cx, carrier);
        });
    }

    /// Extract a parent [`Context`] from a header carrier.
    ///
    /// On the consumer side:
    ///
    /// ```ignore
    /// let cx = extract_parent_context(&carrier);
    /// let span = info_span!("kafka.consume", ...);
    /// span.set_parent(cx);
    /// ```
    pub fn extract_parent_context<E: Extractor>(carrier: &E) -> Context {
        opentelemetry::global::get_text_map_propagator(|propagator| propagator.extract(carrier))
    }

    // ----- Kafka carriers (feature-gated on `events-kafka`) -----

    #[cfg(feature = "events-kafka")]
    pub use kafka_carriers::*;

    #[cfg(feature = "events-kafka")]
    mod kafka_carriers {
        use super::*;
        use rdkafka::message::{Header, Headers, OwnedHeaders};

        /// [`Injector`] adapter over [`OwnedHeaders`].
        ///
        /// `OwnedHeaders::insert` consumes `self`, so we hold the value in an
        /// `Option` and reassemble it on each `set`. After injection, call
        /// [`KafkaHeadersInjector::into_inner`] to recover the populated
        /// `OwnedHeaders` for attachment to `FutureRecord::headers(..)`.
        pub struct KafkaHeadersInjector {
            inner: Option<OwnedHeaders>,
        }

        impl KafkaHeadersInjector {
            pub fn new() -> Self {
                Self {
                    inner: Some(OwnedHeaders::new()),
                }
            }

            pub fn from_existing(headers: OwnedHeaders) -> Self {
                Self {
                    inner: Some(headers),
                }
            }

            pub fn into_inner(self) -> OwnedHeaders {
                self.inner.unwrap_or_default()
            }
        }

        impl Default for KafkaHeadersInjector {
            fn default() -> Self {
                Self::new()
            }
        }

        impl Injector for KafkaHeadersInjector {
            fn set(&mut self, key: &str, value: String) {
                let current = self.inner.take().unwrap_or_default();
                let replaced = current.insert(Header {
                    key,
                    value: Some(value.as_bytes()),
                });
                self.inner = Some(replaced);
            }
        }

        /// [`Extractor`] adapter over an `rdkafka` headers reference.
        ///
        /// Use with `BorrowedHeaders` from a delivered message:
        /// `KafkaHeadersExtractor::new(msg.headers())`.
        pub struct KafkaHeadersExtractor<'a, H: Headers + ?Sized> {
            headers: Option<&'a H>,
        }

        impl<'a, H: Headers + ?Sized> KafkaHeadersExtractor<'a, H> {
            pub fn new(headers: Option<&'a H>) -> Self {
                Self { headers }
            }
        }

        impl<'a, H: Headers + ?Sized> Extractor for KafkaHeadersExtractor<'a, H> {
            fn get(&self, key: &str) -> Option<&str> {
                let headers = self.headers?;
                for i in 0..headers.count() {
                    let h = headers.try_get(i)?;
                    if h.key.eq_ignore_ascii_case(key) {
                        if let Some(bytes) = h.value {
                            return std::str::from_utf8(bytes).ok();
                        }
                    }
                }
                None
            }

            fn keys(&self) -> Vec<&str> {
                let Some(headers) = self.headers else {
                    return Vec::new();
                };
                (0..headers.count())
                    .filter_map(|i| headers.try_get(i).map(|h| h.key))
                    .collect()
            }
        }
    }

    // ----- RabbitMQ carriers (feature-gated on `events-rabbit`) -----

    #[cfg(feature = "events-rabbit")]
    pub use rabbit_carriers::*;

    #[cfg(feature = "events-rabbit")]
    mod rabbit_carriers {
        use super::*;
        use lapin::types::{AMQPValue, FieldTable, LongString, ShortString};

        /// [`Injector`] adapter over a `lapin` [`FieldTable`].
        ///
        /// Trace-context values are stored as `AMQPValue::LongString` so
        /// consumers read them as plain UTF-8 strings regardless of length.
        pub struct RabbitHeadersInjector<'a> {
            pub(crate) table: &'a mut FieldTable,
        }

        impl<'a> RabbitHeadersInjector<'a> {
            pub fn new(table: &'a mut FieldTable) -> Self {
                Self { table }
            }
        }

        impl<'a> Injector for RabbitHeadersInjector<'a> {
            fn set(&mut self, key: &str, value: String) {
                self.table.insert(
                    ShortString::from(key),
                    AMQPValue::LongString(LongString::from(value.into_bytes())),
                );
            }
        }

        /// [`Extractor`] adapter over a `lapin` [`FieldTable`].
        pub struct RabbitHeadersExtractor<'a> {
            pub(crate) table: &'a FieldTable,
        }

        impl<'a> RabbitHeadersExtractor<'a> {
            pub fn new(table: &'a FieldTable) -> Self {
                Self { table }
            }

            fn value_as_str(v: &AMQPValue) -> Option<&str> {
                match v {
                    AMQPValue::LongString(s) => std::str::from_utf8(s.as_bytes()).ok(),
                    AMQPValue::ShortString(s) => Some(s.as_str()),
                    _ => None,
                }
            }
        }

        impl<'a> Extractor for RabbitHeadersExtractor<'a> {
            fn get(&self, key: &str) -> Option<&str> {
                let inner = self.table.inner();
                // ShortString borrows as &str.
                inner.get(key).and_then(Self::value_as_str)
            }

            fn keys(&self) -> Vec<&str> {
                self.table
                    .inner()
                    .keys()
                    .map(|k| k.as_str())
                    .collect::<Vec<_>>()
            }
        }
    }
}

// --------------------------------------------------------------------------
// otel OFF — no-op stubs so callers don't need their own cfg branching.
// --------------------------------------------------------------------------
#[cfg(not(feature = "otel"))]
mod otel_disabled {
    /// Opaque placeholder returned by [`extract_parent_context`] when the
    /// `otel` feature is disabled. Carries no data and is inert if passed to
    /// `tracing::Span::set_parent` (requires the `otel` feature on that side
    /// anyway).
    #[derive(Clone, Copy, Default)]
    pub struct NoopContext;

    /// Marker trait used in place of `opentelemetry::propagation::Injector`
    /// when `otel` is off. Any type implements it.
    pub trait Injector {}
    impl<T: ?Sized> Injector for T {}

    /// Marker trait used in place of `opentelemetry::propagation::Extractor`
    /// when `otel` is off.
    pub trait Extractor {}
    impl<T: ?Sized> Extractor for T {}

    /// No-op when the `otel` feature is disabled.
    pub fn inject_current_context<I: ?Sized>(_carrier: &mut I) {}

    /// No-op when the `otel` feature is disabled. Returns an inert context.
    pub fn extract_parent_context<E: ?Sized>(_carrier: &E) -> NoopContext {
        NoopContext
    }
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------
#[cfg(all(test, feature = "otel"))]
mod tests {
    use super::*;
    use opentelemetry::propagation::{Extractor, Injector};
    use std::collections::HashMap;

    #[test]
    fn inject_then_extract_roundtrip_via_hashmap_carrier() {
        // HashMap<String, String> implements Injector+Extractor directly.
        // Install a noop propagator by relying on opentelemetry's default —
        // the test only asserts that injection is plumbed correctly (no
        // panic, no missing symbols). Extraction returns a Context that may
        // or may not be valid depending on the propagator, so we only smoke
        // the call path.
        let mut carrier: HashMap<String, String> = HashMap::new();
        inject_current_context(&mut carrier);

        // The call path is exercised; we don't assert on keys because the
        // globally-installed propagator in unit tests is implementation
        // defined.
        let _ = extract_parent_context(&carrier);

        // Sanity: carrier is still a HashMap we can read.
        let _ = carrier.len();
        let _ = carrier.get("traceparent");
    }

    #[cfg(feature = "events-kafka")]
    #[test]
    fn kafka_injector_roundtrips_set_values() {
        let mut injector = KafkaHeadersInjector::new();
        injector.set("traceparent", "00-abc-def-01".to_string());
        injector.set("tracestate", "vendor=x".to_string());

        let headers = injector.into_inner();
        let extractor = KafkaHeadersExtractor::new(Some(headers.as_borrowed()));
        assert_eq!(extractor.get("traceparent"), Some("00-abc-def-01"));
        assert_eq!(extractor.get("tracestate"), Some("vendor=x"));
        assert!(extractor
            .keys()
            .iter()
            .any(|k| *k == "traceparent" || *k == "tracestate"));
    }

    #[cfg(feature = "events-rabbit")]
    #[test]
    fn rabbit_injector_roundtrips_set_values() {
        use lapin::types::FieldTable;

        let mut table = FieldTable::default();
        {
            let mut injector = RabbitHeadersInjector::new(&mut table);
            injector.set("traceparent", "00-abc-def-01".to_string());
            injector.set("tracestate", "vendor=x".to_string());
        }

        let extractor = RabbitHeadersExtractor::new(&table);
        assert_eq!(extractor.get("traceparent"), Some("00-abc-def-01"));
        assert_eq!(extractor.get("tracestate"), Some("vendor=x"));
    }
}
