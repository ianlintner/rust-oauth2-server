//! Conformance-mode SUT interface v2 (contract `contract/sut-interface.md` §7).
//!
//! Everything here is reachable only in conformance mode: the server wires
//! [`ConformanceControls`] as `app_data` and registers the `/conformance/*`
//! routes **only** when conformance mode is on (after the production guard
//! and seed). With the mode off there is no state and no route, so the paths
//! are plain 404s and [`dpop_nonce_forced`] is always `false`.
//!
//! Capabilities are advertised only when actually implemented.

use std::sync::atomic::{AtomicBool, Ordering};

use actix_web::{web, HttpResponse};
use serde_json::{json, Value};

/// Process-local conformance state (contract §7: resets on restart).
#[derive(Debug, Default)]
pub struct ConformanceControls {
    dpop_nonce_required: AtomicBool,
}

impl ConformanceControls {
    pub fn dpop_nonce_required(&self) -> bool {
        self.dpop_nonce_required.load(Ordering::SeqCst)
    }

    pub fn set_dpop_nonce_required(&self, required: bool) {
        self.dpop_nonce_required.store(required, Ordering::SeqCst);
    }
}

/// True when the conformance DPoP-nonce toggle forces nonce enforcement.
/// Always `false` when `controls` is absent (i.e. outside conformance mode).
pub fn dpop_nonce_forced(controls: Option<&web::Data<ConformanceControls>>) -> bool {
    controls.is_some_and(|c| c.dpop_nonce_required())
}

/// Capabilities this server implements. Keep in sync with the routes below;
/// `test-clock`, `restart`, `multi-instance` and `mtls` are not implemented
/// yet and therefore not advertised.
const CAPABILITIES: &[&str] = &["dpop-nonce-mode"];

/// `GET /conformance/capabilities`
pub async fn capabilities() -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "interface_version": 2,
        "capabilities": CAPABILITIES,
    }))
}

/// `POST /conformance/dpop-nonce` with `{"required": true|false}`.
pub async fn set_dpop_nonce(
    controls: web::Data<ConformanceControls>,
    body: web::Bytes,
) -> HttpResponse {
    let required = serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|v| v.get("required").and_then(Value::as_bool));
    match required {
        Some(required) => {
            controls.set_dpop_nonce_required(required);
            HttpResponse::Ok().json(json!({ "required": required }))
        }
        None => HttpResponse::BadRequest()
            .json(json!({ "error": "invalid_request", "error_description": "body must be {\"required\": true|false}" })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggle_defaults_off_and_flips() {
        let c = ConformanceControls::default();
        assert!(!c.dpop_nonce_required());
        c.set_dpop_nonce_required(true);
        assert!(c.dpop_nonce_required());
    }

    #[test]
    fn nonce_never_forced_without_controls() {
        assert!(!dpop_nonce_forced(None));
        let on = web::Data::new(ConformanceControls::default());
        assert!(!dpop_nonce_forced(Some(&on)));
        on.set_dpop_nonce_required(true);
        assert!(dpop_nonce_forced(Some(&on)));
    }
}
