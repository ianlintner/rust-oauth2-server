//! Paved-path metrics baseline conformance tests.
//!
//! Locks in the §2 required-metric inventory and §3 bucket policy from the
//! in-repo `prometheus-metrics` skill. A missing metric name or a changed
//! bucket boundary surfaces here before dashboards notice.

use oauth2_observability::{
    encode_prometheus_text, Metrics, STANDARD_LATENCY_BUCKETS, STANDARD_SIZE_BUCKETS,
};

fn metrics_text() -> String {
    let metrics = Metrics::new().expect("metrics");
    // The `app_info` gauge is emitted at Metrics::new(), so a fresh scrape
    // always surfaces at least that one series.
    let body = encode_prometheus_text(&metrics.registry).expect("encode");
    String::from_utf8(body).expect("utf-8")
}

/// Every paved-path-required metric family must be registered and exposed
/// on the scrape endpoint, even before any handler has touched it. This
/// guarantees dashboards don't have to wait for a first request to find
/// their series.
#[test]
fn required_metrics_are_registered() {
    let body = metrics_text();
    let required = [
        // §2 HTTP server RED
        "oauth2_server_http_requests_total",
        "oauth2_server_http_request_duration_seconds",
        // §2 HTTP client (outbound)
        "oauth2_server_http_client_requests_total",
        "oauth2_server_http_client_request_duration_seconds",
        // §2 errors
        "oauth2_server_errors_total",
        // §2 database client
        "oauth2_server_db_queries_total",
        "oauth2_server_db_query_duration_seconds",
        // Redis client
        "oauth2_server_redis_client_operations_total",
        "oauth2_server_redis_client_operation_duration_seconds",
        // Event bus
        "oauth2_server_events_published_total",
        "oauth2_server_events_publish_duration_seconds",
        // Build / deployment metadata
        "oauth2_server_app_info",
    ];
    for name in required {
        assert!(
            body.contains(name),
            "paved-path spec §2: required metric `{name}` missing from /metrics scrape"
        );
    }
}

/// `app_info` is emitted exactly once at startup as the pattern
/// `app_info{service, version, rust_version} 1`.
#[test]
fn app_info_carries_version_label_and_is_one() {
    let body = metrics_text();
    let line = body
        .lines()
        .find(|l| l.starts_with("oauth2_server_app_info{"))
        .expect("app_info series present");
    assert!(
        line.contains(&format!("version=\"{}\"", env!("CARGO_PKG_VERSION"))),
        "app_info must carry the crate version as a label — got: {line}"
    );
    assert!(
        line.contains("service=\"oauth2-server\""),
        "app_info must carry the service name — got: {line}"
    );
    assert!(
        line.ends_with(" 1"),
        "app_info gauge value must be exactly 1 — got: {line}"
    );
}

/// Paved-path §3: every latency histogram must ship with the curated
/// bucket boundaries, not the prometheus-client default.
#[test]
fn standard_latency_buckets_match_spec() {
    // Spec §3 exact sequence.
    assert_eq!(
        STANDARD_LATENCY_BUCKETS,
        &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    );
}

#[test]
fn standard_size_buckets_match_spec() {
    assert_eq!(
        STANDARD_SIZE_BUCKETS,
        &[
            128.0,
            512.0,
            2048.0,
            8192.0,
            32768.0,
            131072.0,
            524288.0,
            2_097_152.0,
            8_388_608.0
        ]
    );
}

/// Histogram families added under this PR must observe the spec buckets.
/// `Metrics::new()` seeds each labeled family with a zero sample so the
/// scrape endpoint carries every spec bucket edge from cold start.
#[test]
fn new_histograms_use_standard_latency_buckets() {
    let body = metrics_text();
    for family in [
        "oauth2_server_http_client_request_duration_seconds",
        "oauth2_server_events_publish_duration_seconds",
        "oauth2_server_redis_client_operation_duration_seconds",
    ] {
        let type_line = format!("# TYPE {family} histogram");
        assert!(
            body.contains(&type_line),
            "histogram family `{family}` missing TYPE declaration on /metrics"
        );
        for bound in STANDARD_LATENCY_BUCKETS {
            // Prometheus omits trailing `.0` on integer bucket edges.
            let rendered = if bound.fract() == 0.0 {
                format!("{}", *bound as i64)
            } else {
                format!("{bound}")
            };
            let needle = format!("{family}_bucket{{");
            assert!(
                body.contains(&needle),
                "histogram family `{family}` missing bucket series; expected `le=\"{rendered}\"` among them"
            );
        }
    }
}
