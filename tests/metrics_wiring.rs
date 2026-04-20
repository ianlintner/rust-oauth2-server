//! Integration tests for the Prometheus metrics middleware.
//!
//! These assert that `MetricsMiddleware`:
//! - Emits `oauth2_server_http_requests_by_class_total` with a `status_class`
//!   label for both successful (2xx) and client-error (4xx) responses.
//! - Observes samples into the `oauth2_server_http_request_duration_seconds`
//!   histogram (the scraped `..._bucket` series has a nonzero `+Inf` count).
//!
//! Admin dashboard charts depend on both series being populated.

use actix_web::{test, web, App, HttpResponse};
use oauth2_observability::{actix::MetricsMiddleware, encode_prometheus_text, Metrics};

async fn ok_handler() -> HttpResponse {
    HttpResponse::Ok().body("ok")
}

async fn not_found_handler() -> HttpResponse {
    HttpResponse::NotFound().body("not found")
}

async fn metrics_dump(metrics: web::Data<Metrics>) -> HttpResponse {
    let body = encode_prometheus_text(&metrics.registry).expect("encode");
    HttpResponse::Ok().body(body)
}

#[actix_web::test]
async fn metrics_middleware_emits_status_class_counter_and_duration_histogram() {
    let metrics = Metrics::new().expect("metrics");

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(metrics.clone()))
            .wrap(MetricsMiddleware::new(metrics.clone()))
            .route("/ok", web::get().to(ok_handler))
            .route("/missing", web::get().to(not_found_handler))
            .route("/metrics", web::get().to(metrics_dump)),
    )
    .await;

    for _ in 0..3 {
        let req = test::TestRequest::get().uri("/ok").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    for _ in 0..2 {
        let req = test::TestRequest::get().uri("/missing").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body = test::read_body(resp).await;
    let body = std::str::from_utf8(&body).expect("utf8 metrics body");

    // New status_class counter: at least one 2xx and one 4xx sample.
    assert!(
        body.lines().any(|l| l
            .starts_with("oauth2_server_http_requests_by_class_total{status_class=\"2xx\"}")
            && parse_value(l) > 0.0),
        "expected 2xx status_class counter > 0\n{body}"
    );
    assert!(
        body.lines().any(|l| l
            .starts_with("oauth2_server_http_requests_by_class_total{status_class=\"4xx\"}")
            && parse_value(l) > 0.0),
        "expected 4xx status_class counter > 0\n{body}"
    );

    // Duration histogram: the +Inf bucket's cumulative count equals total
    // observed samples. With requests above, this must be > 0.
    let inf_line = body
        .lines()
        .find(|l| l.starts_with("oauth2_server_http_request_duration_seconds_bucket{le=\"+Inf\"}"))
        .unwrap_or_else(|| panic!("expected +Inf bucket line\n{body}"));
    assert!(
        parse_value(inf_line) > 0.0,
        "expected +Inf bucket > 0, got: {inf_line}"
    );
}

/// Parse the trailing numeric value from a Prometheus text-format line like
/// `name{labels} 3` or `name 3`.
fn parse_value(line: &str) -> f64 {
    line.rsplit_once(' ')
        .and_then(|(_, v)| v.trim().parse::<f64>().ok())
        .unwrap_or(0.0)
}
