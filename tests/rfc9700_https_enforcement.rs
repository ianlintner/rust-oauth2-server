//! RFC 9700 §2.6 — HTTPS enforcement middleware conformance tests.

use actix_web::{test, web, App, HttpResponse};
use oauth2_actix::middleware::https_redirect::HttpsRedirect;

async fn probe() -> HttpResponse {
    HttpResponse::Ok().body("reached handler")
}

/// When `enforce = false` the middleware is a no-op and plain-HTTP requests
/// reach the inner handler. This is the dev default and must stay that way.
#[actix_web::test]
async fn disabled_by_default_passes_plain_http_through() {
    let app = test::init_service(
        App::new()
            .wrap(HttpsRedirect::new(false, false))
            .route("/probe", web::get().to(probe)),
    )
    .await;

    let resp = test::call_service(&app, test::TestRequest::get().uri("/probe").to_request()).await;

    assert_eq!(
        resp.status(),
        200,
        "no-op middleware must pass request through"
    );
}

/// With enforcement on, a plain-HTTP request is rewritten to the matching
/// `https://` URL and returned as HTTP 308 Permanent Redirect.
#[actix_web::test]
async fn enforced_plain_http_is_redirected_308_to_https() {
    let app = test::init_service(
        App::new()
            .wrap(HttpsRedirect::new(true, false))
            .route("/oauth/authorize", web::get().to(probe)),
    )
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/oauth/authorize?foo=bar")
            .insert_header(("Host", "auth.example.com"))
            .to_request(),
    )
    .await;

    assert_eq!(
        resp.status(),
        308,
        "RFC 9700 §2.6: plain HTTP must 308 → HTTPS"
    );
    let location = resp
        .headers()
        .get("Location")
        .expect("Location header")
        .to_str()
        .unwrap();
    assert_eq!(location, "https://auth.example.com/oauth/authorize?foo=bar");

    // Redirect must not be cached — otherwise a temporary HTTPS outage could
    // lock clients to a stale URL.
    let cache_control = resp
        .headers()
        .get("Cache-Control")
        .expect("Cache-Control header")
        .to_str()
        .unwrap();
    assert!(cache_control.contains("no-store"));
}

/// With `trust_proxy_headers = true`, the middleware honors
/// `X-Forwarded-Proto: https` set by a TLS-terminating reverse proxy and
/// lets the request through even though the local scheme is plain.
#[actix_web::test]
async fn trusted_forwarded_proto_https_passes_through() {
    let app = test::init_service(
        App::new()
            .wrap(HttpsRedirect::new(true, true))
            .route("/oauth/token", web::post().to(probe)),
    )
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .insert_header(("Host", "auth.example.com"))
            .insert_header(("X-Forwarded-Proto", "https"))
            .to_request(),
    )
    .await;

    assert_eq!(
        resp.status(),
        200,
        "request terminated at proxy as HTTPS must reach handler"
    );
}

/// When `trust_proxy_headers = false`, even `X-Forwarded-Proto: https` is
/// ignored — prevents a spoofed header from bypassing the redirect when the
/// server is not actually behind a trusted proxy.
#[actix_web::test]
async fn untrusted_forwarded_proto_header_is_ignored() {
    let app = test::init_service(
        App::new()
            .wrap(HttpsRedirect::new(true, false))
            .route("/oauth/token", web::post().to(probe)),
    )
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .insert_header(("Host", "auth.example.com"))
            .insert_header(("X-Forwarded-Proto", "https"))
            .to_request(),
    )
    .await;

    assert_eq!(
        resp.status(),
        308,
        "spoofed X-Forwarded-Proto must NOT bypass the redirect when proxy headers are untrusted"
    );
}
