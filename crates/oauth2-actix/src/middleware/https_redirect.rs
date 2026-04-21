//! HTTPS enforcement middleware (RFC 9700 §2.6).
//!
//! When `enforce_https = true`, any request arriving over plain HTTP is
//! rewritten to `https://` and returned with an HTTP 308 Permanent Redirect.
//!
//! Scheme detection:
//! - When `trust_proxy_headers = true`, prefer the `X-Forwarded-Proto` header
//!   (set by TLS-terminating reverse proxies such as nginx / Envoy / AGIC).
//! - Otherwise fall back to the request's connection scheme. Binary tests
//!   run over `actix_web::test` report `http` by default, which is exactly
//!   the condition this middleware is meant to catch in production.
//!
//! Dev-mode escape hatch: leaving `enforce_https = false` (the default) makes
//! the middleware a no-op, so local `cargo run` + `curl http://localhost:8080`
//! still works.

use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse,
};
use futures::future::LocalBoxFuture;
use std::future::{ready, Ready};
use std::rc::Rc;

/// Factory configuration for [`HttpsRedirect`].
#[derive(Clone, Copy, Debug)]
pub struct HttpsRedirect {
    pub enforce: bool,
    pub trust_proxy_headers: bool,
}

impl HttpsRedirect {
    pub fn new(enforce: bool, trust_proxy_headers: bool) -> Self {
        Self {
            enforce,
            trust_proxy_headers,
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for HttpsRedirect
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = HttpsRedirectService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(HttpsRedirectService {
            service: Rc::new(service),
            enforce: self.enforce,
            trust_proxy_headers: self.trust_proxy_headers,
        }))
    }
}

pub struct HttpsRedirectService<S> {
    service: Rc<S>,
    enforce: bool,
    trust_proxy_headers: bool,
}

impl<S, B> Service<ServiceRequest> for HttpsRedirectService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        let enforce = self.enforce;
        let trust_proxy = self.trust_proxy_headers;

        Box::pin(async move {
            if enforce && !request_is_secure(&req, trust_proxy) {
                if let Some(https_url) = to_https_url(&req) {
                    tracing::info!(
                        original_uri = %req.uri(),
                        redirect = %https_url,
                        "RFC 9700 §2.6: redirecting plain-HTTP request to HTTPS"
                    );
                    let resp = HttpResponse::PermanentRedirect()
                        .append_header(("Location", https_url))
                        // Prevent caching of the redirect so that once TLS is
                        // terminated at a different layer the upgrade sticks.
                        .append_header(("Cache-Control", "no-store"))
                        .finish();
                    return Ok(req.into_response(resp).map_into_right_body());
                }
            }
            let res = svc.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}

/// Returns `true` when the request arrived over TLS.
///
/// We intentionally do NOT use `ServiceRequest::connection_info()` here:
/// Actix's `ConnectionInfo` always reads `Forwarded` / `X-Forwarded-Proto`
/// regardless of configuration, so it would silently honor a spoofed header
/// even when the operator set `trust_proxy_headers = false`. This helper
/// inspects the forwarded header only when explicitly trusted, and
/// otherwise consults the raw URI scheme on the `ServiceRequest` — which
/// is populated by actix from the socket, not from client-supplied headers.
///
/// Unknown or missing values are treated as insecure so the middleware
/// fails safe.
fn request_is_secure(req: &ServiceRequest, trust_proxy: bool) -> bool {
    if trust_proxy {
        if let Some(value) = req.headers().get("X-Forwarded-Proto") {
            if let Ok(s) = value.to_str() {
                // Comma-separated list — the first value is the closest proxy.
                let first = s.split(',').next().unwrap_or("").trim();
                return first.eq_ignore_ascii_case("https");
            }
        }
    }
    match req.uri().scheme_str() {
        Some(scheme) => scheme.eq_ignore_ascii_case("https"),
        None => false,
    }
}

/// Build the `https://` equivalent of the current request URL so the browser
/// can follow the redirect. Uses the `Host` header directly so we do not rely
/// on `connection_info()` (which merges forwarded headers unconditionally).
/// Returns `None` when the host is not recoverable.
fn to_https_url(req: &ServiceRequest) -> Option<String> {
    let host = req
        .headers()
        .get("Host")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| {
            req.uri()
                .authority()
                .map(|a| a.as_str().to_string())
                .filter(|s| !s.is_empty())
        })?;
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    Some(format!("https://{host}{path_and_query}"))
}
