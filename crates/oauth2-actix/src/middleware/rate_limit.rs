//! Rate limiting middleware.
//!
//! Uses the `RateLimiter` trait from `oauth2-ratelimit` to enforce per-key
//! rate limits. Follows the same Transform/Service pattern as `AdminGuard`.

use std::future::{ready, Ready};
use std::rc::Rc;
use std::sync::Arc;

/// Penalty bucket for `invalid_client` failures on the token endpoint.
///
/// Injected as `app_data` so the token handler can record credential failures
/// and block credential-stuffing once the per-IP limit is reached.
pub struct InvalidClientRateLimiter(pub Arc<dyn oauth2_ratelimit::RateLimiter>);

use actix_web::body::EitherBody;
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error, HttpResponse};
use futures::future::LocalBoxFuture;
use oauth2_ratelimit::{RateLimitResult, RateLimiter};

/// Middleware that enforces rate limits on incoming requests.
///
/// Exempt paths (health, ready, metrics) are passed through without checking.
pub struct RateLimitMiddleware {
    limiter: Arc<dyn RateLimiter>,
    exempt_paths: Vec<String>,
    trust_proxy_headers: bool,
}

impl RateLimitMiddleware {
    pub fn new(
        limiter: Arc<dyn RateLimiter>,
        exempt_paths: Vec<String>,
        trust_proxy_headers: bool,
    ) -> Self {
        Self {
            limiter,
            exempt_paths,
            trust_proxy_headers,
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimitMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = RateLimitService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimitService {
            service: Rc::new(service),
            limiter: self.limiter.clone(),
            exempt_paths: self.exempt_paths.clone(),
            trust_proxy_headers: self.trust_proxy_headers,
        }))
    }
}

pub struct RateLimitService<S> {
    service: Rc<S>,
    limiter: Arc<dyn RateLimiter>,
    exempt_paths: Vec<String>,
    trust_proxy_headers: bool,
}

impl<S, B> RateLimitService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
{
    fn extract_client_ip(&self, req: &ServiceRequest) -> String {
        if self.trust_proxy_headers {
            if let Some(forwarded) = req.headers().get("X-Forwarded-For") {
                if let Ok(value) = forwarded.to_str() {
                    if let Some(first_ip) = value.split(',').next() {
                        return first_ip.trim().to_string();
                    }
                }
            }
        }
        req.peer_addr()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }
}

impl<S, B> Service<ServiceRequest> for RateLimitService<S>
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
        let limiter = self.limiter.clone();
        let exempt = self.exempt_paths.clone();
        let path = req.path().to_string();
        let client_ip = self.extract_client_ip(&req);

        Box::pin(async move {
            // Skip rate limiting for exempt paths
            if exempt.iter().any(|p| path.starts_with(p)) {
                let res = svc.call(req).await?;
                return Ok(res.map_into_left_body());
            }

            match limiter.check(&client_ip).await {
                Ok(result) => {
                    if result.allowed {
                        let res = svc.call(req).await?;
                        let res = add_rate_limit_headers(res, &result);
                        Ok(res.map_into_left_body())
                    } else {
                        // Rejected — return 429
                        let retry_after =
                            result.retry_after.map(|d| d.as_secs().max(1)).unwrap_or(1);

                        let reset_unix = result
                            .reset_at
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();

                        tracing::warn!(
                            client_ip = %client_ip,
                            path = %path,
                            "Rate limit exceeded"
                        );

                        let response = HttpResponse::TooManyRequests()
                            .insert_header(("X-RateLimit-Limit", result.limit.to_string()))
                            .insert_header(("X-RateLimit-Remaining", "0"))
                            .insert_header(("X-RateLimit-Reset", reset_unix.to_string()))
                            .insert_header(("Retry-After", retry_after.to_string()))
                            .json(serde_json::json!({
                                "error": "too_many_requests",
                                "error_description": "Rate limit exceeded. Try again later.",
                                "retry_after": retry_after
                            }));

                        Ok(req.into_response(response).map_into_right_body())
                    }
                }
                Err(e) => {
                    // Backend failure — fail open (allow the request)
                    tracing::error!(error = %e, "Rate limiter backend error, failing open");
                    let res = svc.call(req).await?;
                    Ok(res.map_into_left_body())
                }
            }
        })
    }
}

fn add_rate_limit_headers<B>(
    res: ServiceResponse<B>,
    result: &RateLimitResult,
) -> ServiceResponse<B> {
    let reset_unix = result
        .reset_at
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let (req, mut response) = res.into_parts();
    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("x-ratelimit-limit"),
        result.limit.to_string().parse().unwrap(),
    );
    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("x-ratelimit-remaining"),
        result.remaining.to_string().parse().unwrap(),
    );
    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("x-ratelimit-reset"),
        reset_unix.to_string().parse().unwrap(),
    );
    ServiceResponse::new(req, response)
}
