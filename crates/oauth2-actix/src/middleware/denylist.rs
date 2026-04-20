//! Middleware that rejects requests matching a denylist entry.
//!
//! Checks the client IP on every request. Paths that receive a username or
//! client_id in the form body (e.g. `/auth/login`, `/oauth/token`) are handled
//! by per-handler checks, since bodies aren't easily inspected here without
//! consuming them.

use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    web, Error, HttpResponse,
};
use futures::future::LocalBoxFuture;
use oauth2_core::DENYLIST_KIND_IP;
use oauth2_ports::DynStorage;
use std::future::{ready, Ready};
use std::rc::Rc;

/// Factory for the `DenylistGuard` middleware.
pub struct DenylistGuard;

impl<S, B> Transform<S, ServiceRequest> for DenylistGuard
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = DenylistGuardService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(DenylistGuardService {
            service: Rc::new(service),
        }))
    }
}

pub struct DenylistGuardService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for DenylistGuardService<S>
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

        Box::pin(async move {
            if let Some(storage) = req.app_data::<web::Data<DynStorage>>() {
                let ip = req
                    .connection_info()
                    .realip_remote_addr()
                    .unwrap_or("")
                    .to_string();
                if !ip.is_empty() {
                    if let Ok(Some(entry)) =
                        storage.find_denylist_entry(DENYLIST_KIND_IP, &ip).await
                    {
                        tracing::warn!(
                            ip = %ip,
                            reason = %entry.reason,
                            "Denylist IP match — blocking request"
                        );
                        let resp = HttpResponse::Forbidden().json(serde_json::json!({
                            "error": "access_denied",
                            "error_description": "request source is denylisted"
                        }));
                        return Ok(req.into_response(resp).map_into_right_body());
                    }
                }
            }

            let res = svc.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}

/// Helper for handlers (login, token endpoint) to check denylist by
/// `username`/`email`/`client_id`. Returns `Some(reason)` when blocked.
pub async fn check_subject_denylisted(
    storage: &DynStorage,
    kind: &str,
    value: &str,
) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    match storage.find_denylist_entry(kind, value).await {
        Ok(Some(entry)) => Some(entry.reason),
        _ => None,
    }
}
