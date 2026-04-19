//! Middleware that restricts access to admin-level users.
//!
//! Accepts two auth mechanisms:
//!
//! 1. **Bearer token** — `Authorization: Bearer <token>` with `admin` scope.
//!    Checked first; intended for machine-to-machine callers (e.g. MCP server).
//! 2. **Session cookie** — `role == "admin"` in the session, or the user's
//!    email matches `OAUTH2_ADMIN_EMAILS`. Intended for browser dashboard access.
//!
//! Unauthenticated requests redirect to `/auth/login`; authenticated but
//! non-admin requests receive a 302 redirect to `OAUTH2_NON_ADMIN_REDIRECT`
//! (defaults to `/profile`).

use actix_session::SessionExt;
use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    web, Error, HttpResponse,
};
use futures::future::LocalBoxFuture;
use oauth2_ports::DynStorage;
use std::future::{ready, Ready};
use std::rc::Rc;

/// Actix-web middleware that gates access to admin-only routes.
pub struct AdminGuard;

impl<S, B> Transform<S, ServiceRequest> for AdminGuard
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = AdminGuardService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AdminGuardService {
            service: Rc::new(service),
        }))
    }
}

pub struct AdminGuardService<S> {
    service: Rc<S>,
}

/// Check if the given email is in the admin emails list.
fn is_admin_email(email: &str) -> bool {
    if let Ok(admin_emails) = std::env::var("OAUTH2_ADMIN_EMAILS") {
        let email_lower = email.to_lowercase();
        return admin_emails
            .split(',')
            .map(|e| e.trim().to_lowercase())
            .any(|e| e == email_lower);
    }
    false
}

impl<S, B> Service<ServiceRequest> for AdminGuardService<S>
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
            // --- Bearer token check (machine-to-machine / MCP) ---
            if let Some(auth_header) = req.headers().get("Authorization") {
                if let Ok(auth_str) = auth_header.to_str() {
                    if let Some(bearer) = auth_str.strip_prefix("Bearer ") {
                        let bearer = bearer.to_string();
                        if let Some(storage) = req.app_data::<web::Data<DynStorage>>() {
                            match storage.get_token_by_access_token(&bearer).await {
                                Ok(Some(token)) if token.is_valid() => {
                                    let scopes: Vec<&str> =
                                        token.scope.split_whitespace().collect();
                                    if scopes.contains(&"admin") {
                                        let res = svc.call(req).await?;
                                        return Ok(res.map_into_left_body());
                                    }
                                    // Valid token but no admin scope
                                    let response =
                                        HttpResponse::Forbidden().json(serde_json::json!({
                                            "error": "insufficient_scope",
                                            "error_description": "Token requires 'admin' scope"
                                        }));
                                    return Ok(req.into_response(response).map_into_right_body());
                                }
                                _ => {
                                    let response = HttpResponse::Unauthorized()
                                        .json(serde_json::json!({
                                            "error": "invalid_token",
                                            "error_description": "Bearer token is invalid or expired"
                                        }));
                                    return Ok(req.into_response(response).map_into_right_body());
                                }
                            }
                        }
                    }
                }
            }

            // --- Session cookie check (browser dashboard) ---
            let session = req.get_session();

            let user_id: Option<String> = session.get("user_id").unwrap_or(None);
            if user_id.is_none() {
                let response = HttpResponse::Found()
                    .append_header(("Location", "/auth/login?error=login_required"))
                    .finish();
                return Ok(req.into_response(response).map_into_right_body());
            }

            let role: String = session
                .get("role")
                .unwrap_or(None)
                .unwrap_or_else(|| "user".to_string());
            let username: String = session.get("username").unwrap_or(None).unwrap_or_default();
            let email: String = session.get("email").unwrap_or(None).unwrap_or_default();

            let is_admin = role == "admin" || is_admin_email(&email);

            if !is_admin {
                let redirect_url = std::env::var("OAUTH2_NON_ADMIN_REDIRECT")
                    .unwrap_or_else(|_| "/profile".to_string());
                tracing::warn!(
                    username = %username,
                    email = %email,
                    "Non-admin user attempted to access admin dashboard, redirecting"
                );
                let response = HttpResponse::Found()
                    .append_header(("Location", redirect_url.as_str()))
                    .finish();
                return Ok(req.into_response(response).map_into_right_body());
            }

            let res = svc.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}
