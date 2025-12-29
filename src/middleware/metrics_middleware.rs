use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use futures::future::LocalBoxFuture;
use std::future::{ready, Ready};
use std::rc::Rc;
use std::time::Instant;

pub struct MetricsMiddleware {
    metrics: crate::metrics::Metrics,
}

impl MetricsMiddleware {
    pub fn new(metrics: crate::metrics::Metrics) -> Self {
        Self { metrics }
    }
}

impl<S, B> Transform<S, ServiceRequest> for MetricsMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = MetricsMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(MetricsMiddlewareService {
            service: Rc::new(service),
            metrics: self.metrics.clone(),
        }))
    }
}

pub struct MetricsMiddlewareService<S> {
    service: Rc<S>,
    metrics: crate::metrics::Metrics,
}

impl<S, B> Service<ServiceRequest> for MetricsMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let start = Instant::now();
        let metrics = self.metrics.clone();
        let svc = self.service.clone();

        let method = req.method().as_str().to_string();

        Box::pin(async move {
            metrics.http_requests_total.inc();

            let res = svc.call(req).await?;

            let status = res.status().as_u16().to_string();
            let route = res
                .request()
                .match_pattern()
                .unwrap_or_else(|| res.request().path().to_string());

            let duration = start.elapsed();
            metrics
                .http_request_duration_seconds
                .observe(duration.as_secs_f64());

            metrics
                .http_requests_total_by_route
                .with_label_values(&[&method, &route, &status])
                .inc();

            metrics
                .http_request_duration_seconds_by_route
                .with_label_values(&[&method, &route, &status])
                .observe(duration.as_secs_f64());

            Ok(res)
        })
    }
}
