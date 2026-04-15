use std::task::{Context, Poll};
use std::time::Instant;

use axum::http::{Request, Response};
use tower::{Layer, Service};

use super::metrics::record_grpc_request;

// ---------------------------------------------------------------------------
// Layer
// ---------------------------------------------------------------------------

/// Tower [`Layer`] that records Prometheus metrics for every gRPC request.
///
/// Wrap the Tonic server with this layer to get per-method request counts and
/// latency histograms automatically.
#[derive(Clone, Debug, Default)]
pub struct GrpcMetricsLayer;

impl<S> Layer<S> for GrpcMetricsLayer {
    type Service = GrpcMetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GrpcMetricsService { inner }
    }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// Wrapping service produced by [`GrpcMetricsLayer`].
#[derive(Clone)]
pub struct GrpcMetricsService<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for GrpcMetricsService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        // Capture the gRPC method path (e.g. "/sanchr.auth.AuthService/Login").
        let method = req.uri().path().to_string();
        let start = Instant::now();

        // `clone_inner` pattern: keep `self` ready for subsequent poll_ready calls.
        let mut inner = self.inner.clone();
        std::mem::swap(&mut inner, &mut self.inner);

        Box::pin(async move {
            let response = inner.call(req).await;
            let duration = start.elapsed();

            let status = match &response {
                Ok(resp) => resp.status().as_u16().to_string(),
                Err(_) => "error".to_string(),
            };

            record_grpc_request(&method, &status, duration);
            response
        })
    }
}
