use std::collections::HashMap;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::http::{Request, Response};
use tower::{Layer, Service};

use sanchr_common::config::RequestSizeConfig;

// ---------------------------------------------------------------------------
// Layer
// ---------------------------------------------------------------------------

/// Tower [`Layer`] that rejects gRPC requests whose `content-length` header
/// exceeds a configurable per-RPC or global size limit.
///
/// Rejected requests receive `tonic::Code::ResourceExhausted` without being
/// forwarded to the inner service.
#[derive(Clone, Debug)]
pub struct RequestSizeLayer {
    limits: Arc<RequestSizeLimits>,
}

#[derive(Debug)]
struct RequestSizeLimits {
    max_bytes: usize,
    per_rpc: HashMap<String, usize>,
}

impl RequestSizeLayer {
    pub fn from_config(config: &RequestSizeConfig) -> Self {
        Self {
            limits: Arc::new(RequestSizeLimits {
                max_bytes: config.max_bytes,
                per_rpc: config.per_rpc.clone(),
            }),
        }
    }
}

impl<S> Layer<S> for RequestSizeLayer {
    type Service = RequestSizeService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestSizeService {
            inner,
            limits: Arc::clone(&self.limits),
        }
    }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// Wrapping service produced by [`RequestSizeLayer`].
#[derive(Clone)]
pub struct RequestSizeService<S> {
    inner: S,
    limits: Arc<RequestSizeLimits>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for RequestSizeService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
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
        let rpc_path = req.uri().path().to_string();

        let limit = lookup_limit(&self.limits, &rpc_path);

        // Check the content-length header.
        let content_length: Option<usize> = req
            .headers()
            .get(axum::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());

        if let Some(len) = content_length {
            if len > limit {
                tracing::warn!(
                    rpc_path = %rpc_path,
                    content_length = len,
                    limit = limit,
                    "request body exceeds size limit, rejecting"
                );

                let status = tonic::Status::resource_exhausted("request body exceeds size limit");
                let http_response = status.into_http();
                let (parts, _body) = http_response.into_parts();
                let response = Response::from_parts(parts, ResBody::default());

                return Box::pin(async move { Ok(response) });
            }
        }

        // `clone_inner` pattern: keep `self` ready for subsequent poll_ready
        // calls.
        let mut inner = self.inner.clone();
        std::mem::swap(&mut inner, &mut self.inner);

        Box::pin(async move { inner.call(req).await })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the size limit for a given RPC path by trying multiple key forms
/// against the per-RPC overrides, falling back to the global default.
fn lookup_limit(limits: &RequestSizeLimits, rpc_path: &str) -> usize {
    // 1. Try the full path as-is (e.g. "/sanchr.keys.KeyService/UploadPreKeys")
    if let Some(&v) = limits.per_rpc.get(rpc_path) {
        return v;
    }

    let trimmed = rpc_path.trim_start_matches('/');

    // 2. Try without leading slash (e.g. "sanchr.keys.KeyService/UploadPreKeys")
    if let Some(&v) = limits.per_rpc.get(trimmed) {
        return v;
    }

    // 3. Try short form "ServiceName/MethodName" by stripping the package prefix
    if let Some(slash) = trimmed.find('/') {
        let service_part = &trimmed[..slash];
        let method_part = &trimmed[slash..]; // includes '/'
        if let Some(dot) = service_part.rfind('.') {
            let short_key = format!("{}{}", &service_part[dot + 1..], method_part);
            if let Some(&v) = limits.per_rpc.get(&short_key) {
                return v;
            }
        }
    }

    limits.max_bytes
}
