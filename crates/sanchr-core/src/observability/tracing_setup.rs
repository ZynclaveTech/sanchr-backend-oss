use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    trace::{RandomIdGenerator, Sampler, SdkTracerProvider},
    Resource,
};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Initialize the tracing subscriber with OpenTelemetry export.
///
/// - Console output (human-readable) for local dev
/// - OTLP exporter to Jaeger/Tempo if `OTEL_EXPORTER_OTLP_ENDPOINT` is set
///
/// Returns an `OtelGuard` that must be kept alive for the duration of the
/// process. Dropping it flushes and shuts down the OTel tracer provider.
pub fn init_tracing(service_name: &str) -> OtelGuard {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("sanchr=debug,tower_http=debug"));

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(false);

    // Determine OTLP endpoint (respects the standard env var or our custom one)
    let otel_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:4317".to_string());

    let resource = Resource::builder()
        .with_service_name(service_name.to_string())
        .build();

    match opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&otel_endpoint)
        .build()
    {
        Ok(exporter) => {
            let provider = SdkTracerProvider::builder()
                .with_sampler(Sampler::ParentBased(Box::new(Sampler::AlwaysOn)))
                .with_id_generator(RandomIdGenerator::default())
                .with_resource(resource)
                .with_batch_exporter(exporter)
                .build();

            let tracer = provider.tracer(service_name.to_string());
            let otel_layer = OpenTelemetryLayer::new(tracer);

            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .with(otel_layer)
                .init();

            tracing::info!(
                endpoint = %otel_endpoint,
                "OpenTelemetry tracing initialized"
            );

            OtelGuard {
                tracer_provider: Some(provider),
            }
        }
        Err(e) => {
            // Fall back to console-only tracing — no OTel layer
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .init();

            tracing::warn!(
                error = %e,
                "OpenTelemetry init failed, using console-only tracing"
            );

            OtelGuard {
                tracer_provider: None,
            }
        }
    }
}

/// RAII guard that shuts down the OTel tracer provider on drop,
/// flushing any in-flight spans.
pub struct OtelGuard {
    tracer_provider: Option<SdkTracerProvider>,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.tracer_provider.take() {
            if let Err(err) = provider.shutdown() {
                eprintln!("OTel tracer provider shutdown error: {err:?}");
            }
        }
    }
}
