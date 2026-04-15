use anyhow::Context;
use axum::extract::State;
use metrics::{counter, describe_counter, describe_gauge, describe_histogram, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::sync::{Arc, OnceLock};

/// Global handle so `init_metrics` is safe to call multiple times (tests).
static METRICS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Install the Prometheus metrics recorder and return a handle for the /metrics endpoint.
///
/// Safe to call multiple times — the recorder is installed only once.
pub fn init_metrics() -> anyhow::Result<PrometheusHandle> {
    if let Some(handle) = METRICS_HANDLE.get() {
        return Ok(handle.clone());
    }

    let handle = PrometheusBuilder::new()
        .install_recorder()
        .context("failed to install Prometheus recorder")?;

    // Register baseline metric descriptions
    describe_counter!(
        "grpc_requests_total",
        "Total gRPC requests by method and status"
    );
    describe_histogram!(
        "grpc_request_duration_seconds",
        "gRPC request duration in seconds"
    );
    describe_counter!("auth_events_total", "Authentication events by type");
    describe_counter!("messages_sent_total", "Total messages sent");
    describe_counter!(
        "messages_pending_total",
        "Total messages queued for offline delivery"
    );
    describe_counter!(
        "device_outbox_enqueued_total",
        "Total durable device-outbox rows enqueued"
    );
    describe_counter!(
        "device_outbox_acked_total",
        "Total durable device-outbox rows acked and deleted"
    );
    describe_counter!(
        "device_outbox_replayed_total",
        "Total durable device-outbox messages replayed during sync"
    );
    describe_counter!(
        "device_outbox_expired_total",
        "Total durable device-outbox rows dropped because the message expired"
    );
    describe_counter!(
        "legacy_device_delivery_total",
        "Total device deliveries routed through the legacy pending-message path"
    );
    describe_histogram!(
        "device_outbox_ack_latency_seconds",
        "Time from message persistence to first device ack"
    );
    describe_counter!(
        "call_events_dropped_total",
        "Total call events dropped because no live device stream was connected"
    );
    describe_gauge!("active_streams", "Number of active bidirectional streams");
    describe_counter!(
        "media_ownership_denied_total",
        "Media access denied because the requesting user does not own the media_id"
    );
    describe_counter!(
        "vault_create_total",
        "Total successful CreateVaultItem RPCs"
    );
    describe_counter!(
        "vault_create_idempotent_hit_total",
        "CreateVaultItem retries that hit an existing (user_id, vault_item_id) row"
    );
    describe_counter!(
        "vault_get_total",
        "Total successful GetVaultItems list RPCs"
    );
    describe_counter!(
        "vault_get_item_total",
        "Total successful GetVaultItem point-read RPCs"
    );
    describe_counter!(
        "vault_delete_total",
        "Total successful DeleteVaultItem RPCs"
    );
    describe_gauge!(
        "vault_orphan_media",
        "Media objects without a backing vault_items or messages row (daily sweep). Gauge, not a counter: Prometheus convention reserves the _total suffix for monotonic counters."
    );
    // Explicitly seed the gauge at 0 so it appears in /metrics output
    // from the very first scrape, not only after the first write. The
    // orphan sweep (spec Section 3.10) is deferred to a follow-up
    // plan, so until that lands this gauge stays pinned at 0. The
    // Prometheus alert `VaultOrphanMediaGrowing` and the Grafana
    // panel "Orphan media objects" both query this metric and will
    // read a flat-zero line until the sweep lands — the zero-line
    // means "sweep has not run yet", NOT "sweep ran and found
    // nothing".
    metrics::gauge!("vault_orphan_media").set(0.0);

    let _ = METRICS_HANDLE.set(handle.clone());
    Ok(METRICS_HANDLE.get().cloned().unwrap_or(handle))
}

// ---------------------------------------------------------------------------
// Per-event recording helpers
// ---------------------------------------------------------------------------

/// Record a completed gRPC request with its method path, HTTP status, and
/// wall-clock duration.
pub fn record_grpc_request(method: &str, status: &str, duration: std::time::Duration) {
    counter!(
        "grpc_requests_total",
        "method" => method.to_string(),
        "status" => status.to_string()
    )
    .increment(1);

    histogram!(
        "grpc_request_duration_seconds",
        "method" => method.to_string()
    )
    .record(duration.as_secs_f64());
}

/// Record an authentication lifecycle event (register, verify_otp, login, …).
pub fn record_auth_event(event_type: &str) {
    counter!("auth_events_total", "type" => event_type.to_string()).increment(1);
}

/// Record a message successfully delivered (stored + routed).
pub fn record_message_sent() {
    counter!("messages_sent_total").increment(1);
}

/// Record a message queued for an offline device.
pub fn record_message_pending() {
    counter!("messages_pending_total").increment(1);
}

pub fn record_device_outbox_enqueued() {
    counter!("device_outbox_enqueued_total").increment(1);
}

pub fn record_device_outbox_acked() {
    counter!("device_outbox_acked_total").increment(1);
}

pub fn record_device_outbox_replayed() {
    counter!("device_outbox_replayed_total").increment(1);
}

pub fn record_device_outbox_expired() {
    counter!("device_outbox_expired_total").increment(1);
}

pub fn record_legacy_device_delivery() {
    counter!("legacy_device_delivery_total").increment(1);
}

pub fn record_device_outbox_ack_latency(duration: std::time::Duration) {
    histogram!("device_outbox_ack_latency_seconds").record(duration.as_secs_f64());
}

/// Record a call event that could not be delivered to a connected device.
pub fn record_call_event_dropped(event_type: &str) {
    counter!(
        "call_events_dropped_total",
        "type" => event_type.to_string()
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// Axum handler
// ---------------------------------------------------------------------------

/// Axum handler that renders the Prometheus text exposition format.
///
/// Mount at `GET /metrics` on the HTTP router.
pub async fn metrics_handler(State(state): State<Arc<crate::server::AppState>>) -> String {
    state.metrics_handle.render()
}
