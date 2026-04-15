use std::fs::File;

use a2::{
    Client, ClientConfig, DefaultNotificationBuilder, Endpoint, NotificationBuilder,
    NotificationOptions, Priority, PushType,
};
use anyhow::Context;

use sanchr_common::config::PushConfig;

/// Thin wrapper around the `a2` APNs HTTP/2 client.
///
/// `Client` is internally backed by a `reqwest` connection pool that
/// multiplexes requests over a single HTTP/2 connection, so a single
/// `ApnsSender` instance is safe to share across all request handlers.
pub struct ApnsSender {
    client: Client,
    bundle_id: String,
    /// APNs topic for VoIP pushes: `<bundle-id>.voip`.
    /// PushKit requires this separate topic; using the standard bundle-id topic
    /// for a VoIP push type will result in a `BadTopic` error from APNs.
    voip_topic: String,
}

impl ApnsSender {
    /// Initialise from config. Returns `None` when APNs is not configured
    /// (empty `apns_key_path`), which is treated as "push disabled" rather
    /// than an error so local dev works without credentials.
    pub fn from_config(config: &PushConfig) -> anyhow::Result<Option<Self>> {
        if config.apns_key_path.is_empty() {
            tracing::info!("APNs push disabled: apns_key_path is not configured");
            return Ok(None);
        }

        let endpoint = if config.apns_sandbox {
            Endpoint::Sandbox
        } else {
            Endpoint::Production
        };

        let mut key_file = File::open(&config.apns_key_path)
            .with_context(|| format!("failed to open APNs key file at {}", config.apns_key_path))?;

        let client_config = ClientConfig {
            endpoint,
            ..Default::default()
        };

        let client = Client::token(
            &mut key_file,
            &config.apns_key_id,
            &config.apns_team_id,
            client_config,
        )
        .context("failed to build APNs client from .p8 key")?;

        tracing::info!(
            key_id = %config.apns_key_id,
            team_id = %config.apns_team_id,
            bundle_id = %config.apns_bundle_id,
            sandbox = config.apns_sandbox,
            "APNs client initialised"
        );

        Ok(Some(Self {
            client,
            voip_topic: format!("{}.voip", config.apns_bundle_id),
            bundle_id: config.apns_bundle_id.clone(),
        }))
    }

    /// Send a "new message" push to a single device token.
    ///
    /// This is fire-and-forget from the router's perspective:
    /// - Failures are logged but never propagate to the caller.
    /// - A 410 response means the token is stale; the caller should delete it.
    ///   We log a warning — token cleanup is handled by the next registration
    ///   cycle from the device rather than a synchronous DB write here.
    pub async fn send_message_push(&self, device_token: &str) {
        let options = NotificationOptions {
            apns_topic: Some(self.bundle_id.as_str()),
            ..Default::default()
        };

        // No message preview — content is E2EE and cannot be included.
        // `mutable-content: 1` lets a future NotificationServiceExtension
        // decrypt and update the notification locally on the device.
        let builder = DefaultNotificationBuilder::new()
            .set_title("Sanchr")
            .set_body("New message")
            .set_sound("default")
            .set_mutable_content();

        let payload = builder.build(device_token, options);

        match self.client.send(payload).await {
            Ok(response) => {
                if response.code == 200 {
                    tracing::debug!(
                        token_prefix = &device_token[..8.min(device_token.len())],
                        "APNs push delivered"
                    );
                } else if response.code == 410 {
                    tracing::warn!(
                        token_prefix = &device_token[..8.min(device_token.len())],
                        "APNs push token is no longer valid (410); \
                         it will be cleaned up on next device registration"
                    );
                } else {
                    tracing::warn!(
                        code = response.code,
                        token_prefix = &device_token[..8.min(device_token.len())],
                        "APNs push returned non-200 status"
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    token_prefix = &device_token[..8.min(device_token.len())],
                    "APNs push failed"
                );
            }
        }
    }

    /// Send a silent background push (`content-available: 1`, no alert).
    ///
    /// Used for sealed-sender messages where we cannot reveal sender identity
    /// or content type in the push payload — the device wakes up, syncs via
    /// gRPC, and decides locally whether to surface a notification.
    pub async fn send_silent_push(&self, device_token: &str) {
        let options = NotificationOptions {
            apns_topic: Some(self.bundle_id.as_str()),
            ..Default::default()
        };

        let builder = DefaultNotificationBuilder::new().set_content_available();
        let payload = builder.build(device_token, options);

        match self.client.send(payload).await {
            Ok(response) => {
                if response.code == 200 {
                    tracing::debug!(
                        token_prefix = &device_token[..8.min(device_token.len())],
                        "APNs silent push delivered"
                    );
                } else if response.code == 410 {
                    tracing::warn!(
                        token_prefix = &device_token[..8.min(device_token.len())],
                        "APNs silent push token no longer valid (410)"
                    );
                } else {
                    tracing::warn!(
                        code = response.code,
                        token_prefix = &device_token[..8.min(device_token.len())],
                        "APNs silent push returned non-200 status"
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    token_prefix = &device_token[..8.min(device_token.len())],
                    "APNs silent push failed"
                );
            }
        }
    }

    /// Send a VoIP push (PushKit) to wake an offline device for an incoming call.
    ///
    /// VoIP pushes are high-priority, bypass Do Not Disturb, and are delivered
    /// even when the app is terminated.  iOS invokes
    /// `PKPushRegistryDelegate.didReceiveIncomingPushWith` which MUST call
    /// `CXProvider.reportNewIncomingCall` before returning.
    ///
    /// The payload carries only the metadata needed for CallKit to show the
    /// incoming call UI (call_id, caller_id, call_type).  The encrypted SDP
    /// offer is NOT included here because APNs enforces a 4096-byte payload
    /// limit and encrypted SDP typically exceeds it.  The iOS app fetches the
    /// full offer from the MessageStream (queued in Redis for replay) after
    /// waking up.
    pub async fn send_voip_push(
        &self,
        device_token: &str,
        call_id: &str,
        caller_id: &str,
        call_type: &str,
    ) {
        // VoIP push topic is <bundle-id>.voip
        let options = NotificationOptions {
            apns_topic: Some(self.voip_topic.as_str()),
            apns_push_type: Some(PushType::Voip),
            apns_priority: Some(Priority::High),
            ..Default::default()
        };

        // VoIP payload: content-available wakes the app; custom fields are
        // passed to PKPushRegistryDelegate so CallKit can be reported before
        // returning from the callback.  We use DefaultNotificationBuilder with
        // set_content_available() for the aps envelope, then attach the call
        // metadata as top-level custom keys via add_custom_data.
        let mut payload = DefaultNotificationBuilder::new()
            .set_content_available()
            .build(device_token, options);

        // Each field is inserted as a top-level key alongside "aps".
        // Errors here are only possible if the values fail JSON serialisation,
        // which cannot happen for plain &str values — unwrap is intentional.
        payload
            .add_custom_data("call_id", &call_id)
            .expect("call_id serialisation cannot fail");
        payload
            .add_custom_data("caller_id", &caller_id)
            .expect("caller_id serialisation cannot fail");
        payload
            .add_custom_data("call_type", &call_type)
            .expect("call_type serialisation cannot fail");

        match self.client.send(payload).await {
            Ok(response) => {
                if response.code == 200 {
                    tracing::debug!(
                        token_prefix = &device_token[..8.min(device_token.len())],
                        call_id,
                        "VoIP push delivered"
                    );
                } else if response.code == 410 {
                    tracing::warn!(
                        token_prefix = &device_token[..8.min(device_token.len())],
                        "VoIP push token no longer valid (410)"
                    );
                } else {
                    tracing::warn!(
                        code = response.code,
                        token_prefix = &device_token[..8.min(device_token.len())],
                        "VoIP push returned non-200 status"
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    token_prefix = &device_token[..8.min(device_token.len())],
                    "VoIP push failed"
                );
            }
        }
    }
}
