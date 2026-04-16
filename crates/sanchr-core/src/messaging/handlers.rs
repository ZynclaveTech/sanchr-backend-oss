use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use scylla::response::{PagingState, PagingStateResponse};
use scylla::value::{CqlTimestamp, CqlTimeuuid};
use tonic::Status;
use uuid::Uuid;

use sanchr_common::errors::internal_status;
use sanchr_db::postgres::conversations as pg_conv;
use sanchr_db::postgres::devices as pg_devices;
use sanchr_db::postgres::users as pg_users;
use sanchr_db::redis::privacy_cache;
use sanchr_db::redis::rate_limit;
use sanchr_db::scylla::messages as sc_msg;
use sanchr_db::scylla::outbox as sc_outbox;
use sanchr_db::scylla::pending as sc_pending;
use sanchr_db::scylla::receipts as sc_receipts;
use sanchr_proto::messaging::{
    server_event, AckedMessageRef, Conversation, DeviceMessage, EncryptedEnvelope, MessageEdited,
    Participant, ReceiptUpdate, ServerEvent,
};

use crate::privacy;
use crate::server::AppState;

use super::router;
use super::stream::StreamManager;

fn current_timestamp_millis() -> Result<i64, std::time::SystemTimeError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64)
}

pub const MAX_DEVICE_MESSAGES_PER_SEND: usize = 100;
pub const MAX_MESSAGE_TTL_SECS: i64 = 30 * 24 * 3600;
pub const MAX_ACK_MESSAGES_PER_REQUEST: usize = 500;

fn is_expired(expires_at: Option<CqlTimestamp>, now_ms: i64) -> bool {
    matches!(expires_at, Some(ts) if ts.0 <= now_ms)
}

/// Result of sending a message.
pub struct SendMessageResult {
    pub message_id: String,
    pub server_timestamp: i64,
}

/// Parameters for sending a message.
pub struct SendMessageParams {
    pub sender_id: Uuid,
    pub sender_device: i32,
    pub conversation_id: String,
    pub device_messages: Vec<DeviceMessage>,
    pub content_type: String,
    pub expires_after_secs: i64,
}

/// Send a message to a conversation, store it, and route to recipients.
pub async fn handle_send_message(
    state: &Arc<AppState>,
    stream_mgr: &StreamManager,
    params: SendMessageParams,
) -> Result<SendMessageResult, Status> {
    let sender_id = params.sender_id;

    // ── Rate limit: 60 messages per 60 seconds (unified bucket) ────────
    rate_limit::check_rate_limit(&state.redis, &format!("rate:msg_all:{sender_id}"), 60, 60)
        .await
        .map_err(|_| Status::resource_exhausted("message rate limit exceeded"))?;

    let sender_device = params.sender_device;
    let content_type = &params.content_type;
    let device_messages = params.device_messages;
    let expires_after_secs = params.expires_after_secs;
    let conversation_id: Uuid = params
        .conversation_id
        .parse()
        .map_err(|_| Status::invalid_argument("invalid conversation_id"))?;

    // Verify sender is a participant of the conversation
    let participants = pg_conv::get_conversation_participants(&state.pg_pool, conversation_id)
        .await
        .map_err(|e| internal_status("failed to get participants", e))?;

    if !participants.contains(&sender_id) {
        return Err(Status::permission_denied(
            "not a member of this conversation",
        ));
    }

    if device_messages.is_empty() {
        return Err(Status::invalid_argument(
            "device_messages must contain at least one target device",
        ));
    }
    if device_messages.len() > MAX_DEVICE_MESSAGES_PER_SEND {
        return Err(Status::invalid_argument(format!(
            "device_messages exceeds maximum of {MAX_DEVICE_MESSAGES_PER_SEND}"
        )));
    }
    if expires_after_secs < 0 {
        return Err(Status::invalid_argument(
            "expires_after_secs must be non-negative",
        ));
    }
    if expires_after_secs > MAX_MESSAGE_TTL_SECS {
        return Err(Status::invalid_argument(format!(
            "expires_after_secs exceeds maximum of {MAX_MESSAGE_TTL_SECS}"
        )));
    }

    let storage_ciphertext = device_messages
        .first()
        .map(|dm| dm.ciphertext.clone())
        .unwrap_or_default();

    let participants_set: HashSet<Uuid> = participants.iter().copied().collect();
    let mut seen_targets = HashSet::new();
    let mut parsed_targets = Vec::with_capacity(device_messages.len());
    let mut by_recipient: std::collections::HashMap<Uuid, std::collections::HashSet<i32>> =
        std::collections::HashMap::new();

    for device_message in device_messages {
        let recipient_id: Uuid = device_message
            .recipient_id
            .parse()
            .map_err(|_| Status::invalid_argument("invalid recipient_id in device_message"))?;

        if !participants_set.contains(&recipient_id) {
            return Err(Status::invalid_argument(
                "recipient device target is not a participant in this conversation",
            ));
        }

        if !seen_targets.insert((recipient_id, device_message.device_id)) {
            return Err(Status::invalid_argument(
                "duplicate recipient/device target in device_messages",
            ));
        }

        by_recipient
            .entry(recipient_id)
            .or_default()
            .insert(device_message.device_id);
        parsed_targets.push((recipient_id, device_message));
    }

    // Store (supports_delivery_ack, push_token) per device so we avoid a
    // second DB round-trip when firing push notifications for offline devices.
    let mut device_capabilities: std::collections::HashMap<(Uuid, i32), (bool, Option<String>)> =
        std::collections::HashMap::new();
    for (recipient_id, device_ids) in by_recipient {
        let device_ids: Vec<i32> = device_ids.into_iter().collect();
        let rows = pg_devices::get_devices_by_ids(&state.pg_pool, recipient_id, &device_ids)
            .await
            .map_err(|e| internal_status("failed to validate device targets", e))?;

        for row in rows {
            device_capabilities.insert(
                (recipient_id, row.device_id),
                (row.supports_delivery_ack, row.push_token),
            );
        }
    }

    let mute_states = pg_conv::get_device_conversation_mutes(
        &state.pg_pool,
        conversation_id,
        &parsed_targets
            .iter()
            .map(|(recipient_id, device_message)| (*recipient_id, device_message.device_id))
            .collect::<Vec<_>>(),
    )
    .await
    .map_err(|e| internal_status("failed to load device conversation notification prefs", e))?;

    let mut validated_targets = Vec::with_capacity(parsed_targets.len());
    for (recipient_id, device_message) in parsed_targets {
        let Some((supports_delivery_ack, push_token)) = device_capabilities
            .get(&(recipient_id, device_message.device_id))
            .cloned()
        else {
            return Err(Status::invalid_argument(
                "device target does not belong to the specified recipient",
            ));
        };

        validated_targets.push(router::ValidatedDeviceMessage {
            recipient_id,
            device_id: device_message.device_id,
            ciphertext: device_message.ciphertext,
            supports_delivery_ack,
            push_token,
            notifications_muted: mute_states
                .get(&(recipient_id, device_message.device_id))
                .copied()
                .unwrap_or(false),
        });
    }

    // Phase 2 block enforcement: silent-drop 1:1 messages when the recipient
    // blocks the sender. Group conversations are deliberately left to
    // client-side filtering per Signal's model — server-side group block
    // enforcement requires per-member delivery gates out of Phase 2 scope.
    //
    // "Silent drop" means the sender observes a successful `SendMessageResult`
    // indistinguishable from a real delivery (same shape, same-looking
    // message_id + timestamp), but the server performs no storage and no
    // routing. This prevents senders from probing recipient block state via
    // timing, error codes, or ack behavior.
    if participants.len() == 2 {
        if let Some(recipient_id) = participants.iter().copied().find(|p| *p != sender_id) {
            let recipient_flags =
                privacy_cache::get_privacy_flags(&state.redis, &state.pg_pool, recipient_id)
                    .await
                    .map_err(|e| internal_status("privacy cache", e))?;

            if recipient_flags.is_blocking(&sender_id.to_string()) {
                tracing::info!(
                    sender_id = %sender_id,
                    recipient_id = %recipient_id,
                    conversation_id = %conversation_id,
                    "silent_drop: recipient blocks sender"
                );

                // Produce a response indistinguishable from a real success.
                // We generate a fresh timeuuid + timestamp here so the sender
                // cannot correlate the returned id against any server-side
                // log of a stored message (there is no stored message).
                let server_ts =
                    current_timestamp_millis().map_err(|e| internal_status("clock error", e))?;
                let dropped_msg_uuid = sanchr_common::new_timeuuid();
                return Ok(SendMessageResult {
                    message_id: dropped_msg_uuid.to_string(),
                    server_timestamp: server_ts,
                });
            }
        }
    }

    // Generate message ID (TIMEUUID / UUID v1) and timestamp
    let server_ts = current_timestamp_millis().map_err(|e| internal_status("clock error", e))?;
    // Use UUID v7 (time-ordered) which is compatible with ScyllaDB TIMEUUID columns
    let msg_uuid = sanchr_common::new_timeuuid();
    let message_id = CqlTimeuuid::from(msg_uuid);

    // Compute optional expiration timestamp from caller-supplied TTL
    let expires_at = if expires_after_secs > 0 {
        let ttl_millis = expires_after_secs
            .checked_mul(1000)
            .ok_or_else(|| Status::invalid_argument("expires_after_secs is too large"))?;
        Some(
            server_ts
                .checked_add(ttl_millis)
                .ok_or_else(|| Status::invalid_argument("expires_after_secs overflows"))?,
        )
    } else {
        None
    };

    // Store in ScyllaDB
    sc_msg::insert_message(
        &state.scylla,
        &sc_msg::InsertMessageParams {
            conversation_id,
            message_id,
            sender_id,
            sender_device,
            ciphertext: &storage_ciphertext,
            content_type,
            expires_at,
        },
    )
    .await
    .map_err(|e| internal_status("failed to store message", e))?;

    // Route to recipient devices
    router::route_message(
        state,
        stream_mgr,
        router::RouteMessageParams {
            conversation_id,
            message_id,
            sender_id,
            sender_device,
            device_messages: validated_targets,
            content_type,
            server_ts,
            expires_at,
        },
    )
    .await?;

    // Increment unread counts for all participants except the sender in one statement.
    let _ = pg_conv::increment_unread_for_other_participants(
        &state.pg_pool,
        conversation_id,
        sender_id,
    )
    .await;
    if let Err(error) = pg_conv::touch_conversation(&state.pg_pool, conversation_id).await {
        tracing::warn!(
            error = %error,
            %conversation_id,
            "failed to touch conversation after message send"
        );
    }

    crate::observability::metrics::record_message_sent();

    Ok(SendMessageResult {
        message_id: Uuid::from(message_id).to_string(),
        server_timestamp: server_ts,
    })
}

/// Drain pending messages for an offline device, returning them as envelopes.
pub async fn handle_sync_messages(
    state: &Arc<AppState>,
    user_id: Uuid,
    device_id: i32,
) -> Result<Vec<EncryptedEnvelope>, Status> {
    let mut envelopes = Vec::new();
    stream_sync_message_pages(state, user_id, device_id, |page| {
        envelopes.extend(page);
        std::future::ready(Ok(()))
    })
    .await?;
    Ok(envelopes)
}

pub async fn stream_sync_message_pages<F, Fut>(
    state: &Arc<AppState>,
    user_id: Uuid,
    device_id: i32,
    mut on_page: F,
) -> Result<(), Status>
where
    F: FnMut(Vec<EncryptedEnvelope>) -> Fut,
    Fut: Future<Output = Result<(), Status>>,
{
    let device = pg_devices::get_device(&state.pg_pool, user_id, device_id)
        .await
        .map_err(|e| internal_status("failed to load device", e))?
        .ok_or_else(|| Status::unauthenticated("device not registered"))?;

    let now_ms = current_timestamp_millis().map_err(|e| internal_status("clock error", e))?;

    if device.supports_delivery_ack {
        let mut paging_state = PagingState::start();
        loop {
            let (outbox, paging_state_response) = sc_outbox::get_outbox_messages_page(
                &state.scylla,
                user_id,
                device_id,
                paging_state,
            )
            .await
            .map_err(|e| internal_status("failed to load device outbox", e))?;

            let mut envelopes = Vec::with_capacity(outbox.len());
            for row in outbox {
                if is_expired(row.expires_at, now_ms) {
                    let _ = sc_outbox::delete_outbox_message(
                        &state.scylla,
                        user_id,
                        device_id,
                        row.message_id,
                    )
                    .await;
                    crate::observability::metrics::record_device_outbox_expired();
                    continue;
                }

                // Defensive filter: a nil sender UUID on a non-sealed row indicates a
                // corrupted or malformed outbox entry that cannot be decrypted by any
                // client path. Legitimate sealed-sender messages carry content_type =
                // "sealed" with nil sender UUID as a deliberate sentinel — those must
                // pass through unchanged. Only rows with nil UUID + wrong content_type
                // are garbage; delete them now so they never reach the client.
                if row.sender_id.is_nil() && row.content_type != "sealed" {
                    tracing::warn!(
                        %user_id,
                        device_id,
                        message_id = %Uuid::from(row.message_id),
                        content_type = %row.content_type,
                        "dropping malformed outbox row: nil sender_id on non-sealed content"
                    );
                    let _ = sc_outbox::delete_outbox_message(
                        &state.scylla,
                        user_id,
                        device_id,
                        row.message_id,
                    )
                    .await;
                    continue;
                }

                crate::observability::metrics::record_device_outbox_replayed();
                envelopes.push(EncryptedEnvelope {
                    conversation_id: row.conversation_id.to_string(),
                    message_id: Uuid::from(row.message_id).to_string(),
                    sender_id: row.sender_id.to_string(),
                    sender_device: row.sender_device,
                    ciphertext: row.ciphertext,
                    content_type: row.content_type,
                    server_timestamp: row.server_ts.0,
                });
            }

            if !envelopes.is_empty() {
                on_page(envelopes).await?;
            }

            match paging_state_response {
                PagingStateResponse::HasMorePages { state } => paging_state = state,
                PagingStateResponse::NoMorePages => break,
            }
        }

        return Ok(());
    }

    let mut paging_state = PagingState::start();
    loop {
        let (pending, paging_state_response) =
            sc_pending::get_pending_messages_page(&state.scylla, user_id, device_id, paging_state)
                .await
                .map_err(|e| internal_status("failed to drain pending", e))?;

        let envelopes: Vec<EncryptedEnvelope> = pending
            .into_iter()
            .map(|row| EncryptedEnvelope {
                conversation_id: row.conversation_id.to_string(),
                message_id: Uuid::from(row.message_id).to_string(),
                sender_id: row.sender_id.to_string(),
                sender_device: 0, // not stored in pending table
                ciphertext: row.ciphertext,
                content_type: row.content_type,
                server_timestamp: row.server_ts.0,
            })
            .collect();

        if !envelopes.is_empty() {
            on_page(envelopes).await?;
        }

        match paging_state_response {
            PagingStateResponse::HasMorePages { state } => paging_state = state,
            PagingStateResponse::NoMorePages => break,
        }
    }

    Ok(())
}

pub async fn handle_ack_messages(
    state: &Arc<AppState>,
    stream_mgr: &StreamManager,
    user_id: Uuid,
    device_id: i32,
    acked_messages: Vec<AckedMessageRef>,
) -> Result<(), Status> {
    if acked_messages.len() > MAX_ACK_MESSAGES_PER_REQUEST {
        return Err(Status::invalid_argument(format!(
            "messages exceeds maximum of {MAX_ACK_MESSAGES_PER_REQUEST}"
        )));
    }

    let mut seen = HashSet::new();
    let mut parsed_acks = Vec::with_capacity(acked_messages.len());

    for ack in acked_messages {
        let conversation_id: Uuid = match ack.conversation_id.parse() {
            Ok(id) => id,
            Err(_) => {
                // Skip malformed acks rather than crashing the entire RPC — a bad entry
                // in the client's pending-ack queue must never block the message stream.
                tracing::warn!(
                    conversation_id = %ack.conversation_id,
                    message_id = %ack.message_id,
                    "skipping ack with invalid conversation_id"
                );
                continue;
            }
        };
        let message_uuid: Uuid = match ack.message_id.parse() {
            Ok(id) => id,
            Err(_) => {
                tracing::warn!(
                    conversation_id = %ack.conversation_id,
                    message_id = %ack.message_id,
                    "skipping ack with invalid message_id"
                );
                continue;
            }
        };
        let message_id = CqlTimeuuid::from(message_uuid);

        if !seen.insert((conversation_id, message_id)) {
            continue;
        }

        parsed_acks.push((conversation_id, message_uuid, message_id));
    }

    let message_ids: Vec<CqlTimeuuid> = parsed_acks
        .iter()
        .map(|(_, _, message_id)| *message_id)
        .collect();

    sc_outbox::delete_outbox_messages(&state.scylla, user_id, device_id, &message_ids)
        .await
        .map_err(|e| internal_status("failed to delete device outbox rows", e))?;

    // Legacy fallback path: clear pending rows on ack as well. This keeps sync
    // non-destructive and prevents loss on interrupted sync streams.
    let _ =
        sc_pending::delete_pending_messages(&state.scylla, user_id, device_id, &message_ids).await;

    for (conversation_id, message_uuid, message_id) in parsed_acks {
        crate::observability::metrics::record_device_outbox_acked();

        let Some(message) = sc_msg::get_message(&state.scylla, conversation_id, message_id)
            .await
            .map_err(|e| internal_status("failed to fetch message for ack", e))?
        else {
            continue;
        };

        if let Some(existing) =
            sc_receipts::get_receipt(&state.scylla, conversation_id, message_id, user_id)
                .await
                .map_err(|e| internal_status("failed to fetch receipt state", e))?
        {
            if existing.status == "read" || existing.status == "delivered" {
                continue;
            }
        }

        sc_receipts::upsert_receipt(
            &state.scylla,
            conversation_id,
            message_id,
            user_id,
            "delivered",
        )
        .await
        .map_err(|e| internal_status("failed to store delivered receipt", e))?;

        let ack_timestamp =
            current_timestamp_millis().map_err(|e| internal_status("clock error", e))?;
        crate::observability::metrics::record_device_outbox_ack_latency(
            std::time::Duration::from_millis((ack_timestamp - message.server_ts.0).max(0) as u64),
        );

        let receipt_update = ReceiptUpdate {
            conversation_id: conversation_id.to_string(),
            message_id: message_uuid.to_string(),
            recipient_id: user_id.to_string(),
            status: "delivered".to_string(),
            timestamp: ack_timestamp,
        };

        let event = ServerEvent {
            event: Some(server_event::Event::Receipt(receipt_update)),
        };

        let _ = stream_mgr
            .send_to_user(&message.sender_id.to_string(), event)
            .await;
    }

    Ok(())
}

/// Soft-delete a message.
pub async fn handle_delete_message(
    state: &Arc<AppState>,
    requester_id: Uuid,
    conversation_id_str: &str,
    message_id_str: &str,
) -> Result<(), Status> {
    let conversation_id: Uuid = conversation_id_str
        .parse()
        .map_err(|_| Status::invalid_argument("invalid conversation_id"))?;

    let message_uuid: Uuid = message_id_str
        .parse()
        .map_err(|_| Status::invalid_argument("invalid message_id"))?;

    let message_id = CqlTimeuuid::from(message_uuid);

    let message = sc_msg::get_message(&state.scylla, conversation_id, message_id)
        .await
        .map_err(|e| internal_status("failed to fetch message", e))?
        .ok_or_else(|| Status::not_found("message not found"))?;

    if message.sender_id != requester_id {
        return Err(Status::permission_denied(
            "only the original sender can delete this message",
        ));
    }

    sc_msg::delete_message(&state.scylla, conversation_id, message_id)
        .await
        .map_err(|e| internal_status("failed to delete message", e))?;

    Ok(())
}

/// Start or retrieve a direct conversation between two users.
pub async fn handle_start_direct_conversation(
    state: &Arc<AppState>,
    caller_id: Uuid,
    recipient_id_str: &str,
) -> Result<Conversation, Status> {
    let recipient_id: Uuid = recipient_id_str
        .parse()
        .map_err(|_| Status::invalid_argument("invalid recipient_id"))?;

    if caller_id == recipient_id {
        return Err(Status::invalid_argument(
            "cannot start conversation with yourself",
        ));
    }

    let conv = pg_conv::find_or_create_direct(&state.pg_pool, caller_id, recipient_id)
        .await
        .map_err(|e| internal_status("failed to create conversation", e))?;

    let participant_ids = pg_conv::get_conversation_participants(&state.pg_pool, conv.id)
        .await
        .unwrap_or_default();

    let user_rows = pg_users::find_by_ids(&state.pg_pool, &participant_ids)
        .await
        .unwrap_or_default();
    let user_map: std::collections::HashMap<Uuid, _> =
        user_rows.into_iter().map(|u| (u.id, u)).collect();

    // Phase 2 avatar visibility enforcement: for every participant other than
    // the caller, consult the owner's profile_photo_visibility flag (and the
    // mutual-contact graph for the "contacts" branch). The caller always sees
    // their own avatar, so we skip the privacy_cache hit on that row.
    let mut participant_protos: Vec<Participant> = Vec::with_capacity(participant_ids.len());
    for pid in &participant_ids {
        let pid = *pid;
        if let Some(user) = user_map.get(&pid) {
            let avatar_url = if pid == caller_id {
                user.avatar_url.clone().unwrap_or_default()
            } else {
                let flags = privacy_cache::get_privacy_flags(&state.redis, &state.pg_pool, pid)
                    .await
                    .map_err(|e| internal_status("privacy cache", e))?;
                privacy::avatar::filter_avatar_url(
                    &state.pg_pool,
                    &flags.profile_photo_visibility,
                    pid,
                    caller_id,
                    user.avatar_url.clone(),
                )
                .await
            };
            participant_protos.push(Participant {
                user_id: pid.to_string(),
                display_name: user.display_name.clone(),
                avatar_url,
            });
        } else {
            participant_protos.push(Participant {
                user_id: pid.to_string(),
                display_name: String::new(),
                avatar_url: String::new(),
            });
        }
    }

    Ok(Conversation {
        id: conv.id.to_string(),
        r#type: conv.type_.clone(),
        participant_ids: participant_ids.iter().map(|p| p.to_string()).collect(),
        unread_count: 0,
        participants: participant_protos,
    })
}

/// Get all conversations for a user.
pub async fn handle_get_conversations(
    state: &Arc<AppState>,
    user_id: Uuid,
) -> Result<Vec<Conversation>, Status> {
    let rows = pg_conv::get_user_conversations(&state.pg_pool, user_id)
        .await
        .map_err(|e| internal_status("failed to get conversations", e))?;

    let conversation_ids: Vec<Uuid> = rows.iter().map(|row| row.id).collect();

    // Batch-fetch participants for all conversations (removes N+1 query pattern).
    let participant_rows =
        pg_conv::get_participants_for_conversations(&state.pg_pool, &conversation_ids)
            .await
            .map_err(|e| internal_status("failed to load conversation participants", e))?;

    let mut participants_by_conversation: std::collections::HashMap<Uuid, Vec<Uuid>> =
        std::collections::HashMap::new();
    let mut all_participant_ids: Vec<Uuid> = Vec::new();

    for (conversation_id, participant_id) in participant_rows {
        participants_by_conversation
            .entry(conversation_id)
            .or_default()
            .push(participant_id);
        all_participant_ids.push(participant_id);
    }

    // Batch-fetch all user profiles in one query
    all_participant_ids.sort();
    all_participant_ids.dedup();
    let user_rows = pg_users::find_by_ids(&state.pg_pool, &all_participant_ids)
        .await
        .map_err(|e| internal_status("failed to load participant profiles", e))?;
    let user_map: std::collections::HashMap<Uuid, _> =
        user_rows.into_iter().map(|u| (u.id, u)).collect();

    // Phase 2 avatar visibility enforcement: cache PrivacyFlags lookups across
    // the whole response so that a user who appears in multiple conversations
    // (e.g. group + DM with the same person) only triggers one Redis/Postgres
    // round trip per call. The cache is intentionally per-request — long-lived
    // caching lives in privacy_cache itself.
    let mut flags_cache: std::collections::HashMap<Uuid, privacy_cache::PrivacyFlags> =
        std::collections::HashMap::new();

    let mut conversations = Vec::with_capacity(rows.len());
    for row in &rows {
        let participants = participants_by_conversation
            .get(&row.id)
            .cloned()
            .unwrap_or_default();
        let mut participant_protos: Vec<Participant> = Vec::with_capacity(participants.len());
        for pid in &participants {
            let pid = *pid;
            if let Some(user) = user_map.get(&pid) {
                let avatar_url = if pid == user_id {
                    user.avatar_url.clone().unwrap_or_default()
                } else {
                    let flags = match flags_cache.get(&pid) {
                        Some(f) => f.clone(),
                        None => {
                            let f =
                                privacy_cache::get_privacy_flags(&state.redis, &state.pg_pool, pid)
                                    .await
                                    .map_err(|e| internal_status("privacy cache", e))?;
                            flags_cache.insert(pid, f.clone());
                            f
                        }
                    };
                    privacy::avatar::filter_avatar_url(
                        &state.pg_pool,
                        &flags.profile_photo_visibility,
                        pid,
                        user_id,
                        user.avatar_url.clone(),
                    )
                    .await
                };
                participant_protos.push(Participant {
                    user_id: pid.to_string(),
                    display_name: user.display_name.clone(),
                    avatar_url,
                });
            } else {
                participant_protos.push(Participant {
                    user_id: pid.to_string(),
                    display_name: String::new(),
                    avatar_url: String::new(),
                });
            }
        }

        conversations.push(Conversation {
            id: row.id.to_string(),
            r#type: row.type_.clone(),
            participant_ids: participants.iter().map(|p| p.to_string()).collect(),
            unread_count: row.unread_count.unwrap_or(0),
            participants: participant_protos,
        });
    }

    Ok(conversations)
}

/// Result of editing a message.
pub struct EditMessageResult {
    pub edited_at: i64,
}

/// Parameters for editing a message.
pub struct EditMessageParams {
    pub editor_id: Uuid,
    pub editor_device: i32,
    pub conversation_id: String,
    pub message_id: String,
    pub device_messages: Vec<DeviceMessage>,
}

/// Edit a previously sent message.
///
/// Validates that the caller is the original sender, updates the storage
/// ciphertext in ScyllaDB, and pushes a `MessageEdited` event to all
/// currently-connected devices in the conversation.  Offline devices receive
/// the updated ciphertext the next time they call `SyncMessages`.
pub async fn handle_edit_message(
    state: &Arc<AppState>,
    stream_mgr: &StreamManager,
    params: EditMessageParams,
) -> Result<EditMessageResult, Status> {
    let editor_id = params.editor_id;

    // ── Rate limit: shared message production bucket ───────────────────
    rate_limit::check_rate_limit(&state.redis, &format!("rate:msg_all:{editor_id}"), 60, 60)
        .await
        .map_err(|_| Status::resource_exhausted("message rate limit exceeded"))?;

    let conversation_id: Uuid = params
        .conversation_id
        .parse()
        .map_err(|_| Status::invalid_argument("invalid conversation_id"))?;
    let message_uuid: Uuid = params
        .message_id
        .parse()
        .map_err(|_| Status::invalid_argument("invalid message_id"))?;
    let message_id = CqlTimeuuid::from(message_uuid);

    if params.device_messages.is_empty() {
        return Err(Status::invalid_argument(
            "device_messages must contain at least one target device",
        ));
    }
    if params.device_messages.len() > MAX_DEVICE_MESSAGES_PER_SEND {
        return Err(Status::invalid_argument(format!(
            "device_messages exceeds maximum of {MAX_DEVICE_MESSAGES_PER_SEND}"
        )));
    }

    // Verify editor is a participant.
    let participants = pg_conv::get_conversation_participants(&state.pg_pool, conversation_id)
        .await
        .map_err(|e| internal_status("failed to get participants", e))?;

    if !participants.contains(&editor_id) {
        return Err(Status::permission_denied(
            "not a member of this conversation",
        ));
    }

    let participants_set: HashSet<Uuid> = participants.iter().copied().collect();

    // Validate device_message targets.
    let mut seen_targets = HashSet::new();
    let mut validated_device_targets = Vec::with_capacity(params.device_messages.len());
    for dm in &params.device_messages {
        let recipient_id: Uuid = dm
            .recipient_id
            .parse()
            .map_err(|_| Status::invalid_argument("invalid recipient_id in device_message"))?;
        if !participants_set.contains(&recipient_id) {
            return Err(Status::invalid_argument(
                "recipient device target is not a participant in this conversation",
            ));
        }
        if !seen_targets.insert((recipient_id, dm.device_id)) {
            return Err(Status::invalid_argument(
                "duplicate recipient/device target in device_messages",
            ));
        }

        validated_device_targets.push((recipient_id, dm));
    }

    // Fetch and validate ownership.
    let message = sc_msg::get_message(&state.scylla, conversation_id, message_id)
        .await
        .map_err(|e| internal_status("failed to fetch message", e))?
        .ok_or_else(|| Status::not_found("message not found"))?;

    if message.sender_id != editor_id {
        return Err(Status::permission_denied(
            "only the original sender can edit this message",
        ));
    }

    if message.is_deleted {
        return Err(Status::failed_precondition("cannot edit a deleted message"));
    }

    // Storage ciphertext: first device's ciphertext (same convention as
    // insert_message, used for SyncMessages replay).
    let storage_ciphertext = params
        .device_messages
        .first()
        .map(|dm| dm.ciphertext.clone())
        .unwrap_or_default();

    let edited_at = current_timestamp_millis().map_err(|e| internal_status("clock error", e))?;

    // Persist the edit.
    sc_msg::edit_message(
        &state.scylla,
        conversation_id,
        message_id,
        &storage_ciphertext,
        edited_at,
    )
    .await
    .map_err(|e| internal_status("failed to store message edit", e))?;

    // Fan-out per-device MessageEdited events to connected devices.
    for (recipient_id, dm) in &validated_device_targets {
        let event = ServerEvent {
            event: Some(server_event::Event::MessageEdited(MessageEdited {
                conversation_id: conversation_id.to_string(),
                message_id: message_uuid.to_string(),
                sender_id: editor_id.to_string(),
                ciphertext: dm.ciphertext.clone(),
                edited_at,
            })),
        };
        let _ = stream_mgr
            .send_to(&recipient_id.to_string(), dm.device_id, event)
            .await;
    }

    // Also notify the editor's own other devices (multi-device sync) using the
    // storage ciphertext since they share the same key material.
    let editor_devices = pg_devices::list_user_devices(&state.pg_pool, editor_id)
        .await
        .unwrap_or_default();

    for device in editor_devices {
        if device.device_id == params.editor_device {
            continue; // skip the originating device
        }
        // Check that this device wasn't already targeted in device_messages.
        if seen_targets.contains(&(editor_id, device.device_id)) {
            continue;
        }
        let event = ServerEvent {
            event: Some(server_event::Event::MessageEdited(MessageEdited {
                conversation_id: conversation_id.to_string(),
                message_id: message_uuid.to_string(),
                sender_id: editor_id.to_string(),
                ciphertext: storage_ciphertext.clone(),
                edited_at,
            })),
        };
        let _ = stream_mgr
            .send_to(&editor_id.to_string(), device.device_id, event)
            .await;
    }

    Ok(EditMessageResult { edited_at })
}

pub async fn handle_delete_conversation(
    state: &Arc<AppState>,
    user_id: Uuid,
    conversation_id_str: &str,
) -> Result<bool, Status> {
    let conversation_id: Uuid = conversation_id_str
        .parse()
        .map_err(|_| Status::invalid_argument("invalid conversation_id"))?;

    let participants = pg_conv::get_conversation_participants(&state.pg_pool, conversation_id)
        .await
        .map_err(|e| internal_status("failed to get participants", e))?;

    if !participants.contains(&user_id) {
        return Err(Status::permission_denied(
            "not a member of this conversation",
        ));
    }

    let deleted = pg_conv::delete_participant(&state.pg_pool, conversation_id, user_id)
        .await
        .map_err(|e| internal_status("failed to delete conversation", e))?;

    Ok(deleted)
}
