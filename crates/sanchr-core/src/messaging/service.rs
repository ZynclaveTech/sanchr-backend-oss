use std::pin::Pin;
use std::sync::Arc;

use base64::Engine;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

use sanchr_common::errors::internal_status;
use sanchr_db::redis::call_events;
use sanchr_db::redis::rate_limit;
use sanchr_proto::messaging::messaging_service_server::MessagingService;
use sanchr_proto::messaging::{
    client_event, server_event, AckMessagesRequest, AckMessagesResponse, Conversation,
    DeleteConversationRequest, DeleteConversationResponse, DeleteMessageRequest,
    DeleteMessageResponse, DeliveryTokenRequest, DeliveryTokenResponse, EditMessageRequest,
    EditMessageResponse, EncryptedEnvelope, GetConversationsRequest, GetConversationsResponse,
    Reaction, ReceiptRequest, ReceiptResponse, SealedInboundMessage, SendMessageRequest,
    SendMessageResponse, SendSealedMessageRequest, SendSealedMessageResponse,
    SenderCertificateRequest, SenderCertificateResponse, ServerEvent,
    StartDirectConversationRequest, SyncRequest,
};

use crate::middleware::auth;
use crate::presence;
use crate::server::AppState;

use super::handlers;
use super::reaction_handler;
use super::sealed_handler;
use super::stream::StreamManager;

const NIL_UUID_STR: &str = "00000000-0000-0000-0000-000000000000";

fn replay_event_from_envelope(envelope: EncryptedEnvelope) -> ServerEvent {
    let is_sealed = envelope.content_type == "sealed"
        || (envelope.sender_id == NIL_UUID_STR && envelope.sender_device == 0);

    if is_sealed {
        return ServerEvent {
            event: Some(server_event::Event::SealedMessage(SealedInboundMessage {
                sealed_envelope: envelope.ciphertext,
                server_timestamp: envelope.server_timestamp,
                message_id: envelope.message_id,
            })),
        };
    }

    ServerEvent {
        event: Some(server_event::Event::Message(envelope)),
    }
}

pub struct MessagingServiceImpl {
    pub state: Arc<AppState>,
    pub stream_mgr: Arc<StreamManager>,
}

#[tonic::async_trait]
impl MessagingService for MessagingServiceImpl {
    async fn send_message(
        &self,
        request: Request<SendMessageRequest>,
    ) -> Result<Response<SendMessageResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;

        // Optional idempotency support for client retries.
        let idempotency_key = request
            .metadata()
            .get("x-idempotency-key")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| v.to_string());

        let req = request.into_inner();

        if let Some(ref key) = idempotency_key {
            let scope = format!("msg:{}:{}", user.user_id, user.device_id);

            if let Some(cached) =
                sanchr_db::redis::idempotency::get_cached_result(&self.state.redis, &scope, key)
                    .await
                    .map_err(|e| internal_status("failed to read idempotency cache", e))?
            {
                let mut parts = cached.splitn(2, ':');
                if let (Some(message_id), Some(server_ts)) = (parts.next(), parts.next()) {
                    if let Ok(server_timestamp) = server_ts.parse::<i64>() {
                        return Ok(Response::new(SendMessageResponse {
                            message_id: message_id.to_string(),
                            server_timestamp,
                        }));
                    }
                }
            }

            let locked =
                sanchr_db::redis::idempotency::try_acquire_lock(&self.state.redis, &scope, key, 30)
                    .await
                    .map_err(|e| internal_status("failed to acquire idempotency lock", e))?;

            if !locked {
                // Another in-flight attempt owns the lock; return a retryable conflict.
                return Err(Status::aborted("duplicate in-flight request"));
            }

            let send_result = handlers::handle_send_message(
                &self.state,
                &self.stream_mgr,
                handlers::SendMessageParams {
                    sender_id: user.user_id,
                    sender_device: user.device_id,
                    conversation_id: req.conversation_id,
                    device_messages: req.device_messages,
                    content_type: req.content_type,
                    expires_after_secs: req.expires_after_secs,
                },
            )
            .await;

            match send_result {
                Ok(result) => {
                    let response = SendMessageResponse {
                        message_id: result.message_id,
                        server_timestamp: result.server_timestamp,
                    };
                    let encoded = format!("{}:{}", response.message_id, response.server_timestamp);
                    let _ = sanchr_db::redis::idempotency::store_result_and_release_lock(
                        &self.state.redis,
                        &scope,
                        key,
                        &encoded,
                        86_400,
                    )
                    .await;
                    Ok(Response::new(response))
                }
                Err(error) => {
                    let _ =
                        sanchr_db::redis::idempotency::release_lock(&self.state.redis, &scope, key)
                            .await;
                    Err(error)
                }
            }
        } else {
            let result = handlers::handle_send_message(
                &self.state,
                &self.stream_mgr,
                handlers::SendMessageParams {
                    sender_id: user.user_id,
                    sender_device: user.device_id,
                    conversation_id: req.conversation_id,
                    device_messages: req.device_messages,
                    content_type: req.content_type,
                    expires_after_secs: req.expires_after_secs,
                },
            )
            .await?;

            Ok(Response::new(SendMessageResponse {
                message_id: result.message_id,
                server_timestamp: result.server_timestamp,
            }))
        }
    }

    async fn start_direct_conversation(
        &self,
        request: Request<StartDirectConversationRequest>,
    ) -> Result<Response<Conversation>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        let conversation = handlers::handle_start_direct_conversation(
            &self.state,
            user.user_id,
            &req.recipient_id,
        )
        .await?;

        Ok(Response::new(conversation))
    }

    type MessageStreamStream =
        Pin<Box<dyn Stream<Item = Result<ServerEvent, Status>> + Send + 'static>>;

    async fn message_stream(
        &self,
        request: Request<Streaming<sanchr_proto::messaging::ClientEvent>>,
    ) -> Result<Response<Self::MessageStreamStream>, Status> {
        // Authenticate using metadata before consuming the request, because
        // Streaming<T> is not Send and cannot be held across .await in authenticate.
        let user = auth::authenticate_metadata(&self.state, request.metadata()).await?;

        let user_id_str = user.user_id.to_string();
        let device_id = user.device_id;

        // Register the stream and get receiver
        let rx = self.stream_mgr.register(&user_id_str, device_id).await;

        // Drain pending messages and send them through a forwarding channel
        let (forward_tx, forward_rx) = mpsc::channel::<Result<ServerEvent, Status>>(256);

        let user_id = user.user_id;

        // Send pending messages first, then replay queued call events.
        let state_clone = Arc::clone(&self.state);
        let forward_tx_pending = forward_tx.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handlers::stream_sync_message_pages(&state_clone, user_id, device_id, |envelopes| {
                    let forward_tx_pending = forward_tx_pending.clone();
                    async move {
                        for envelope in envelopes {
                            let event = replay_event_from_envelope(envelope);
                            if forward_tx_pending.send(Ok(event)).await.is_err() {
                                return Err(Status::cancelled("message stream closed"));
                            }
                        }
                        Ok(())
                    }
                })
                .await
            {
                tracing::error!(error = %e, "failed to drain pending messages");
            }

            match call_events::peek_call_events(&state_clone.redis, &user_id.to_string()).await {
                Ok(events) => {
                    for event_item in events {
                        match event_item {
                            call_events::CallInboxEvent::Offer {
                                call_id,
                                caller_id,
                                call_type,
                                sdp_offer,
                                srtp_key_params,
                                encrypted_sdp_payload,
                            } => {
                                let sdp_offer = match decode_optional_call_bytes(&sdp_offer) {
                                    Ok(v) => v,
                                    Err(_) => continue,
                                };
                                let srtp_key_params =
                                    match decode_optional_call_bytes(&srtp_key_params) {
                                        Ok(v) => v,
                                        Err(_) => continue,
                                    };
                                let encrypted_sdp_payload =
                                    match decode_optional_call_bytes(&encrypted_sdp_payload) {
                                        Ok(v) => v,
                                        Err(_) => continue,
                                    };
                                let event = ServerEvent {
                                    event: Some(
                                        sanchr_proto::messaging::server_event::Event::CallOffer(
                                            sanchr_proto::messaging::CallOfferEvent {
                                                call_id,
                                                caller_id,
                                                call_type,
                                                sdp_offer,
                                                srtp_key_params,
                                                encrypted_sdp_payload,
                                            },
                                        ),
                                    ),
                                };
                                if forward_tx_pending.send(Ok(event)).await.is_err() {
                                    return;
                                }
                            }
                            call_events::CallInboxEvent::Lifecycle {
                                call_id,
                                peer_id,
                                event_type,
                                actor_id,
                            } => {
                                let event = ServerEvent {
                                    event: Some(
                                        sanchr_proto::messaging::server_event::Event::CallLifecycle(
                                            sanchr_proto::messaging::CallLifecycleEvent {
                                                call_id,
                                                peer_id,
                                                event_type,
                                                actor_id,
                                            },
                                        ),
                                    ),
                                };
                                if forward_tx_pending.send(Ok(event)).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(error = %error, "failed to read call event replay inbox");
                }
            }
        });

        // Forward live events from the stream manager receiver
        let forward_tx_live = forward_tx.clone();
        tokio::spawn(async move {
            let mut rx = rx;
            while let Some(event) = rx.recv().await {
                if forward_tx_live.send(Ok(event)).await.is_err() {
                    break;
                }
            }
        });

        // Handle incoming client events (typing indicators)
        let mut inbound = request.into_inner();
        let state_clone = Arc::clone(&self.state);
        let stream_mgr_clone = Arc::clone(&self.stream_mgr);
        let user_id_for_events = user.user_id;
        let user_id_str_for_cleanup = user_id_str.clone();

        tokio::spawn(async move {
            while let Ok(Some(client_event)) = inbound.message().await {
                match client_event.event {
                    Some(client_event::Event::Typing(typing)) => {
                        // Set/clear typing in Redis and broadcast to participants
                        presence::handlers::handle_typing(
                            &state_clone,
                            &stream_mgr_clone,
                            user_id_for_events,
                            &typing.conversation_id,
                            typing.is_typing,
                        )
                        .await;
                    }
                    Some(client_event::Event::CallEventAck(ack)) => {
                        if ack.call_id.is_empty()
                            || !matches!(ack.kind.as_str(), "offer" | "lifecycle")
                        {
                            tracing::warn!(
                                user_id = %user_id_for_events,
                                call_id = %ack.call_id,
                                kind = %ack.kind,
                                "dropping invalid call event ack"
                            );
                            continue;
                        }
                        match call_events::ack_call_event(
                            &state_clone.redis,
                            &user_id_for_events.to_string(),
                            &ack.call_id,
                            &ack.kind,
                        )
                        .await
                        {
                            Ok(()) => tracing::info!(
                                user_id = %user_id_for_events,
                                call_id = %ack.call_id,
                                kind = %ack.kind,
                                "call event ack applied"
                            ),
                            Err(error) => tracing::warn!(
                                error = %error,
                                user_id = %user_id_for_events,
                                call_id = %ack.call_id,
                                kind = %ack.kind,
                                "failed to apply call event ack"
                            ),
                        }
                    }
                    None => {}
                }
            }

            // Client disconnected - unregister stream
            stream_mgr_clone
                .unregister(&user_id_str_for_cleanup, device_id)
                .await;
            tracing::debug!(
                user_id = %user_id_str_for_cleanup,
                device_id,
                "client disconnected from message stream"
            );
        });

        let output_stream = ReceiverStream::new(forward_rx);
        Ok(Response::new(
            Box::pin(output_stream) as Self::MessageStreamStream
        ))
    }

    type SyncMessagesStream =
        Pin<Box<dyn Stream<Item = Result<EncryptedEnvelope, Status>> + Send + 'static>>;

    async fn sync_messages(
        &self,
        request: Request<SyncRequest>,
    ) -> Result<Response<Self::SyncMessagesStream>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let (tx, rx) = mpsc::channel(256);
        let state = Arc::clone(&self.state);
        let user_id = user.user_id;
        let device_id = user.device_id;

        tokio::spawn(async move {
            let result =
                handlers::stream_sync_message_pages(&state, user_id, device_id, |envelopes| {
                    let tx = tx.clone();
                    async move {
                        for envelope in envelopes {
                            if tx.send(Ok(envelope)).await.is_err() {
                                return Err(Status::cancelled("sync stream closed"));
                            }
                        }
                        Ok(())
                    }
                })
                .await;

            if let Err(error) = result {
                let _ = tx.send(Err(error)).await;
            }
        });

        let stream = ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream) as Self::SyncMessagesStream))
    }

    async fn delete_message(
        &self,
        request: Request<DeleteMessageRequest>,
    ) -> Result<Response<DeleteMessageResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        handlers::handle_delete_message(
            &self.state,
            user.user_id,
            &req.conversation_id,
            &req.message_id,
        )
        .await?;

        Ok(Response::new(DeleteMessageResponse {}))
    }

    async fn edit_message(
        &self,
        request: Request<EditMessageRequest>,
    ) -> Result<Response<EditMessageResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        let result = handlers::handle_edit_message(
            &self.state,
            &self.stream_mgr,
            handlers::EditMessageParams {
                editor_id: user.user_id,
                editor_device: user.device_id,
                conversation_id: req.conversation_id,
                message_id: req.message_id,
                device_messages: req.device_messages,
            },
        )
        .await?;

        Ok(Response::new(EditMessageResponse {
            edited_at: result.edited_at,
        }))
    }

    async fn ack_messages(
        &self,
        request: Request<AckMessagesRequest>,
    ) -> Result<Response<AckMessagesResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        handlers::handle_ack_messages(
            &self.state,
            &self.stream_mgr,
            user.user_id,
            user.device_id,
            req.messages,
        )
        .await?;

        Ok(Response::new(AckMessagesResponse {}))
    }

    async fn send_receipt(
        &self,
        request: Request<ReceiptRequest>,
    ) -> Result<Response<ReceiptResponse>, Status> {
        // Sub-phase 5: read receipts are now sent as sealed-sender envelopes
        // (contentType "receipt/v1") directly between clients. The server
        // cannot read or timestamp them. This RPC is kept in the proto for
        // backward compatibility but is a no-op on the server.
        let _ = request;
        Ok(Response::new(ReceiptResponse {}))
    }

    async fn get_conversations(
        &self,
        request: Request<GetConversationsRequest>,
    ) -> Result<Response<GetConversationsResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;

        let conversations = handlers::handle_get_conversations(&self.state, user.user_id).await?;

        Ok(Response::new(GetConversationsResponse { conversations }))
    }

    async fn send_reaction(
        &self,
        request: Request<Reaction>,
    ) -> Result<Response<Reaction>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let reaction = request.into_inner();

        let result = reaction_handler::handle_send_reaction(
            &self.state,
            &self.stream_mgr,
            user.user_id,
            &reaction,
        )
        .await?;

        Ok(Response::new(result))
    }

    async fn get_sender_certificate(
        &self,
        request: Request<SenderCertificateRequest>,
    ) -> Result<Response<SenderCertificateResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;

        // Fetch the caller's identity public key from the key store.
        let identity_key = sanchr_db::postgres::keys::get_identity_key(
            &self.state.pg_pool,
            user.user_id,
            user.device_id,
        )
        .await
        .map_err(|e| internal_status("failed to fetch identity key", e))?
        .ok_or_else(|| {
            Status::failed_precondition(
                "no identity key uploaded for this device; upload a key bundle first",
            )
        })?;

        let (certificate, expiration) = self
            .state
            .sealed_sender_signer
            .issue_certificate(
                &user.user_id.to_string(),
                user.device_id as u32,
                &identity_key,
            )
            .map_err(|e| internal_status("failed to issue sender certificate", e))?;

        Ok(Response::new(SenderCertificateResponse {
            certificate,
            expiration: expiration as i64,
        }))
    }

    async fn get_delivery_tokens(
        &self,
        request: Request<DeliveryTokenRequest>,
    ) -> Result<Response<DeliveryTokenResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;

        // ── Rate limit: shared message production bucket (60/min) ──────
        rate_limit::check_rate_limit(
            &self.state.redis,
            &format!("rate:msg_all:{}", user.user_id),
            60,
            60,
        )
        .await
        .map_err(|_| Status::resource_exhausted("delivery token rate limit exceeded"))?;

        let req = request.into_inner();

        let tokens =
            sanchr_db::redis::delivery_tokens::issue_tokens(&self.state.redis, req.count as u32)
                .await
                .map_err(|e| internal_status("failed to issue delivery tokens", e))?;

        Ok(Response::new(DeliveryTokenResponse { tokens }))
    }

    async fn send_sealed_message(
        &self,
        request: Request<SendSealedMessageRequest>,
    ) -> Result<Response<SendSealedMessageResponse>, Status> {
        // No JWT authentication — the delivery token is the sole credential.
        let req = request.into_inner();

        let response =
            sealed_handler::handle_send_sealed_message(&self.state, &self.stream_mgr, req).await?;

        Ok(Response::new(response))
    }

    async fn delete_conversation(
        &self,
        request: Request<DeleteConversationRequest>,
    ) -> Result<Response<DeleteConversationResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;
        let req = request.into_inner();

        let success =
            handlers::handle_delete_conversation(&self.state, user.user_id, &req.conversation_id)
                .await?;

        Ok(Response::new(DeleteConversationResponse { success }))
    }
}

fn decode_optional_call_bytes(raw: &str) -> Result<Vec<u8>, base64::DecodeError> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    base64::engine::general_purpose::STANDARD.decode(raw)
}
