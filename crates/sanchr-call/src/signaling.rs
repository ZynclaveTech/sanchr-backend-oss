//! Call signaling service.
//!
//! **Security Note:** NATS subjects for call signaling (e.g., `call.{call_id}.*`)
//! should be secured with NATS ACLs in production to prevent unauthorized
//! subscription. Each call uses a unique UUID-based subject, but subjects are
//! guessable if call IDs leak. Configure NATS authorization to restrict
//! subject access per authenticated user.

use std::pin::Pin;
use std::sync::Arc;

use chrono::Utc;
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use tonic::{Request, Response, Status, Streaming};
use uuid::Uuid;

use sanchr_common::{errors::internal_status, CallLifecyclePayload, CallOfferPayload};
use sanchr_db::redis::{call_state, sessions};
use sanchr_db::scylla::calls;
use sanchr_proto::calling::{
    call_signal, call_signaling_service_server::CallSignalingService, CallControl, CallJoin,
    CallLogEntry, CallOffer, CallResponse, CallSignal, EndCallRequest, EndCallResponse,
    GetCallHistoryRequest, GetCallHistoryResponse, GetTurnCredentialsRequest, TurnCredentials,
};
use sanchr_server_crypto::jwt::{JwtError, JwtManager};

use crate::turn;
use crate::CallAppState;

const DEFAULT_CALL_HISTORY_LIMIT: i32 = 50;
pub const MAX_CALL_HISTORY_LIMIT: i32 = 100;
const RINGING_TIMEOUT_SECS: i64 = 120;
const MISSED_SWEEP_INTERVAL_SECS: u64 = 5;

enum SignalingValidationError {
    InvalidArgument(&'static str),
    PermissionDenied(&'static str),
}

impl SignalingValidationError {
    fn into_status(self) -> Status {
        match self {
            Self::InvalidArgument(message) => Status::invalid_argument(message),
            Self::PermissionDenied(message) => Status::permission_denied(message),
        }
    }
}

pub struct CallSignalingServiceImpl {
    pub state: Arc<CallAppState>,
}

pub fn spawn_missed_call_sweeper(state: Arc<CallAppState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(MISSED_SWEEP_INTERVAL_SECS));
        loop {
            interval.tick().await;
            let now_ms = Utc::now().timestamp_millis();
            let due = match call_state::due_missed_call_ids(&state.redis, now_ms, 100).await {
                Ok(due) => due,
                Err(error) => {
                    tracing::warn!(error = %error, "missed-call sweeper failed to read deadlines");
                    continue;
                }
            };
            for call_id in due {
                if let Err(error) =
                    transition_terminal_call(Arc::clone(&state), &call_id, None, "missed").await
                {
                    tracing::warn!(error = %error, call_id, "missed-call transition failed");
                }
            }
        }
    })
}

/// Extract and validate a bearer JWT from gRPC metadata, then confirm the
/// session is still live in Redis. Returns `(user_id, device_id)`.
async fn authenticate(
    jwt: &JwtManager,
    redis: &fred::clients::RedisClient,
    metadata: &tonic::metadata::MetadataMap,
) -> Result<(Uuid, i32), Status> {
    tracing::debug!("authenticate: extracting bearer token");

    let token = metadata
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            tracing::warn!("authenticate: missing or invalid authorization header");
            Status::unauthenticated("missing or invalid authorization header")
        })?;

    tracing::debug!(token_len = token.len(), "authenticate: validating JWT");

    let claims = jwt.validate_token(token).map_err(|e| match e {
        JwtError::Expired => {
            tracing::warn!("authenticate: JWT expired");
            Status::unauthenticated("token expired")
        }
        JwtError::ValidationError(msg) => {
            tracing::warn!(msg, "authenticate: JWT validation failed");
            Status::unauthenticated(format!("invalid token: {}", msg))
        }
        JwtError::CreationError(msg) => {
            tracing::error!(msg, "authenticate: JWT creation error");
            internal_status("jwt error", msg)
        }
    })?;

    tracing::debug!(jti = %claims.jti, "authenticate: JWT valid, checking Redis session");

    let session = sessions::validate_session(redis, &claims.jti)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, jti = %claims.jti, "authenticate: Redis session lookup failed");
            internal_status("session check failed", e)
        })?;

    let (user_id, device_id) = session.ok_or_else(|| {
        tracing::warn!(jti = %claims.jti, "authenticate: session not found in Redis (expired or revoked)");
        Status::unauthenticated("session expired or revoked")
    })?;

    tracing::debug!(%user_id, device_id, "authenticate: OK");
    Ok((user_id, device_id))
}

#[tonic::async_trait]
impl CallSignalingService for CallSignalingServiceImpl {
    /// Initiate a new call: generate call_id, store in Redis, notify recipient via NATS.
    async fn initiate_call(
        &self,
        request: Request<CallOffer>,
    ) -> Result<Response<CallResponse>, Status> {
        let (user_id, _device_id) =
            authenticate(&self.state.jwt, &self.state.redis, request.metadata()).await?;

        let offer = request.into_inner();

        let recipient_id: Uuid = offer
            .recipient_id
            .parse()
            .map_err(|_| Status::invalid_argument("invalid recipient_id"))?;

        if recipient_id == user_id {
            return Err(Status::invalid_argument("cannot call yourself"));
        }

        if active_nonterminal_call_for_user(&self.state.redis, &user_id.to_string()).await?
            || active_nonterminal_call_for_user(&self.state.redis, &recipient_id.to_string())
                .await?
        {
            tracing::info!(
                caller_id = %user_id,
                recipient_id = %recipient_id,
                "InitiateCall: caller or recipient is already in an active call"
            );
            return Ok(Response::new(CallResponse {
                call_id: String::new(),
                status: "busy".to_string(),
            }));
        }

        let call_id = Uuid::new_v4();
        let call_id_str = call_id.to_string();

        let started_at = Utc::now().timestamp();
        let now_ms = Utc::now().timestamp_millis();
        let call_type = offer.call_type.clone();
        let active_call = call_state::ActiveCall {
            call_id: call_id_str.clone(),
            caller_id: user_id.to_string(),
            recipient_id: recipient_id.to_string(),
            call_type: call_type.clone(),
            status: "ringing".to_string(),
            started_at,
            answered_at: None,
        };
        let created = call_state::begin_active_call(
            &self.state.redis,
            &active_call,
            self.state.config.calling.max_call_duration as i64,
            now_ms + RINGING_TIMEOUT_SECS * 1_000,
        )
        .await
        .map_err(|e| internal_status("redis error", e))?;
        if !created {
            tracing::info!(
                caller_id = %user_id,
                recipient_id = %recipient_id,
                "InitiateCall: caller or recipient became busy before active call was created"
            );
            return Ok(Response::new(CallResponse {
                call_id: String::new(),
                status: "busy".to_string(),
            }));
        }

        // Log the call for the caller (outgoing)
        if let Err(error) = calls::insert_call_log(
            &self.state.scylla,
            &calls::InsertCallLogParams {
                user_id: &user_id,
                call_id: &call_id,
                peer_id: &recipient_id,
                call_type: &call_type,
                direction: "outgoing",
                status: "ringing",
                started_at_ms: now_ms,
                ended_at_ms: None,
                duration_secs: None,
            },
        )
        .await
        {
            cleanup_active_call(&self.state.redis, &active_call).await;
            return Err(internal_status("failed to record caller call log", error));
        }

        // Log the call for the recipient (incoming)
        if let Err(error) = calls::insert_call_log(
            &self.state.scylla,
            &calls::InsertCallLogParams {
                user_id: &recipient_id,
                call_id: &call_id,
                peer_id: &user_id,
                call_type: &call_type,
                direction: "incoming",
                status: "ringing",
                started_at_ms: now_ms,
                ended_at_ms: None,
                duration_secs: None,
            },
        )
        .await
        {
            cleanup_active_call(&self.state.redis, &active_call).await;
            return Err(internal_status(
                "failed to record recipient call log",
                error,
            ));
        }

        // Publish call offer to NATS so sanchr-core can deliver it via MessageStream
        let nats_subject = format!("call.offer.{}", recipient_id);
        let nats_payload = serde_json::to_string(&CallOfferPayload {
            call_id: call_id_str.clone(),
            caller_id: user_id.to_string(),
            call_type,
            sdp_offer: String::new(),
            srtp_key_params: String::new(),
            encrypted_sdp_payload: base64_encode(&offer.encrypted_sdp_payload),
        })
        .map_err(|e| internal_status("failed to encode call offer", e))?;
        if let Err(error) = self
            .state
            .nats
            .publish(nats_subject, nats_payload.into())
            .await
        {
            cleanup_active_call(&self.state.redis, &active_call).await;
            return Err(internal_status("failed to publish call offer event", error));
        }
        // Avoid per-request flush() on the hot path to reduce call setup latency.
        // async-nats publish() already enqueues to the connection writer task.

        Ok(Response::new(CallResponse {
            call_id: call_id_str,
            status: "ringing".to_string(),
        }))
    }

    type CallStreamStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<CallSignal, Status>> + Send>>;

    /// Bidirectional streaming: relay CallSignal messages between caller and callee
    /// via NATS pub/sub on `call.signal.{call_id}`.
    async fn call_stream(
        &self,
        request: Request<Streaming<CallSignal>>,
    ) -> Result<Response<Self::CallStreamStream>, Status> {
        let (user_id, _device_id) =
            authenticate(&self.state.jwt, &self.state.redis, request.metadata()).await?;

        let mut inbound = request.into_inner();

        // New clients send an initial CallJoin that only carries call_id/role.
        // Older clients send answer/ICE/control first; keep that path by
        // publishing the first message after subscription is ready.
        let first_msg = inbound
            .next()
            .await
            .ok_or_else(|| Status::invalid_argument("empty stream"))?
            .map_err(|e| internal_status("stream error", e))?;

        let call_id = first_msg.call_id.clone();
        if call_id.is_empty() {
            return Err(Status::invalid_argument("missing call_id"));
        }
        let nats_subject = format!("call.signal.{}", call_id);
        let user_id_str = user_id.to_string();
        let first_is_join = matches!(first_msg.signal, Some(call_signal::Signal::Join(_)));

        let active_call =
            load_participating_call(&self.state.redis, &call_id, &user_id_str).await?;
        let join_role = match &first_msg.signal {
            Some(call_signal::Signal::Join(join)) => join.role.as_str(),
            _ => "legacy",
        };
        if let Some(call_signal::Signal::Join(join)) = &first_msg.signal {
            validate_join_role(&active_call, &user_id_str, &join.role)
                .map_err(SignalingValidationError::into_status)?;
        }

        // Subscribe to NATS subject for incoming signals from the other participant
        let mut subscription = self
            .state
            .nats
            .subscribe(nats_subject.clone())
            .await
            .map_err(|e| internal_status("nats subscribe error", e))?;

        tracing::info!(
            call_id,
            user_id = %user_id,
            role = join_role,
            first_is_join,
            status = %active_call.status,
            "CallStream joined"
        );

        // Create a channel to send outbound messages from replay/NATS to gRPC.
        let (tx, rx) = tokio::sync::mpsc::channel(64);

        // Replay signals sent before this participant joined.  Join messages are
        // not stored, so every replay item is a peer-visible signal.
        let replayed = call_state::replay_call_signals(&self.state.redis, &call_id)
            .await
            .map_err(|e| internal_status("redis signal replay error", e))?;
        let mut replay_count = 0usize;
        for stored in replayed {
            if stored.sender_id == user_id_str {
                continue;
            }
            if let Some(signal) = decode_signal_value(&call_id, &stored.signal) {
                replay_count += 1;
                if tx.send(Ok(signal)).await.is_err() {
                    break;
                }
            }
        }
        tracing::info!(call_id, user_id = %user_id, replay_count, "CallStream replay complete");

        if !first_is_join {
            persist_and_publish_signal(Arc::clone(&self.state), &call_id, &user_id_str, &first_msg)
                .await?;
        }

        // Spawn a task to forward inbound gRPC messages to NATS
        let state_for_inbound = Arc::clone(&self.state);
        let call_id_for_inbound = call_id.clone();
        let sender_clone = user_id_str.clone();
        tokio::spawn(async move {
            while let Some(Ok(msg)) = inbound.next().await {
                if matches!(msg.signal, Some(call_signal::Signal::Join(_))) {
                    continue;
                }
                if msg.call_id != call_id_for_inbound {
                    tracing::warn!(
                        expected_call_id = %call_id_for_inbound,
                        actual_call_id = %msg.call_id,
                        "dropping call signal for wrong call_id"
                    );
                    continue;
                }
                if let Err(error) = persist_and_publish_signal(
                    Arc::clone(&state_for_inbound),
                    &call_id_for_inbound,
                    &sender_clone,
                    &msg,
                )
                .await
                {
                    tracing::error!(error = %error, call_id = %call_id_for_inbound, "failed to publish call signal");
                    break;
                }
            }
        });

        tokio::spawn(async move {
            while let Some(msg) = subscription.next().await {
                let payload_str = String::from_utf8_lossy(&msg.payload);
                match serde_json::from_str::<serde_json::Value>(&payload_str) {
                    Ok(parsed) => {
                        // Skip messages sent by this user (echo suppression)
                        if parsed
                            .get("sender_id")
                            .and_then(|v| v.as_str())
                            .map(|s| s == user_id_str)
                            .unwrap_or(false)
                        {
                            continue;
                        }

                        if let Some(signal) = decode_call_signal(&call_id, &parsed) {
                            if tx.send(Ok(signal)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(error) => {
                        tracing::warn!(error = %error, "dropping malformed call stream payload");
                    }
                }
            }
        });

        let output_stream = ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(output_stream)))
    }

    /// End an active call: clean up Redis, update ScyllaDB logs, notify via NATS.
    async fn end_call(
        &self,
        request: Request<EndCallRequest>,
    ) -> Result<Response<EndCallResponse>, Status> {
        let (user_id, _device_id) =
            authenticate(&self.state.jwt, &self.state.redis, request.metadata()).await?;

        let req = request.into_inner();
        let call_id: Uuid = req
            .call_id
            .parse()
            .map_err(|_| Status::invalid_argument("invalid call_id"))?;
        let reason = normalize_terminal_reason(&req.reason, "ended")
            .map_err(SignalingValidationError::into_status)?;

        let transitioned = transition_terminal_call(
            Arc::clone(&self.state),
            &req.call_id,
            Some(&user_id.to_string()),
            reason,
        )
        .await?;

        // Publish call ended event via NATS
        let nats_payload = serde_json::json!({
            "call_id": req.call_id,
            "ended_by": user_id.to_string(),
            "reason": reason,
        });
        self.state
            .nats
            .publish(
                format!("call.ended.{}", req.call_id),
                nats_payload.to_string().into(),
            )
            .await
            .map_err(|error| internal_status("failed to publish call ended event", error))?;

        // Also signal on the call stream subject so both sides know
        let end_signal = serde_json::json!({
            "sender_id": user_id.to_string(),
            "signal": { "control": { "action": reason } },
        });
        self.state
            .nats
            .publish(
                format!("call.signal.{}", req.call_id),
                end_signal.to_string().into(),
            )
            .await
            .map_err(|error| internal_status("failed to publish end signal", error))?;

        tracing::info!(
            call_id = %call_id,
            actor_id = %user_id,
            reason,
            transitioned,
            "EndCall processed"
        );

        Ok(Response::new(EndCallResponse {}))
    }

    /// Return call history for the authenticated user.
    async fn get_call_history(
        &self,
        request: Request<GetCallHistoryRequest>,
    ) -> Result<Response<GetCallHistoryResponse>, Status> {
        let (user_id, _device_id) =
            authenticate(&self.state.jwt, &self.state.redis, request.metadata()).await?;

        let req = request.into_inner();
        let limit = if req.limit > 0 {
            req.limit.min(MAX_CALL_HISTORY_LIMIT)
        } else {
            DEFAULT_CALL_HISTORY_LIMIT
        };

        let rows = calls::get_call_history(&self.state.scylla, &user_id, limit)
            .await
            .map_err(|e| internal_status("scylla error", e))?;

        let entries = rows
            .into_iter()
            .map(|r| CallLogEntry {
                call_id: r.call_id.to_string(),
                peer_id: r.peer_id.to_string(),
                peer_name: String::new(), // Would require a user lookup; left empty for now
                call_type: r.call_type,
                direction: r.direction,
                status: r.status,
                started_at: r.started_at.0 / 1000, // CqlTimestamp is millis, proto wants seconds
                ended_at: r.ended_at.map(|t| t.0 / 1000).unwrap_or(0),
                duration_secs: r.duration_secs.unwrap_or(0),
            })
            .collect();

        Ok(Response::new(GetCallHistoryResponse { entries }))
    }

    /// Return short-lived TURN credentials for the authenticated user.
    async fn get_turn_credentials(
        &self,
        request: Request<GetTurnCredentialsRequest>,
    ) -> Result<Response<TurnCredentials>, Status> {
        tracing::info!("GetTurnCredentials: request received");

        let (user_id, _device_id) =
            authenticate(&self.state.jwt, &self.state.redis, request.metadata()).await?;

        tracing::info!(%user_id, "GetTurnCredentials: authenticated, generating credentials");

        let (urls, username, credential, ttl) =
            turn::get_turn_credentials(&self.state.config.calling, &user_id.to_string());

        tracing::info!(
            urls_count = urls.len(),
            urls = ?urls,
            username_len = username.len(),
            credential_len = credential.len(),
            ttl,
            "GetTurnCredentials: returning credentials"
        );

        Ok(Response::new(TurnCredentials {
            urls,
            username,
            credential,
            ttl: ttl as i64,
        }))
    }
}

// ---- helpers ----

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

async fn cleanup_active_call(redis: &fred::clients::RedisClient, call: &call_state::ActiveCall) {
    if let Err(error) = call_state::clear_active_call(redis, call).await {
        tracing::error!(error = %error, call_id = %call.call_id, "failed to clean up active call state");
    }
}

async fn active_nonterminal_call_for_user(
    redis: &fred::clients::RedisClient,
    user_id: &str,
) -> Result<bool, Status> {
    let Some(call_id) = call_state::active_call_id_for_user(redis, user_id)
        .await
        .map_err(|e| internal_status("redis error", e))?
    else {
        return Ok(false);
    };
    let Some(call) = call_state::get_active_call(redis, &call_id)
        .await
        .map_err(|e| internal_status("redis error", e))?
    else {
        return Ok(false);
    };
    Ok(!is_terminal_status(&call.status))
}

async fn load_participating_call(
    redis: &fred::clients::RedisClient,
    call_id: &str,
    user_id: &str,
) -> Result<call_state::ActiveCall, Status> {
    let call = call_state::get_active_call(redis, call_id)
        .await
        .map_err(|e| internal_status("redis error", e))?
        .ok_or_else(|| Status::not_found("call not found or already ended"))?;
    if call.caller_id != user_id && call.recipient_id != user_id {
        return Err(Status::permission_denied("not a participant of this call"));
    }
    Ok(call)
}

fn is_terminal_status(status: &str) -> bool {
    matches!(
        status,
        "completed" | "ended" | "declined" | "cancelled" | "busy" | "missed" | "failed"
    )
}

fn validate_join_role(
    call: &call_state::ActiveCall,
    user_id: &str,
    role: &str,
) -> Result<(), SignalingValidationError> {
    match role {
        "caller" if call.caller_id == user_id => Ok(()),
        "callee" if call.recipient_id == user_id => Ok(()),
        "caller" | "callee" => Err(SignalingValidationError::PermissionDenied(
            "join role does not match call participant",
        )),
        _ => Err(SignalingValidationError::InvalidArgument(
            "invalid call join role",
        )),
    }
}

fn normalize_terminal_reason<'a>(
    reason: &'a str,
    default: &'static str,
) -> Result<&'a str, SignalingValidationError> {
    let reason = if reason.trim().is_empty() {
        default
    } else {
        reason.trim()
    };
    match reason {
        "ended" | "declined" | "cancelled" | "busy" | "missed" | "failed" => Ok(reason),
        _ => Err(SignalingValidationError::InvalidArgument(
            "invalid call end reason",
        )),
    }
}

fn terminal_log_status(call: &call_state::ActiveCall, reason: &str) -> &'static str {
    match reason {
        "ended" if call.status == "accepted" => "completed",
        "ended" => "cancelled",
        "declined" => "declined",
        "cancelled" => "cancelled",
        "busy" => "busy",
        "missed" => "missed",
        "failed" => "failed",
        _ => "failed",
    }
}

async fn transition_accepted_call(
    state: Arc<CallAppState>,
    call_id: &str,
    actor_id: &str,
) -> Result<(), Status> {
    let mut call = load_participating_call(&state.redis, call_id, actor_id).await?;
    if call.status == "accepted" {
        return Ok(());
    }
    if call.status != "ringing" {
        return Ok(());
    }
    call.status = "accepted".to_string();
    call.answered_at = Some(Utc::now().timestamp());
    call_state::put_active_call(
        &state.redis,
        &call,
        state.config.calling.max_call_duration as i64,
    )
    .await
    .map_err(|e| internal_status("failed to persist accepted call state", e))?;
    let _ = call_state::remove_missed_deadline(&state.redis, call_id).await;
    publish_lifecycle_pair(&state, &call, "accepted", actor_id).await?;
    tracing::info!(call_id, actor_id, "call state transitioned to accepted");
    Ok(())
}

async fn transition_terminal_call(
    state: Arc<CallAppState>,
    call_id: &str,
    actor_id: Option<&str>,
    reason: &str,
) -> Result<bool, Status> {
    let Some(call) = call_state::get_active_call(&state.redis, call_id)
        .await
        .map_err(|e| internal_status("redis error", e))?
    else {
        return Ok(false);
    };

    if let Some(actor_id) = actor_id {
        if call.caller_id != actor_id && call.recipient_id != actor_id {
            return Err(Status::permission_denied("not a participant of this call"));
        }
    }

    let call_uuid: Uuid = call
        .call_id
        .parse()
        .map_err(|_| Status::invalid_argument("invalid call_id"))?;
    let caller_uuid: Uuid = call
        .caller_id
        .parse()
        .map_err(|_| internal_status("invalid caller_id in call state", "parse error"))?;
    let recipient_uuid: Uuid = call
        .recipient_id
        .parse()
        .map_err(|_| internal_status("invalid recipient_id in call state", "parse error"))?;

    let now = Utc::now();
    let now_ms = now.timestamp_millis();
    let duration = (now.timestamp() - call.started_at).max(0) as i32;
    let status = terminal_log_status(&call, reason);

    if let Err(error) = calls::update_call_status(
        &state.scylla,
        &caller_uuid,
        &call_uuid,
        status,
        now_ms,
        duration,
    )
    .await
    {
        tracing::error!(error = %error, user_id = %caller_uuid, call_id = %call_uuid, status, "failed to update caller call status");
    }
    if let Err(error) = calls::update_call_status(
        &state.scylla,
        &recipient_uuid,
        &call_uuid,
        status,
        now_ms,
        duration,
    )
    .await
    {
        tracing::error!(error = %error, user_id = %recipient_uuid, call_id = %call_uuid, status, "failed to update recipient call status");
    }

    call_state::clear_active_call(&state.redis, &call)
        .await
        .map_err(|e| internal_status("failed to clear active call state", e))?;
    publish_lifecycle_pair(&state, &call, reason, actor_id.unwrap_or("system")).await?;
    tracing::info!(
        call_id,
        reason,
        status,
        actor_id = actor_id.unwrap_or("system"),
        "call state transitioned to terminal"
    );
    Ok(true)
}

async fn publish_lifecycle_pair(
    state: &CallAppState,
    call: &call_state::ActiveCall,
    event_type: &str,
    actor_id: &str,
) -> Result<(), Status> {
    let caller_lifecycle = serde_json::to_string(&CallLifecyclePayload {
        call_id: call.call_id.clone(),
        peer_id: call.recipient_id.clone(),
        event_type: event_type.to_string(),
        actor_id: actor_id.to_string(),
    })
    .map_err(|e| internal_status("failed to encode caller lifecycle event", e))?;
    let recipient_lifecycle = serde_json::to_string(&CallLifecyclePayload {
        call_id: call.call_id.clone(),
        peer_id: call.caller_id.clone(),
        event_type: event_type.to_string(),
        actor_id: actor_id.to_string(),
    })
    .map_err(|e| internal_status("failed to encode recipient lifecycle event", e))?;

    state
        .nats
        .publish(
            format!("call.lifecycle.{}", call.caller_id),
            caller_lifecycle.into(),
        )
        .await
        .map_err(|e| internal_status("failed to publish caller lifecycle event", e))?;
    state
        .nats
        .publish(
            format!("call.lifecycle.{}", call.recipient_id),
            recipient_lifecycle.into(),
        )
        .await
        .map_err(|e| internal_status("failed to publish recipient lifecycle event", e))?;
    Ok(())
}

async fn persist_and_publish_signal(
    state: Arc<CallAppState>,
    call_id: &str,
    sender_id: &str,
    msg: &CallSignal,
) -> Result<(), Status> {
    if let Some(call_signal::Signal::Control(control)) = &msg.signal {
        match control.action.as_str() {
            "accepted" => {
                transition_accepted_call(Arc::clone(&state), call_id, sender_id).await?;
            }
            "declined" | "busy" | "missed" | "ended" | "cancelled" | "failed" => {
                let reason = normalize_terminal_reason(&control.action, "ended")
                    .map_err(SignalingValidationError::into_status)?;
                let _ =
                    transition_terminal_call(Arc::clone(&state), call_id, Some(sender_id), reason)
                        .await?;
            }
            _ => {}
        }
    }

    let signal = encode_call_signal(msg);
    call_state::store_call_signal(
        &state.redis,
        call_id,
        &call_state::StoredCallSignal {
            sender_id: sender_id.to_string(),
            signal: signal.clone(),
        },
    )
    .await
    .map_err(|e| internal_status("failed to persist call signal replay", e))?;

    let payload = serde_json::json!({
        "sender_id": sender_id,
        "signal": signal,
    });
    state
        .nats
        .publish(
            format!("call.signal.{}", call_id),
            payload.to_string().into(),
        )
        .await
        .map_err(|error| internal_status("failed to publish call signal to NATS", error))?;
    Ok(())
}

fn encode_call_signal(signal: &CallSignal) -> serde_json::Value {
    match &signal.signal {
        Some(sanchr_proto::calling::call_signal::Signal::IceCandidate(data)) => {
            serde_json::json!({ "ice_candidate": base64_encode(data) })
        }
        Some(sanchr_proto::calling::call_signal::Signal::Control(ctrl)) => {
            serde_json::json!({ "control": { "action": ctrl.action } })
        }
        Some(sanchr_proto::calling::call_signal::Signal::EncryptedSdpAnswer(data)) => {
            serde_json::json!({ "encrypted_sdp_answer": base64_encode(data) })
        }
        Some(sanchr_proto::calling::call_signal::Signal::Join(join)) => {
            serde_json::json!({ "join": { "role": join.role } })
        }
        None => serde_json::json!(null),
    }
}

fn decode_call_signal(call_id: &str, parsed: &serde_json::Value) -> Option<CallSignal> {
    let signal_val = parsed.get("signal")?;
    decode_signal_value(call_id, signal_val)
}

fn decode_signal_value(call_id: &str, signal_val: &serde_json::Value) -> Option<CallSignal> {
    use base64::Engine;
    let signal = if let Some(sdp) = signal_val
        .get("encrypted_sdp_answer")
        .or_else(|| signal_val.get("sdp_answer"))
        .and_then(|v| v.as_str())
    {
        let data = base64::engine::general_purpose::STANDARD.decode(sdp).ok()?;
        Some(sanchr_proto::calling::call_signal::Signal::EncryptedSdpAnswer(data))
    } else if let Some(ice) = signal_val.get("ice_candidate").and_then(|v| v.as_str()) {
        let data = base64::engine::general_purpose::STANDARD.decode(ice).ok()?;
        Some(sanchr_proto::calling::call_signal::Signal::IceCandidate(
            data,
        ))
    } else if let Some(ctrl) = signal_val.get("control") {
        let action = ctrl.get("action")?.as_str()?.to_string();
        Some(sanchr_proto::calling::call_signal::Signal::Control(
            CallControl { action },
        ))
    } else if let Some(join) = signal_val.get("join") {
        let role = join.get("role")?.as_str()?.to_string();
        Some(sanchr_proto::calling::call_signal::Signal::Join(CallJoin {
            role,
        }))
    } else {
        None
    };

    Some(CallSignal {
        call_id: call_id.to_string(),
        signal,
    })
}
