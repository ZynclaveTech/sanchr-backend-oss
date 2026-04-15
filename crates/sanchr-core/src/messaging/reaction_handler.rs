use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use scylla::frame::value::CqlTimeuuid;
use tonic::Status;
use uuid::Uuid;

use sanchr_common::errors::internal_status;
use sanchr_db::postgres::conversations as pg_conv;
use sanchr_db::redis::rate_limit;
use sanchr_db::scylla::reactions as sc_reactions;
use sanchr_proto::messaging::{server_event, Reaction, ServerEvent};

use crate::server::AppState;

use super::stream::StreamManager;

pub async fn handle_send_reaction(
    state: &Arc<AppState>,
    stream_mgr: &StreamManager,
    user_id: Uuid,
    reaction: &Reaction,
) -> Result<Reaction, Status> {
    // ── Rate limit: 30 reactions per 60 seconds ────────────────────────
    rate_limit::check_rate_limit(
        &state.redis,
        &format!("rate:send_reaction:{user_id}"),
        30,
        60,
    )
    .await
    .map_err(|_| Status::resource_exhausted("reaction rate limit exceeded"))?;

    let conversation_id: Uuid = reaction
        .conversation_id
        .parse()
        .map_err(|_| Status::invalid_argument("invalid conversation_id"))?;

    let message_uuid: Uuid = reaction
        .message_id
        .parse()
        .map_err(|_| Status::invalid_argument("invalid message_id"))?;

    if reaction.emoji.is_empty() {
        return Err(Status::invalid_argument("emoji must not be empty"));
    }

    // Verify the caller is a participant of the conversation.
    let participants = pg_conv::get_conversation_participants(&state.pg_pool, conversation_id)
        .await
        .map_err(|e| internal_status("failed to get participants", e))?;

    if !participants.contains(&user_id) {
        return Err(Status::permission_denied(
            "not a member of this conversation",
        ));
    }

    let message_id = CqlTimeuuid::from(message_uuid);

    if reaction.removed {
        sc_reactions::remove_reaction(
            &state.scylla,
            conversation_id,
            message_id,
            user_id,
            &reaction.emoji,
        )
        .await
        .map_err(|e| internal_status("remove_reaction failed", e))?;
    } else {
        sc_reactions::add_reaction(
            &state.scylla,
            conversation_id,
            message_id,
            user_id,
            &reaction.emoji,
        )
        .await
        .map_err(|e| internal_status("add_reaction failed", e))?;
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| internal_status("clock error", e))?
        .as_millis() as i64;

    let outgoing = Reaction {
        message_id: reaction.message_id.clone(),
        conversation_id: reaction.conversation_id.clone(),
        user_id: user_id.to_string(),
        emoji: reaction.emoji.clone(),
        removed: reaction.removed,
        timestamp,
    };

    // Broadcast to all other participants who are currently connected.
    let event = ServerEvent {
        event: Some(server_event::Event::Reaction(outgoing.clone())),
    };
    for pid in &participants {
        if *pid != user_id {
            let _ = stream_mgr
                .send_to_user(&pid.to_string(), event.clone())
                .await;
        }
    }

    Ok(outgoing)
}
