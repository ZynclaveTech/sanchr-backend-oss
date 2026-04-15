use std::sync::Arc;

use uuid::Uuid;

use sanchr_db::redis::privacy_cache;
use sanchr_db::redis::typing;
use sanchr_proto::messaging::{server_event, ServerEvent, TypingIndicator};

use crate::messaging::stream::StreamManager;
use crate::server::AppState;

/// Set or clear typing indicator in Redis and push TypingIndicator event to
/// conversation participants via stream manager.
pub async fn handle_typing(
    state: &Arc<AppState>,
    stream_mgr: &Arc<StreamManager>,
    user_id: Uuid,
    conversation_id: &str,
    is_typing: bool,
) {
    use sanchr_db::postgres::conversations as pg_conv;

    let user_id_str = user_id.to_string();

    if is_typing {
        if let Err(error) = typing::set_typing(&state.redis, conversation_id, &user_id_str).await {
            tracing::warn!(error = %error, %user_id, "failed to set typing");
        }
    } else if let Err(error) =
        typing::clear_typing(&state.redis, conversation_id, &user_id_str).await
    {
        tracing::warn!(error = %error, %user_id, "failed to clear typing");
    }

    let conv_id = match Uuid::parse_str(conversation_id) {
        Ok(id) => id,
        Err(_) => {
            tracing::warn!(%conversation_id, "invalid conversation_id for typing broadcast");
            return;
        }
    };

    let participants = match pg_conv::get_conversation_participants(&state.pg_pool, conv_id).await {
        Ok(p) => p,
        Err(error) => {
            tracing::warn!(error = %error, "failed to get participants for typing auth check");
            return;
        }
    };
    if !participants.contains(&user_id) {
        tracing::warn!(%user_id, %conversation_id, "typing: user not a member of conversation");
        return;
    }

    // Enforce typing indicator privacy (Redis-cached, falls back to Postgres)
    match privacy_cache::get_privacy_flags(&state.redis, &state.pg_pool, user_id).await {
        Ok(flags) => {
            if !flags.can_forward_typing() {
                tracing::debug!(%user_id, "typing indicator suppressed by privacy setting (cached)");
                return;
            }
        }
        Err(e) => {
            tracing::warn!(%user_id, error = %e, "privacy check failed, suppressing typing");
            return;
        }
    }

    let event = ServerEvent {
        event: Some(server_event::Event::Typing(TypingIndicator {
            conversation_id: conversation_id.to_string(),
            user_id: user_id_str.clone(),
            is_typing,
        })),
    };

    // Phase 2 block enforcement: per-recipient silent-drop.
    let mut recipient_is_blocked: std::collections::HashMap<Uuid, bool> =
        std::collections::HashMap::new();

    for participant_id in participants {
        if participant_id == user_id {
            continue;
        }

        let blocked = match recipient_is_blocked.get(&participant_id).copied() {
            Some(b) => b,
            None => {
                match privacy_cache::get_privacy_flags(&state.redis, &state.pg_pool, participant_id)
                    .await
                {
                    Ok(recipient_flags) => {
                        let b = recipient_flags.is_blocking(&user_id_str);
                        recipient_is_blocked.insert(participant_id, b);
                        b
                    }
                    Err(e) => {
                        tracing::warn!(
                            sender_id = %user_id,
                            recipient_id = %participant_id,
                            error = %e,
                            "typing: privacy check failed, suppressing for this recipient"
                        );
                        recipient_is_blocked.insert(participant_id, true);
                        true
                    }
                }
            }
        };

        if blocked {
            tracing::debug!(
                sender_id = %user_id,
                recipient_id = %participant_id,
                "typing_blocked: recipient blocks sender"
            );
            continue;
        }

        let _ = stream_mgr
            .send_to_user(&participant_id.to_string(), event.clone())
            .await;
    }
}
