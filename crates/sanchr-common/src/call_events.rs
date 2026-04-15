use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CallOfferPayload {
    pub call_id: String,
    pub caller_id: String,
    pub call_type: String,
    #[serde(default)]
    pub sdp_offer: String,
    #[serde(default)]
    pub srtp_key_params: String,
    #[serde(default)]
    pub encrypted_sdp_payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CallLifecyclePayload {
    pub call_id: String,
    pub peer_id: String,
    pub event_type: String,
    pub actor_id: String,
}
