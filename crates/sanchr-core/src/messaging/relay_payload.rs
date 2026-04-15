use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayEnvelope {
    pub conversation_id: String,
    pub message_id: String,
    pub sender_id: String,
    pub sender_device: i32,
    pub ciphertext: Vec<u8>,
    pub content_type: String,
    pub server_timestamp: i64,
}
