use std::collections::HashMap;

use sanchr_proto::messaging::ServerEvent;
use tokio::sync::{mpsc, RwLock};

type StreamSender = mpsc::Sender<ServerEvent>;

/// Manages active bidirectional streams for connected devices.
///
/// Each connected device registers a channel sender here. Messages can
/// then be pushed to individual devices or broadcast to all devices
/// belonging to a user.
pub struct StreamManager {
    streams: RwLock<HashMap<String, HashMap<i32, StreamSender>>>,
}

impl StreamManager {
    pub fn new() -> Self {
        Self {
            streams: RwLock::new(HashMap::new()),
        }
    }

    /// Register a new stream for a user/device pair. Returns the receiver
    /// half that the gRPC response stream reads from.
    pub async fn register(&self, user_id: &str, device_id: i32) -> mpsc::Receiver<ServerEvent> {
        let (tx, rx) = mpsc::channel(256);
        self.streams
            .write()
            .await
            .entry(user_id.to_owned())
            .or_default()
            .insert(device_id, tx);
        rx
    }

    /// Remove a device stream (e.g. on disconnect).
    pub async fn unregister(&self, user_id: &str, device_id: i32) {
        let mut streams = self.streams.write().await;
        if let Some(user_streams) = streams.get_mut(user_id) {
            user_streams.remove(&device_id);
            if user_streams.is_empty() {
                streams.remove(user_id);
            }
        }
    }

    /// Check whether a specific device is currently connected.
    pub async fn is_connected(&self, user_id: &str, device_id: i32) -> bool {
        self.streams
            .read()
            .await
            .get(user_id)
            .is_some_and(|user_streams| user_streams.contains_key(&device_id))
    }

    /// Send a server event to a specific device. Returns `true` if sent.
    pub async fn send_to(&self, user_id: &str, device_id: i32, event: ServerEvent) -> bool {
        let tx = {
            let streams = self.streams.read().await;
            streams
                .get(user_id)
                .and_then(|user_streams| user_streams.get(&device_id))
                .cloned()
        };

        match tx {
            Some(tx) => tx.send(event).await.is_ok(),
            None => false,
        }
    }

    /// Broadcast a server event to all connected devices of a user.
    /// Returns the number of devices that received the event.
    pub async fn send_to_user(&self, user_id: &str, event: ServerEvent) -> u32 {
        let targets: Vec<StreamSender> = {
            let streams = self.streams.read().await;
            streams
                .get(user_id)
                .map(|user_streams| user_streams.values().cloned().collect())
                .unwrap_or_default()
        };

        let mut sent = 0u32;
        for tx in targets {
            if tx.send(event.clone()).await.is_ok() {
                sent += 1;
            }
        }
        sent
    }
}

impl Default for StreamManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sanchr_proto::messaging::{server_event, TypingIndicator};

    fn make_test_event() -> ServerEvent {
        ServerEvent {
            event: Some(server_event::Event::Typing(TypingIndicator {
                conversation_id: "conv-test".to_string(),
                user_id: "test".to_string(),
                is_typing: true,
            })),
        }
    }

    #[tokio::test]
    async fn register_and_receive() {
        let mgr = StreamManager::new();
        let mut rx = mgr.register("user-1", 1).await;

        let event = make_test_event();
        let sent = mgr.send_to("user-1", 1, event.clone()).await;
        assert!(sent);

        let received = rx.recv().await.unwrap();
        assert!(received.event.is_some());
    }

    #[tokio::test]
    async fn send_to_unregistered_returns_false() {
        let mgr = StreamManager::new();
        let sent = mgr.send_to("nobody", 1, make_test_event()).await;
        assert!(!sent);
    }

    #[tokio::test]
    async fn is_connected_after_register() {
        let mgr = StreamManager::new();
        assert!(!mgr.is_connected("user-1", 1).await);
        let _rx = mgr.register("user-1", 1).await;
        assert!(mgr.is_connected("user-1", 1).await);
    }

    #[tokio::test]
    async fn unregister_removes_stream() {
        let mgr = StreamManager::new();
        let _rx = mgr.register("user-1", 1).await;
        assert!(mgr.is_connected("user-1", 1).await);

        mgr.unregister("user-1", 1).await;
        assert!(!mgr.is_connected("user-1", 1).await);
    }

    #[tokio::test]
    async fn send_to_user_broadcasts_to_all_devices() {
        let mgr = StreamManager::new();
        let mut rx1 = mgr.register("user-1", 1).await;
        let mut rx2 = mgr.register("user-1", 2).await;
        let _rx3 = mgr.register("user-2", 1).await; // different user

        let count = mgr.send_to_user("user-1", make_test_event()).await;
        assert_eq!(count, 2);

        assert!(rx1.recv().await.is_some());
        assert!(rx2.recv().await.is_some());
    }

    #[tokio::test]
    async fn send_to_user_returns_zero_for_unknown() {
        let mgr = StreamManager::new();
        let count = mgr.send_to_user("unknown", make_test_event()).await;
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn multiple_devices_independent() {
        let mgr = StreamManager::new();
        let _rx1 = mgr.register("user-1", 1).await;
        let _rx2 = mgr.register("user-1", 2).await;

        // Send to device 1 only
        let sent = mgr.send_to("user-1", 1, make_test_event()).await;
        assert!(sent);

        // Device 2 should still be connected but not have received
        assert!(mgr.is_connected("user-1", 2).await);
    }

    #[tokio::test]
    async fn re_register_replaces_stream() {
        let mgr = StreamManager::new();
        let _rx_old = mgr.register("user-1", 1).await;
        let mut rx_new = mgr.register("user-1", 1).await;

        // Old rx is now orphaned, new one should work
        mgr.send_to("user-1", 1, make_test_event()).await;
        assert!(rx_new.recv().await.is_some());
    }

    #[tokio::test]
    async fn default_impl_works() {
        let mgr = StreamManager::default();
        assert!(!mgr.is_connected("user", 1).await);
    }
}
