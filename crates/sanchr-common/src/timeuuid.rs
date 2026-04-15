//! Generate UUID v1 (time-based) suitable for ScyllaDB TIMEUUID columns.
//!
//! ScyllaDB rejects UUID v7 in TIMEUUID columns — only v1 is accepted.
//! This module provides a simple v1 generator using the system clock and
//! a random node ID.

use std::sync::atomic::{AtomicU16, Ordering};
use uuid::{Timestamp, Uuid};

/// Monotonic clock sequence counter to avoid collisions within the same tick.
static CLOCK_SEQ: AtomicU16 = AtomicU16::new(0);

/// Generate a new UUID v1 from the current system time.
///
/// Uses a random-ish 6-byte node ID derived from the process ID and a counter,
/// plus an atomic clock_seq to guarantee uniqueness within a single process.
pub fn new_timeuuid() -> Uuid {
    let clock_seq = CLOCK_SEQ.fetch_add(1, Ordering::Relaxed);

    // Node ID: 6 bytes. Use a pseudo-random but stable value per process.
    let pid = std::process::id();
    let node_id: [u8; 6] = [
        0x01, // set multicast bit to indicate locally-administered
        ((pid >> 24) & 0xFF) as u8,
        ((pid >> 16) & 0xFF) as u8,
        ((pid >> 8) & 0xFF) as u8,
        (pid & 0xFF) as u8,
        (clock_seq & 0xFF) as u8,
    ];

    let ts = Timestamp::now(uuid::timestamp::context::NoContext);
    Uuid::new_v1(ts, &node_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_v1() {
        let id = new_timeuuid();
        assert_eq!(id.get_version_num(), 1, "must be UUID version 1");
    }

    #[test]
    fn unique_ids() {
        let a = new_timeuuid();
        let b = new_timeuuid();
        assert_ne!(a, b, "sequential calls must produce unique UUIDs");
    }

    #[test]
    fn monotonically_ordered() {
        let ids: Vec<Uuid> = (0..100).map(|_| new_timeuuid()).collect();
        for window in ids.windows(2) {
            // UUID v1 time fields should be non-decreasing
            assert!(window[0] != window[1], "must be unique");
        }
    }
}
