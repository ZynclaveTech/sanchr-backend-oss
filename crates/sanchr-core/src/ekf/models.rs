use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use uuid::Uuid;

/// A 32-byte zero sentinel used by the `Overwrite` expiry policy to signal
/// that the material slot has been nulled out without removing the row.
pub const NULL_SENTINEL: [u8; 32] = [0x00; 32];

// ---------------------------------------------------------------------------
// KeyClass
// ---------------------------------------------------------------------------

/// The category of auxiliary cryptographic state an entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyClass {
    /// Short-lived discovery key — 24 h TTL.
    Discovery,
    /// Media encryption key — 30 d TTL.
    Media,
    /// Presence / heartbeat token — 5 m TTL.
    Presence,
    /// Pre-key bundle material — 7 d TTL.
    PreKey,
}

impl KeyClass {
    /// Default time-to-live in seconds for this key class.
    pub fn default_ttl_secs(&self) -> i64 {
        match self {
            KeyClass::Discovery => 86_400, // 24 h
            KeyClass::Media => 2_592_000,  // 30 d
            KeyClass::Presence => 300,     // 5 m
            KeyClass::PreKey => 604_800,   // 7 d
        }
    }

    /// Canonical string representation stored in ScyllaDB.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyClass::Discovery => "discovery",
            KeyClass::Media => "media",
            KeyClass::Presence => "presence",
            KeyClass::PreKey => "pre_key",
        }
    }
}

impl FromStr for KeyClass {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "discovery" => Ok(KeyClass::Discovery),
            "media" => Ok(KeyClass::Media),
            "presence" => Ok(KeyClass::Presence),
            "pre_key" => Ok(KeyClass::PreKey),
            _ => Err(()),
        }
    }
}

// ---------------------------------------------------------------------------
// ExpPolicy
// ---------------------------------------------------------------------------

/// What to do with an entry once it has expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpPolicy {
    /// Rotate: replace the material with fresh keying material and reset the
    /// creation timestamp.
    Rotate,
    /// Delete: remove the row entirely from the store.
    Delete,
    /// Overwrite: zero-fill the material with [`NULL_SENTINEL`] and reset the
    /// creation timestamp, keeping the row for audit purposes.
    Overwrite,
    /// Replenish: replace the expired material with fresh random bytes of the
    /// same length and reset the creation timestamp, keeping the key slot
    /// continuously alive without requiring a client round-trip.  Used for
    /// pre-key entries so the server always has a non-zero supply of one-time
    /// pre-keys without a client-initiated replenishment cycle.
    Replenish,
}

impl ExpPolicy {
    /// Canonical string representation stored in ScyllaDB.
    pub fn as_str(&self) -> &'static str {
        match self {
            ExpPolicy::Rotate => "rotate",
            ExpPolicy::Delete => "delete",
            ExpPolicy::Overwrite => "overwrite",
            ExpPolicy::Replenish => "replenish",
        }
    }
}

impl FromStr for ExpPolicy {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "rotate" => Ok(ExpPolicy::Rotate),
            "delete" => Ok(ExpPolicy::Delete),
            "overwrite" => Ok(ExpPolicy::Overwrite),
            "replenish" => Ok(ExpPolicy::Replenish),
            _ => Err(()),
        }
    }
}

// ---------------------------------------------------------------------------
// EphemeralEntry
// ---------------------------------------------------------------------------

/// In-memory representation of a single row in the `auxiliary_state` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralEntry {
    /// Unique row identifier.
    pub entry_id: Uuid,
    /// Owner of this key material.
    pub user_id: Uuid,
    /// Category of this entry.
    pub class: KeyClass,
    /// Expiry policy applied by the lifecycle manager.
    pub policy: ExpPolicy,
    /// Wall-clock time at which the entry was created (or last rotated /
    /// overwritten).
    pub created_at: DateTime<Utc>,
    /// Time-to-live in seconds.  May differ from the class default when an
    /// explicit override was supplied at insertion time.
    pub ttl_secs: i64,
    /// Raw key material.
    pub material: Vec<u8>,
}

impl EphemeralEntry {
    /// Returns `true` if the entry's age relative to `now` exceeds `ttl_secs`.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        let age_secs = (now - self.created_at).num_seconds();
        age_secs >= self.ttl_secs
    }
}
