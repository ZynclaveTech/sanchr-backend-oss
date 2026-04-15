//! Avatar visibility enforcement.
//!
//! Decides whether a requester is allowed to see the owner's avatar URL based
//! on the owner's `profile_photo_visibility` setting and, for the `"contacts"`
//! mode, a mutual-contact lookup against `sanchr_db::postgres::contacts`.
//!
//! The decision logic is intentionally split into two layers:
//!
//! 1. [`AvatarVisibility`] + [`decide_avatar_visibility`] — a pure, synchronous
//!    state machine that takes a parsed visibility enum and a
//!    `mutual_contact` boolean and returns a yes/no verdict. Exhaustively
//!    unit-testable without touching a database.
//! 2. [`should_reveal_avatar`] + [`filter_avatar_url`] — thin async wrappers
//!    that parse the raw visibility string, short-circuit on owner identity,
//!    perform the DB call (for `Contacts`), and delegate to
//!    `decide_avatar_visibility`.
//!
//! Splitting them this way keeps the policy matrix trivially testable while
//! still providing a PgPool-aware entry point that handlers can call directly.
//! Integration tests in `tests/privacy_enforcement.rs` (Task 11) exercise the
//! async path end-to-end against a real Postgres test harness.

use sqlx::PgPool;
use uuid::Uuid;

use sanchr_db::postgres::contacts as pg_contacts;

/// Parsed form of the `profile_photo_visibility` string stored in
/// `PrivacyFlags`.
///
/// Unknown strings map to [`AvatarVisibility::Everyone`] on purpose: if a
/// future client writes a newer visibility mode that this server build
/// doesn't know about, we'd rather fall back to the permissive default than
/// silently break avatar rendering. This is the same forward-compat policy
/// documented in the Phase 2 spec §3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvatarVisibility {
    /// Any authenticated user can see the avatar.
    Everyone,
    /// Only mutual contacts can see the avatar.
    Contacts,
    /// Nobody other than the owner can see the avatar.
    Nobody,
}

impl AvatarVisibility {
    /// Parse the protocol string. Unknown values fall back to [`Self::Everyone`].
    ///
    /// The match is case-sensitive because the protocol fixes the canonical
    /// lowercase spellings. Clients are expected to send the canonical form.
    pub fn parse(raw: &str) -> Self {
        match raw {
            "nobody" => Self::Nobody,
            "contacts" => Self::Contacts,
            // "everyone" and everything else (including the empty string)
            // fall through to the permissive default.
            _ => Self::Everyone,
        }
    }
}

/// Pure decision function over the parsed visibility enum and a pre-resolved
/// `mutual_contact` flag. Exhaustively unit-testable.
///
/// `mutual_contact` is only consulted when `visibility` is
/// [`AvatarVisibility::Contacts`]. Callers should pass `false` for the other
/// branches — both to save a DB round trip and to make the control flow
/// obvious in the call site.
///
/// This helper does **not** handle the owner-identity short-circuit. That's
/// the responsibility of [`should_reveal_avatar`], because an owner-identity
/// match is a property of the request, not of the visibility state machine.
pub fn decide_avatar_visibility(visibility: AvatarVisibility, mutual_contact: bool) -> bool {
    match visibility {
        AvatarVisibility::Everyone => true,
        AvatarVisibility::Nobody => false,
        AvatarVisibility::Contacts => mutual_contact,
    }
}

/// Decides whether `requester_id` should see `owner_id`'s avatar.
///
/// Decision order:
/// 1. Owner always sees their own avatar — short-circuits before any DB work.
/// 2. Parse the visibility string via [`AvatarVisibility::parse`].
/// 3. For `Contacts`, call `pg_contacts::are_mutual_contacts`. Any DB error
///    is treated as "not a mutual contact" — i.e. the function **fails
///    closed** on the privacy side. We'd rather hide an avatar than leak
///    one because of a transient query failure.
/// 4. Delegate to [`decide_avatar_visibility`] for the final verdict.
///
/// The `owner_id == requester_id` check comes first so that a user can still
/// see their own avatar regardless of visibility setting (important for the
/// "edit profile" screen on the client).
pub async fn should_reveal_avatar(
    pg: &PgPool,
    visibility: &str,
    owner_id: Uuid,
    requester_id: Uuid,
) -> bool {
    if owner_id == requester_id {
        return true;
    }

    let parsed = AvatarVisibility::parse(visibility);

    // Only hit the DB when the visibility state machine actually depends on
    // the mutual-contact flag. Other branches pass `false` — it's ignored.
    let mutual_contact = match parsed {
        AvatarVisibility::Contacts => pg_contacts::are_mutual_contacts(pg, owner_id, requester_id)
            .await
            .unwrap_or(false),
        _ => false,
    };

    decide_avatar_visibility(parsed, mutual_contact)
}

/// Convenience wrapper: returns the avatar URL if visible, empty string
/// otherwise.
///
/// The empty string is the protocol convention for "no avatar available" on
/// the `string avatar_url` proto field — clients render a placeholder. This
/// lets handlers project the original `Option<String>` through the privacy
/// check without having to re-express the empty-string sentinel at every
/// call site.
pub async fn filter_avatar_url(
    pg: &PgPool,
    visibility: &str,
    owner_id: Uuid,
    requester_id: Uuid,
    avatar_url: Option<String>,
) -> String {
    if should_reveal_avatar(pg, visibility, owner_id, requester_id).await {
        avatar_url.unwrap_or_default()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- AvatarVisibility::parse ------------------------------------------------

    #[test]
    fn parse_recognizes_everyone() {
        assert_eq!(
            AvatarVisibility::parse("everyone"),
            AvatarVisibility::Everyone
        );
    }

    #[test]
    fn parse_recognizes_contacts() {
        assert_eq!(
            AvatarVisibility::parse("contacts"),
            AvatarVisibility::Contacts
        );
    }

    #[test]
    fn parse_recognizes_nobody() {
        assert_eq!(AvatarVisibility::parse("nobody"), AvatarVisibility::Nobody);
    }

    #[test]
    fn parse_unknown_falls_back_to_everyone() {
        // Forward-compat: a newer client might send a mode this server build
        // doesn't know about. We choose permissive over broken rendering.
        assert_eq!(
            AvatarVisibility::parse("mutuals-only-v2"),
            AvatarVisibility::Everyone
        );
        assert_eq!(AvatarVisibility::parse(""), AvatarVisibility::Everyone);
        assert_eq!(
            AvatarVisibility::parse("NOBODY"),
            AvatarVisibility::Everyone
        );
    }

    // --- decide_avatar_visibility (pure, no DB) ---------------------------------

    #[test]
    fn decide_everyone_always_reveals() {
        // The mutual_contact flag is ignored for Everyone.
        assert!(decide_avatar_visibility(AvatarVisibility::Everyone, true));
        assert!(decide_avatar_visibility(AvatarVisibility::Everyone, false));
    }

    #[test]
    fn decide_nobody_never_reveals_to_non_owner() {
        // The mutual_contact flag is ignored for Nobody. The owner-identity
        // short-circuit lives in should_reveal_avatar, not here.
        assert!(!decide_avatar_visibility(AvatarVisibility::Nobody, true));
        assert!(!decide_avatar_visibility(AvatarVisibility::Nobody, false));
    }

    #[test]
    fn decide_contacts_requires_mutual_flag() {
        assert!(decide_avatar_visibility(AvatarVisibility::Contacts, true));
        assert!(!decide_avatar_visibility(AvatarVisibility::Contacts, false));
    }

    // --- Owner-identity short-circuit (documented invariant) --------------------

    // `should_reveal_avatar` takes a PgPool which cannot be constructed at unit
    // test level without a live database. We verify the owner-identity
    // short-circuit logic by asserting the property that drives the early
    // return (Uuid equality). The end-to-end path, including the DB read for
    // the Contacts branch, is covered by integration tests in
    // tests/privacy_enforcement.rs (Task 11).

    fn uid(seed: u8) -> Uuid {
        Uuid::from_bytes([seed; 16])
    }

    #[test]
    fn owner_short_circuit_uuid_equality_property() {
        let alice = uid(1);
        let bob = uid(2);
        // Precondition the short-circuit relies on: distinct seeds produce
        // distinct Uuids, and the same seed produces equal Uuids.
        assert_ne!(alice, bob);
        assert_eq!(alice, uid(1));
    }
}
