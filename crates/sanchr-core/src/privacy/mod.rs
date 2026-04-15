//! Server-side privacy enforcement helpers.
//!
//! This module centralizes the decision logic for which private fields a
//! requester is allowed to observe on another user's records. Keeping these
//! helpers in a single place makes the privacy policy auditable and lets
//! handlers stay thin.
//!
//! See `docs/superpowers/specs/2026-04-10-privacy-phase2-backend-design.md`
//! for the Phase 2 design and threat model.

pub mod avatar;
