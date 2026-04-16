# Consolidated Threat Model

**Project:** Sanchr Backend (OSS)
**Date:** 2026-04-16

This document merges the backend threat model (`backend-threat-model.md`) with the research paper's formal threat framework (T1/T2/T3 x S1/S2/S3).

---

## Threat Actors

| Code | Threat Actor | Description |
|------|-------------|-------------|
| **T1** | Passive server compromise (honest-but-curious) | Server operator or compromised server process observes all data at rest and in transit within the backend, but does not modify it. Follows the protocol faithfully but attempts to learn private information. |
| **T2** | Active server compromise (malicious) | Server operator or compromised server process actively modifies data, injects messages, substitutes keys, or alters protocol flows. Can forge NATS events, manipulate database records, and issue fraudulent certificates. |
| **T3** | Client device compromise | Attacker gains access to a user's device, including local storage, key material, and session tokens. May be a stolen device, malware, or physical access scenario. |

## Security Objectives

| Code | Security Objective | Description |
|------|-------------------|-------------|
| **S1** | Message content confidentiality | The plaintext content of messages must be inaccessible to any party other than the intended sender and recipient(s). |
| **S2** | Metadata privacy (who talks to whom, when) | Communication patterns -- sender identity, recipient identity, timing, frequency, and group membership -- must be protected or minimized. |
| **S3** | Auxiliary state (contact lists, keys, media references) | Stored state beyond message content -- contact graphs, pre-key bundles, media metadata, vault items, backup metadata, discovery queries -- must be protected with appropriate access controls and time bounds. |

---

## 3x3 Threat Matrix

### T1 x S1: Passive Server vs. Message Confidentiality

**Defense:** End-to-end encryption (Signal Protocol / Double Ratchet)

**Implementation:** Message content is encrypted client-side before reaching the server. The server stores and relays opaque ciphertext blobs in ScyllaDB outboxes (`crates/sanchr-db/src/scylla/`). The server never possesses plaintext message content or the session keys needed to decrypt it.

**Crate:** `sanchr-core` (messaging handlers store/relay ciphertext), `sanchr-proto` (message protobuf carries `ciphertext` bytes fields)

**Formal property:** An honest-but-curious server that faithfully stores and forwards encrypted messages learns nothing about message content beyond ciphertext length and timing metadata.

**Residual risk:** Ciphertext length may leak information about message type (text vs. media reference vs. reaction). Timing metadata is visible (see T1 x S2).

---

### T1 x S2: Passive Server vs. Metadata Privacy

**Defense:** Sealed sender protocol, delivery tokens, timing obfuscation (planned)

**Implementation:**
- **Sealed sender certificates** (`crates/sanchr-server-crypto/src/sealed_sender.rs`): Ed25519-signed `SenderCertificate` protos with 24h TTL. The sealed sender flow allows the sending client to encrypt the sender identity within the message envelope. The server relay processes sealed messages (`crates/sanchr-core/src/messaging/sealed_handler.rs`) using one-time delivery tokens (`crates/sanchr-db/src/redis/delivery_tokens.rs`) so the server does not learn who is sending to whom.
- **Delivery tokens** are single-use, Redis-stored credentials that allow anonymous message submission without revealing the sender's identity to the server.

**Crate:** `sanchr-server-crypto` (certificate signing), `sanchr-core` (sealed handler, relay bridge), `sanchr-db` (delivery token storage)

**Formal property:** Under sealed sender, a passive server learns only that *some* authenticated user submitted a message for a given recipient device. The sender identity is encrypted within the sealed envelope. Without the recipient's identity key, the server cannot determine the sender.

**Residual risks:**
- Timing correlation: the server sees when sealed messages arrive and when recipients fetch them.
- Delivery token acquisition reveals that a sender intends to communicate with a specific recipient.
- Sealed sender signer key is ephemeral in dev mode (TM-005); production signer integration is not in the public repo.

---

### T1 x S3: Passive Server vs. Auxiliary State

**Defense:** OPRF-based private contact discovery, EKF lifecycle enforcement, salted Bloom filters, HKDF-derived media keys

**Implementation:**
- **OPRF contact discovery** (`crates/sanchr-psi/src/oprf.rs`): Ristretto255-based 2-HashDH-OPRF. Client blinds phone number hashes before sending to server. Server evaluates under secret scalar `k` without learning the input. Result: `k * H(phone)` -- client can check membership without revealing their contact list.
- **Salted Bloom filter** (`crates/sanchr-psi/src/bloom.rs`): Fast-path membership test with daily-rotating salt via EKF. SHA-256 salted hashing with double-hashing for k bit indices.
- **EKF lifecycle** (`crates/sanchr-core/src/ekf/manager.rs`): Periodic tick loop (default 60s) scans key classes (Presence, Discovery, PreKey, Media) for expired entries. Applies Rotate/Delete/Overwrite policies with grace period (default 3600s).
- **HKDF-derived media keys** (`crates/sanchr-psi/src/hkdf_utils.rs`): Media encryption keys derived from chain keys using domain-separated HKDF-SHA256 with forward-secrecy chain advancement.
- **Media key verification** (`crates/sanchr-server-crypto/src/media_keys.rs`): Server-side constant-time verification of client-claimed media keys against chain_key + file_hash derivation.

**Crate:** `sanchr-psi` (OPRF, Bloom filter, HKDF), `sanchr-core` (EKF manager, discovery handlers), `sanchr-server-crypto` (media key verification)

**Formal property:** A passive server cannot enumerate the client's contact list from OPRF queries (obliviousness property of 2-HashDH-OPRF under DDH assumption on Ristretto255). Auxiliary state entries expire according to EKF policies, limiting the temporal window of exposure.

**Residual risks:**
- OPRF secret is ephemeral in dev if `oprf_secret_hex` is not configured.
- Discovery daily salt and OPRF set elements are served to authenticated users; rate limits bound but do not prevent determined enumeration over time.
- Media/backup/vault retention depends on S3 lifecycle policies and EKF enforcement actually running; no integration tests prove deletion (TM-007).

---

### T2 x S1: Active Server vs. Message Confidentiality

**Defense:** Client-side identity key verification, key transparency (planned)

**Implementation:** The server distributes pre-key bundles (`crates/sanchr-core/src/keys/handlers.rs`) but cannot forge valid identity keys without breaking the client's key verification. Clients are expected to verify identity keys out-of-band (safety numbers). The server stores public key material only.

**Crate:** `sanchr-core` (key service), `sanchr-proto` (key bundle protobuf)

**Formal property:** An active server that substitutes pre-key bundles is detectable by clients that verify identity keys. The Signal Protocol provides forward secrecy: even if a session key is compromised, past messages remain confidential.

**Residual risks:**
- No key transparency log is implemented in this repository. Key substitution by a malicious server is undetectable without out-of-band verification.
- KeyService RPCs are rate-limited (GetPreKeyBundle: 60/hr, UploadPreKeys: 10/hr, UploadSignedPreKey: 10/hr), but a malicious server itself is not bound by its own rate limits.

---

### T2 x S2: Active Server vs. Metadata Privacy

**Defense:** Sealed sender (partial protection), limited by server's routing role

**Implementation:** Even under sealed sender, an active server retains the ability to:
- Observe delivery timing and recipient identifiers (sealed sender protects sender identity only)
- Correlate message submission and retrieval patterns
- Inject NATS relay events to probe for active connections (TM-003)

**Crate:** `sanchr-core` (relay bridge, stream manager), `sanchr-call` (signaling)

**Formal property:** Sealed sender provides sender anonymity against the server under the assumption that the server cannot break the sealed envelope encryption. However, an active server can perform traffic analysis, selective dropping, or replay to infer communication patterns.

**Residual risks:**
- NATS event injection allows a malicious server (or compromised pod) to forge relay events (TM-003).
- No padding or dummy traffic to prevent traffic analysis.
- Call signaling metadata (caller, callee, duration) is fully visible to the server.
- Presence information and push notification routing reveal activity patterns.

---

### T2 x S3: Active Server vs. Auxiliary State

**Defense:** EKF enforcement, client-side encryption of vault/backup/media content

**Implementation:**
- Vault items, backup payloads, and media blobs are encrypted client-side. The server stores ciphertext and metadata.
- EKF lifecycle enforcement (`crates/sanchr-core/src/ekf/`) provides automatic expiry, but an active server could disable the EKF loop or skip deletions.
- S3 lifecycle policies provide a second layer of time-bounded retention, but are operator-configured.

**Crate:** `sanchr-core` (EKF, vault, backup, media handlers), `sanchr-db` (ScyllaDB auxiliary state)

**Formal property:** Client-side encryption ensures that even an active server cannot read vault/backup/media content. However, an active server can retain metadata, extend retention windows, or refuse to delete expired entries.

**Residual risks:**
- Scylla startup code drops vault tables in dev/staging (TM-007) -- if executed in production, causes data loss.
- Server controls retention: a malicious operator can keep metadata indefinitely despite EKF policies.
- Media metadata (file hashes, sizes, upload times, ownership) is server-readable even though content is encrypted.
- Contact discovery responses reveal registered-user set membership to the server.

---

### T3 x S1: Device Compromise vs. Message Confidentiality

**Defense:** Client-side key management (out of scope for this backend audit)

**Implementation:** The backend stores no plaintext messages or session keys. A compromised device has access to all local key material and message history stored on that device. The server's role is limited to providing refresh/access tokens for that device's sessions.

**Crate:** Not applicable to backend (client-side concern)

**Formal property:** Forward secrecy from the Double Ratchet protocol limits exposure: compromise of current session keys does not reveal past messages (assuming ratchet state has advanced). Future secrecy is provided by the ratchet mechanism: the compromised session eventually heals if the attacker loses access.

**Residual risks (backend-relevant):**
- Stolen refresh tokens allow persistent session access. Refresh tokens are hashed in Postgres (`crates/sanchr-db/src/postgres/refresh_tokens.rs`) and rotated on use, but there is no evidence of revocation on device deregistration.
- A compromised device can upload malicious pre-keys, potentially degrading security for future sessions with that user.
- Registration lock PIN protects against SIM-swap account takeover, but only if the user has enabled it.

---

### T3 x S2: Device Compromise vs. Metadata Privacy

**Defense:** Session isolation, per-device tokens

**Implementation:** Each device has its own JWT access token with device ID claim (`did` field in JWT claims). Session management is per-device in Redis (`crates/sanchr-db/src/redis/sessions.rs`).

**Crate:** `sanchr-server-crypto` (JWT with device ID), `sanchr-db` (per-device sessions)

**Formal property:** Compromise of one device's session tokens does not directly expose metadata from other devices belonging to the same user. Each device must independently authenticate.

**Residual risks:**
- A compromised device reveals all contacts, communication partners, and timing information stored on that device.
- The device can query discovery endpoints to enumerate registered users within rate limits.
- Call history and presence state for the compromised device's sessions are accessible.

---

### T3 x S3: Device Compromise vs. Auxiliary State

**Defense:** EKF time-bounding (server-side), client-side key deletion (out of scope)

**Implementation:** The server's EKF lifecycle enforcement ensures that server-held auxiliary state (pre-keys, discovery entries, media metadata) expires. A compromised device has access to its own vault, backup, and media keys, but the server does not return other users' auxiliary state.

**Crate:** `sanchr-core` (EKF, ownership checks on vault/media/backup)

**Formal property:** Server-side ownership checks prevent a compromised device from accessing other users' auxiliary state. Time-bounded EKF enforcement limits the window during which server-held state for the compromised user remains available.

**Residual risks:**
- All locally cached auxiliary state (contact list, pre-key material, vault decryption keys) is exposed.
- Backup restoration on a new device is possible if the attacker has the backup decryption key.
- Server-side ownership checks are the primary access control; no additional device attestation is performed.

---

## Summary Matrix

| | S1: Message Content | S2: Metadata Privacy | S3: Auxiliary State |
|---|---|---|---|
| **T1: Passive Server** | **Strong.** E2EE prevents content access. Ciphertext length leaks type. | **Partial.** Sealed sender hides sender identity. Timing, delivery patterns visible. | **Partial.** OPRF discovery, EKF lifecycle, salted Bloom. Contact sync response redacted. |
| **T2: Active Server** | **Strong (with client verification).** Key substitution detectable via safety numbers. No key transparency log. | **Weak.** Active server can correlate traffic, inject NATS events, observe all routing metadata. | **Partial.** Client-side encryption protects content. Server controls retention and metadata. |
| **T3: Device Compromise** | **Bounded by forward secrecy.** Past messages protected; current session exposed. | **Exposed on device.** All local metadata accessible. Server limits cross-device exposure. | **Exposed on device.** Server ownership checks prevent cross-user access. EKF bounds server-side window. |

---

## Tamarin Model References

The research paper references formal verification using Tamarin prover for the following properties. The backend repository does not contain Tamarin models; these references are to the paper's formal analysis:

1. **OPRF obliviousness:** Server learns nothing about client input from blinded queries (DDH assumption on Ristretto255)
2. **Sealed sender sender-anonymity:** Server cannot determine sender identity from sealed envelopes
3. **EKF forward erasure:** Expired auxiliary state cannot be recovered after deletion/overwrite
4. **Media chain forward secrecy:** Previous chain keys cannot be derived from current chain key (one-way HKDF advancement)

**Note:** The Tamarin models verify protocol-level properties. The implementation gap between the formal model and the running code is the primary subject of this security audit. Key areas where implementation may diverge from the formal model are documented in `known-issues.md` under TM-005.
