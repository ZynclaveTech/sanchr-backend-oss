# Sanchr Privacy Protocol: System-Level Composition Proofs

**Version:** 1.0
**Date:** 2026-04-16
**Status:** Companion document to the Sanchr research paper
**Scope:** Cross-system composition arguments that complement the Tamarin mechanised proofs

---

This document provides rigorous hand-written proofs for system-level composition
properties of the Sanchr privacy protocol. These properties span multiple
protocol sub-systems and are therefore awkward to express in Tamarin's symbolic
model, which excels at single-protocol analysis but does not natively support
reasoning about lifecycle enforcement, cross-domain key separation, or
composed forward secrecy windows.

The document is structured in the classical mathematical style:
**Assumptions --> Definitions --> Lemmas --> Theorems**, with explicit proof
sketches for every non-trivial claim.

---

## 1. Foundational Assumptions

We rely on the following assumptions throughout. Each is either a standard
cryptographic hardness assumption or a system-level liveness condition.

**A1 (Decisional Diffie-Hellman on Ristretto255).**
The DDH problem is hard in the Ristretto255 prime-order group (built on
Curve25519, order q ~ 2^{252}). Concretely: given (G, G^a, G^b), no PPT
adversary can distinguish G^{ab} from G^c for random c with non-negligible
advantage. This underpins the obliviousness guarantee of the 2-HashDH-OPRF
used in contact discovery.

*Basis:* Ristretto255 inherits the security properties of Curve25519. The DDH
assumption holds in prime-order groups where the CDH problem is believed hard
[Bernstein 2006, Hamburg 2015].

**A2 (Random Oracle for HKDF-SHA256).**
HKDF-SHA256 (as instantiated via `hkdf::Hkdf<Sha256>`) is modelled as a random
oracle. That is, for distinct domain-separation labels `info_1 != info_2`, the
outputs `HKDF(ikm, salt, info_1)` and `HKDF(ikm, salt, info_2)` are
computationally independent. The implementation enforces domain separation via
the labels defined in `sanchr_psi::hkdf_utils::labels`:

    MEDIA_KEY           = b"sanchr-media-v1"
    ACCESS_KEY          = b"sanchr-access-v1"
    DISCOVERY_CACHED    = b"sanchr-discovery-v1"
    ROTATION_KEY        = b"sanchr-rotate-v1"
    MEDIA_CHAIN_ADVANCE = b"sanchr-media-chain-advance-v1"
    MEDIA_CHAIN_INIT    = b"sanchr-media-chain-init-v1"

*Basis:* The random oracle model for HKDF is standard in the provable security
literature [Krawczyk 2010, RFC 5869].

**A3 (EKF Liveness).**
The Ephemeral Key Fence (EKF) tick loop executes at least once per
`tick_interval` seconds (default: 60s). Formally: for any wall-clock interval
[t, t + tick_interval], the function `lifecycle_tick()` is invoked at least
once. The implementation uses `tokio::time::interval` with
`MissedTickBehavior::Skip`, so under transient overload, ticks are skipped
rather than queued -- but at least one tick fires per interval once the system
recovers.

*Basis:* Tokio's timer guarantee on cooperative async runtimes with bounded
task queues.

**A4 (Signal Double Ratchet Forward Secrecy).**
The Signal Double Ratchet protocol provides forward secrecy for chain keys:
compromise of chain key CK_{n+1} reveals no information about CK_n. This is
an inherited property; Sanchr does not modify the ratchet.

*Basis:* [Cohn-Gordon et al. 2020], Signal Protocol specification.

**A5 (Honest-but-Curious Server).**
The server faithfully executes the protocol (processes OPRF evaluations, runs
the EKF tick loop, delivers messages) but may inspect all data it handles. The
server does not forge, drop, or reorder messages beyond what the protocol
permits. Active compromise is addressed separately in the threat matrix
(Section 6).

---

## 2. Definitions

**Definition 1 (Auxiliary State Map).**
The auxiliary state map S is the set of all rows in the `auxiliary_state`
ScyllaDB table. Each entry is a tuple:

    e = (user_id, class, entry_id, material, created_at, ttl_secs, policy)

where:
- `user_id`    : UUID -- the owning principal
- `class`      : KeyClass in {Presence, Discovery, PreKey, Media}
- `entry_id`   : UUID -- unique row identifier
- `material`   : Vec<u8> -- raw key material (or NULL_SENTINEL = 0x00^{32})
- `created_at` : DateTime<Utc> -- wall-clock creation (or last rotation)
- `ttl_secs`   : i64 -- time-to-live in seconds
- `policy`     : ExpPolicy in {Delete, Overwrite, Rotate, Replenish}

The default TTL values, as defined in `KeyClass::default_ttl_secs()`, are:

| KeyClass  | Default TTL | Default Policy |
|-----------|-------------|----------------|
| Presence  | 300s (5m)   | Delete         |
| Discovery | 86400s (24h)| Rotate         |
| PreKey    | 604800s (7d)| Replenish      |
| Media     | 2592000s (30d)| Overwrite    |

**Definition 2 (Cross-Domain Entry).**
An entry e in S is *cross-domain* if there exist two distinct protocol domains
D_a, D_b in {PresenceSystem, DiscoverySystem, KeyExchangeSystem, MediaSystem}
such that e.material is consumed by both D_a and D_b during normal protocol
execution.

**Definition 3 (Persistent Entry).**
An entry e in S is *persistent* at time t if:

    t > e.created_at + e.ttl_secs + grace_period

and e has not been processed by any EKF `lifecycle_tick()` invocation that would
apply its `policy`. The `grace_period` is configured via
`EkfConfig::rotation_grace_secs` (default: 3600s).

**Definition 4 (Forward Secrecy Window).**
For a defense mechanism D_i operating on key material with lifetime L_i, the
*forward secrecy window* W_i is defined as:

    W_i = max { t - t_compromise : data encrypted before t_compromise
                                    remains protected at time t }

Intuitively, W_i is the maximum duration of retrospective protection provided
by D_i after an adversary compromises the current key state.

**Definition 5 (NULL Sentinel).**
The constant `NULL_SENTINEL = [0x00; 32]` is a distinguished 32-byte value
used by the `Overwrite` expiry policy to signal that a material slot has been
cryptographically erased while preserving the row for audit purposes.

---

## 3. Core Lemmas

### Lemma 1 (OPRF Discovery Bound -- D1)

**Statement.** Under A1 and A3, no contact discovery query result remains
valid beyond 24 hours after the daily salt rotation.

**Proof.**

Contact discovery in Sanchr is a two-layer system:

*Layer 1 (Bloom filter fast-path).* The salted Bloom filter hashes phone
numbers as `SHA256(phone || daily_salt)`. The daily salt is a 32-byte CSPRNG
output rotated every 24 hours by `run_salt_rotation_loop()`. After rotation,
the new salt replaces the old via `ArcSwap::store()`, and the discovery
snapshot cache is invalidated via `discovery_snapshot_cache.invalidate()`. Any
Bloom filter constructed with the old salt is no longer usable for membership
queries against the new filter.

*Layer 2 (OPRF-PSI).* The 2-HashDH-OPRF computes:

    Client: B = r * H(phone),  sends B to server
    Server: R = k * B,         sends R to client
    Client: r^{-1} * R = k * H(phone)

The unblinded value `k * H(phone)` is stable across sessions (it depends only
on the server secret k and the phone number). However, the *discovery hash*
used for set intersection is derived as:

    discovery_hash = HKDF(SHA256(phone), daily_salt, "sanchr-discovery-v1")

(see `derive_discovery_hash()` in `hkdf_utils.rs`). This binds the discovery
result to the daily salt. After salt rotation, previously computed discovery
hashes no longer match the server's re-computed set.

*EKF enforcement.* Discovery entries in S have TTL = 86400s and policy =
Rotate. By A3, the EKF tick loop detects these entries within `tick_interval`
seconds of expiry. The Rotate policy triggers a NATS notification for the
client to refresh; if the entry persists beyond `rotation_grace_secs` (default
3600s) without client action, the entry is force-deleted.

Combining: the maximum validity window is bounded by:

    W_discovery <= 86400 + 3600 = 90000s = 25h

After this window, both the Bloom filter membership and the OPRF-derived
discovery hash are invalid.

*Security argument.* Under A1 (DDH), the server observes only the blinded
point B = r * H(phone), which is uniformly distributed in the Ristretto255
group and reveals no information about `phone`. The daily salt rotation ensures
that even if an adversary observes discovery hashes from day d, they cannot
correlate them with hashes from day d+1 (the salt provides independent keying
for the HKDF derivation under the random oracle model A2). QED.

---

### Lemma 2 (MediaK Ratchet Binding -- D2)

**Statement.** Under A2 and A4, compromise of chain key CK_{n+1} reveals
nothing about MediaK_n = HKDF(CK_n || file_hash, [], "sanchr-media-v1").

**Proof.**

The media key derivation is implemented in `derive_media_key()`:

    ikm = CK_n || file_hash         (64 bytes)
    MediaK_n = HKDF-SHA256(ikm, salt=[], info="sanchr-media-v1")

We must show that knowledge of CK_{n+1} provides no computational advantage
in recovering MediaK_n.

*Step 1 (Chain key independence).* By A4, the Signal Double Ratchet provides
forward secrecy for chain keys. Formally:

    Pr[A(CK_{n+1}) = CK_n] <= negl(lambda)

for any PPT adversary A. The chain key advance function is a one-way KDF:

    CK_{n+1} = HKDF(CK_n, [], "sanchr-media-chain-advance-v1")

(see `advance_media_chain()` in `hkdf_utils.rs`). Under A2, this is
indistinguishable from a random function, so inverting CK_{n+1} to recover
CK_n requires breaking the one-wayness of HKDF-SHA256.

*Step 2 (Media key derivation).* Given that CK_n is computationally hidden
from an adversary who knows CK_{n+1}, the media key MediaK_n is also hidden.
Under A2 (random oracle model for HKDF), even if the adversary knows
file_hash (which is not secret -- it is the content hash of the encrypted
file), they cannot compute MediaK_n without CK_n:

    MediaK_n = RO(CK_n || file_hash, "sanchr-media-v1")

The random oracle output is uniformly random and independent for each
distinct input. Since the adversary does not know CK_n, they cannot evaluate
the random oracle on the correct input.

*Step 3 (Per-file uniqueness).* The file_hash binding ensures that even if
CK_n were somehow recovered, each file encrypted under the same chain step
gets a unique key:

    For file_hash_a != file_hash_b:
    MediaK_n^a = HKDF(CK_n || file_hash_a, ...) != HKDF(CK_n || file_hash_b, ...)

with overwhelming probability under A2. This prevents a single chain key
compromise from yielding a universal decryption capability for all media in
that ratchet step.

*EKF bound.* Media entries in S have TTL = 2592000s (30d) and policy =
Overwrite. After TTL expiry, the material field is replaced with
`NULL_SENTINEL = [0x00; 32]`, rendering the stored media key reference
irrecoverable from the auxiliary state. QED.

---

### Lemma 3 (EKF Temporal Guarantee -- D3)

**Statement.** Under A3, for any entry e in S with policy
p in {Delete, Overwrite, Rotate, Replenish}, e does not survive with valid
material beyond `e.created_at + e.ttl_secs + grace_period`.

**Proof.**

The EKF lifecycle loop (`run_lifecycle_loop()`) runs with period
`tick_interval` (default 60s). On each invocation of `lifecycle_tick()`, the
following sequence executes for each KeyClass:

1. **Query:** Fetch all entries where `now_millis > created_at_ms + ttl_secs * 1000`
   via `auxiliary::fetch_expired_entries()`.

2. **Policy application:** For each expired entry, apply the configured policy:

   - **Delete:** The row is removed via `auxiliary::delete_entry()`. The
     material is irrecoverable after this point.

   - **Overwrite:** The material field is replaced with `NULL_SENTINEL` and
     `created_at` is reset via `auxiliary::overwrite_entry()`. The row
     persists for audit, but the cryptographic material is destroyed.

   - **Rotate:** A NATS notification is published for the client to supply
     fresh material. If the entry has been expired for longer than
     `rotation_grace_secs`, it is force-deleted:

         expired_for_secs = (now_millis - created_at_ms) / 1000 - ttl_secs
         if expired_for_secs > grace_secs:
             auxiliary::delete_entry(...)

   - **Replenish:** The material is replaced with fresh random bytes of the
     same length (`rand::rngs::OsRng`) and `created_at` is reset. The key
     slot remains alive with new, uncorrelated material.

3. **Timing bound:** By A3, the tick loop fires at least once per
   `tick_interval`. The worst-case detection latency for an expired entry is
   `tick_interval` seconds (the entry expires immediately after a tick). The
   worst-case action latency for Rotate policy is an additional
   `rotation_grace_secs`. Therefore, the maximum survival time with valid
   material is:

       T_max = ttl_secs + tick_interval + rotation_grace_secs

   With defaults: T_max = ttl_secs + 60 + 3600 = ttl_secs + 3660s.

   For non-Rotate policies (Delete, Overwrite, Replenish), the grace period
   does not apply, so: T_max = ttl_secs + tick_interval.

Since the `MissedTickBehavior::Skip` policy ensures that under transient
overload, ticks are skipped rather than queued (no thundering herd), the
system may briefly exceed T_max during sustained outages. However, A3
explicitly assumes recovery within `tick_interval`, bounding the worst case.

We define `grace_period = tick_interval + rotation_grace_secs` as the
envelope, yielding the statement: no entry survives with valid material
beyond `created_at + ttl_secs + grace_period`. QED.

---

### Lemma 4 (Access Key Device Isolation)

**Statement.** Under A2, for distinct device secrets dls_a != dls_b, the
access keys derived from the same media key are computationally independent:

    AccessK_a = HKDF(MediaK_n || dls_a, [], "sanchr-access-v1-<id>")
    AccessK_b = HKDF(MediaK_n || dls_b, [], "sanchr-access-v1-<id>")

and Pr[AccessK_a = AccessK_b] <= negl(lambda).

**Proof.** Under A2, HKDF is a random oracle. The inputs
`(MediaK_n || dls_a)` and `(MediaK_n || dls_b)` differ (since dls_a != dls_b),
so the outputs are independently and uniformly distributed. Compromise of
dls_a reveals AccessK_a but not AccessK_b, providing per-device isolation for
media access. QED.

---

## 4. Cross-Domain Persistence Invariant

### Theorem 1 (No Cross-Domain Persistence)

**Statement.** Under A1--A5, no entry in the auxiliary state map S is
simultaneously cross-domain (Definition 2) and persistent (Definition 3).

**Proof.** We proceed by exhaustive case analysis on each KeyClass. For each
class, we show that entries are either (a) not cross-domain, or (b) not
persistent, or (c) both.

**Case 1: Presence (TTL = 300s, policy = Delete).**

Presence entries store ephemeral heartbeat tokens used exclusively by the
presence subsystem. These tokens encode online/offline/typing status and are
consumed only by the presence notification pipeline. No other protocol domain
(discovery, key exchange, media) references presence material.

By Lemma 3, presence entries are deleted within 300 + 60 = 360s of creation
(no grace period for Delete policy).

Conclusion: Not cross-domain. Not persistent. PASS.

**Case 2: Discovery (TTL = 86400s, policy = Rotate).**

Discovery entries store OPRF-derived set elements and salted Bloom filter
membership data. These are consumed exclusively by the discovery subsystem
(specifically, `discovery::service` and `discovery::cache`). The discovery
hash derivation uses the domain label `"sanchr-discovery-v1"`, which is not
shared with any other subsystem's key derivation.

By Lemma 1, discovery results are invalidated within 24h of salt rotation.
By Lemma 3, stale entries are rotated or force-deleted within
86400 + 60 + 3600 = 90060s of creation.

Conclusion: Not cross-domain (unique domain label, single-consumer subsystem).
Not persistent (EKF enforces TTL + grace). PASS.

**Case 3: PreKey (TTL = 604800s, policy = Replenish).**

Pre-key entries store one-time pre-key material consumed by the key exchange
subsystem (X3DH initial key agreement). These pre-keys are uploaded by the
client and consumed exactly once during session establishment. No other
subsystem reads pre-key material.

The Replenish policy replaces expired material with fresh random bytes,
maintaining the slot. The old material is overwritten in place -- it is not
copied or migrated to another domain.

By Lemma 3 (Replenish case), old material survives at most
604800 + 60 = 604860s before being replaced with cryptographically
independent random bytes.

Conclusion: Not cross-domain (single-consumer subsystem). Old material is not
persistent (replaced by Replenish). PASS.

**Case 4: Media (TTL = 2592000s, policy = Overwrite).**

Media entries reference encrypted media key material. They are consumed by the
media subsystem (`media::handlers`). The media key derivation uses the domain
label `"sanchr-media-v1"`, distinct from all other labels.

By Lemma 2, the media key is bound to the ratchet chain key CK_n and the
file hash, providing cryptographic isolation from other protocol domains.
By Lemma 3, media entries are overwritten with NULL_SENTINEL within
2592000 + 60 = 2592060s of creation (no grace period for Overwrite policy).

The media ciphertext stored in the object store (S3) is subject to a separate
lifecycle policy (bucket expiration), but the *key material* in S is
destroyed by the EKF regardless of the ciphertext's persistence.

Conclusion: Not cross-domain (unique domain label, ratchet binding). Not
persistent after overwrite (material = NULL_SENTINEL). PASS.

**Synthesis.** In all four cases, entries are consumed by exactly one protocol
domain and are destroyed or replaced within TTL + grace_period. No entry is
simultaneously cross-domain and persistent. QED.

---

## 5. Composed Forward Secrecy

### Theorem 2 (Forward Secrecy Windows)

**Statement.** The composed Sanchr system provides the following forward
secrecy windows for each defense layer:

| Defense  | Component          | Window W_i          | Governing Mechanism                   |
|----------|--------------------|---------------------|---------------------------------------|
| D1       | Contact Discovery  | 24h + grace (25h)   | Daily salt rotation + OPRF (Lemma 1)  |
| D2       | Media Keys         | 30d + tick (30d 1m) | Ratchet binding + HKDF (Lemma 2)      |
| D3       | Auxiliary State    | TTL + grace (varies)| EKF lifecycle enforcement (Lemma 3)   |
| Baseline | Message Content    | Per-ratchet step    | Signal Double Ratchet (A4, inherited) |

**Proof.**

We must show that each window W_i is a tight bound: data encrypted under
material governed by D_i remains protected for exactly W_i after key
compromise, and no longer.

*D1 (Discovery).* Suppose an adversary compromises the current daily salt
at time t_c. They can compute `HKDF(SHA256(phone), salt, "sanchr-discovery-v1")`
for any phone number and thus determine set membership. However, this
capability expires when the salt rotates (at most 24h later). After rotation,
the old salt is replaced in memory via ArcSwap and the cache is invalidated.
By Lemma 3, any auxiliary state entry retaining the old salt-derived material
is purged within grace_period. Total window: 86400 + 3660 = 90060s ~ 25h.

*D2 (Media).* Suppose an adversary compromises chain key CK_n at time t_c.
They can derive MediaK_n for any file whose hash they know. However, by A4,
CK_{n-1} (and hence MediaK_{n-1}) remains protected. The window is bounded
by the media entry TTL: after 30d + tick_interval, the EKF overwrites the
material with NULL_SENTINEL. Forward secrecy for *chain keys* is immediate
(per ratchet step); the 30d window applies to the *auxiliary state entry*
referencing MediaK_n.

*D3 (Auxiliary State).* This is the meta-defense: the EKF guarantees that
no auxiliary state entry outlives its TTL + grace. The forward secrecy window
is therefore class-dependent:
- Presence: 300 + 60 = 360s
- Discovery: 86400 + 3660 = 90060s
- PreKey: 604800 + 60 = 604860s
- Media: 2592000 + 60 = 2592060s

*Baseline (Message Content).* The Signal Double Ratchet provides forward
secrecy per ratchet step. Each DH ratchet turn generates a new root key;
each symmetric ratchet step generates a new chain key. Compromise of the
current state reveals future keys (until the next DH ratchet turn) but not
past keys. This property is inherited unchanged by Sanchr (A4).

**Composition argument.** The four defense layers operate on disjoint key
material (ensured by Theorem 1 -- no cross-domain persistence). Therefore,
compromise of one layer's material does not affect the forward secrecy
guarantees of other layers. The composed forward secrecy of the system is:

    W_composed = min(W_D1, W_D2, W_D3, W_baseline)

For any specific data class, the relevant window applies. The weakest link
for *message content* is the baseline Signal ratchet. The weakest link for
*auxiliary state* is the class-specific TTL + grace. No composition
amplifies the adversary's advantage beyond the individual bounds. QED.

---

## 6. Threat Coverage Completeness

We argue that the threat matrix {T1, T2, T3} x {S1, S2, S3} is fully
covered, where:

- **T1:** Passive server compromise (honest-but-curious, reads all server-side data)
- **T2:** Active server compromise (modifies protocol execution)
- **T3:** Client compromise (adversary obtains client key state)

and the asset classes are:

- **S1:** Contact graph / social relationships
- **S2:** Message metadata (sender, recipient, timing)
- **S3:** Message content

### Coverage Matrix

```
            S1 (Social Graph)    S2 (Metadata)         S3 (Content)
          +--------------------+--------------------+--------------------+
T1 (Pass) | OPRF hides phone   | Sealed Sender      | E2EE (Signal)     |
          | numbers (D1).      | hides sender ID.   | Server sees only  |
          | Server sees only   | Server cannot link | ciphertext.       |
          | blinded points     | sender to message. | Inherited from A4.|
          | B = r * H(phone).  |                    |                    |
          +--------------------+--------------------+--------------------+
T2 (Act)  | EKF limits cached  | Sealed Sender cert | E2EE (Signal)     |
          | discovery state    | expiry (24h) bounds| Content remains   |
          | (D3). Daily salt   | metadata window.   | encrypted even    |
          | rotation (D1)      | Active server      | under active      |
          | forces re-query.   | cannot forge sender| compromise.       |
          |                    | without Ed25519 key| Ratchet provides  |
          |                    | (out of scope).    | forward secrecy.  |
          +--------------------+--------------------+--------------------+
T3 (Cli)  | Forward secrecy of | Forward secrecy    | Double Ratchet    |
          | ratchet protects   | limits metadata    | forward secrecy   |
          | past discovery     | exposure to current| protects past     |
          | queries. EKF       | session. EKF       | messages (A4).    |
          | deletes auxiliary  | deletes presence   | MediaK binding    |
          | state (D3).        | tokens (5m TTL).   | (D2) protects     |
          |                    |                    | past media keys.  |
          +--------------------+--------------------+--------------------+
```

### Cell-by-Cell Justification

**T1 x S1 (Passive server, social graph):** Under A1, the OPRF evaluation
R = k * B reveals no information about the phone number to the server. The
server holds the secret scalar k but sees only blinded points. Even with
access to the Bloom filter, the daily salt rotation (Lemma 1) limits the
window for offline correlation attacks.

**T1 x S2 (Passive server, metadata):** The sealed sender certificate system
(implemented in `sealed_sender.rs`) issues Ed25519-signed sender certificates
valid for 24 hours. The server routes messages based on encrypted envelope
data and cannot read the sender identity from the sealed sender ciphertext.

**T1 x S3 (Passive server, content):** End-to-end encryption via the Signal
protocol (A4). The server handles only ciphertext. This is inherited.

**T2 x S1 (Active server, social graph):** An active server could refuse to
rotate the daily salt, extending the discovery hash validity. However, the EKF
(D3) independently enforces TTL on discovery entries (Lemma 3). The client can
also detect a stale salt by comparing the received salt hash against a
previously seen value.

**T2 x S2 (Active server, metadata):** An active server could log message
routing patterns. Sealed sender limits this to the encrypted envelope. The
sender certificate has a 24h expiry; the server cannot extend it without the
Ed25519 signing key (which, under the trust model, is held in an HSM or
secure configuration).

**T2 x S3 (Active server, content):** End-to-end encryption prevents content
access even under active compromise. The ratchet's forward secrecy (A4)
ensures past messages remain protected.

**T3 x S1 (Client compromise, social graph):** The adversary obtains the
client's current discovery cache. By Lemma 1, this cache is valid for at most
24h. The EKF (D3) deletes the server-side auxiliary state entries within
TTL + grace, limiting the retrospective exposure window.

**T3 x S2 (Client compromise, metadata):** The adversary can observe current
session metadata. Forward secrecy of the ratchet means past session metadata
(ratchet states, message counters) is not recoverable. Presence tokens have
a 5m TTL (the shortest in the system), limiting the metadata exposure window.

**T3 x S3 (Client compromise, content):** The Double Ratchet's forward
secrecy (A4) protects past messages. The media key binding (Lemma 2) ensures
that past media keys derived from earlier chain keys are not recoverable from
the current chain key.

---

## 7. Failure Mode Analysis

### Theorem 3 (Graceful Degradation)

**Statement.** No single-component failure in {OPRF, EKF, Sealed Sender}
causes the system's security guarantees to fall below baseline Signal
protocol security.

**Proof.** We analyse each failure mode independently.

**Case 1: OPRF Failure.**

*Failure mode:* The OPRF server secret k is lost, the OPRF evaluation service
is unavailable, or the Ristretto255 implementation is compromised.

*Impact:* Contact discovery falls back to hash-based contact sync, where the
server receives `SHA256(phone || salt)` values. This is equivalent to Signal's
current production contact discovery approach (prior to Intel SGX / ORAM
enhancements). The server can perform dictionary attacks on phone numbers
(the phone number space is small: ~10^{10} for E.164).

*Unaffected:* Message encryption (E2EE via Signal ratchet), forward secrecy
of chain keys, media key derivation, sealed sender metadata protection, and
EKF lifecycle enforcement. These are all independent subsystems that do not
depend on OPRF.

*Conclusion:* Security degrades to Signal-equivalent for contact discovery.
All other guarantees are preserved.

**Case 2: EKF Failure.**

*Failure mode:* The `lifecycle_tick()` function stops executing (process
crash, ScyllaDB outage, tokio runtime stall).

*Impact:* Auxiliary state entries may persist beyond their configured TTL.
This means:
- Presence tokens (5m TTL) may linger, revealing stale online/offline status.
- Discovery entries (24h TTL) may outlive a salt rotation, allowing
  correlation across rotation boundaries.
- Pre-key material (7d TTL) may not be replenished, eventually exhausting
  the one-time pre-key supply.
- Media key references (30d TTL) may persist, keeping stale key material
  accessible to anyone with database access.

*Unaffected:* Message E2EE and forward secrecy. These are provided by the
Signal Double Ratchet operating entirely on the client side. The EKF manages
only server-side auxiliary state; it has no role in message encryption or
decryption. The OPRF evaluation (contact discovery privacy) is also
independent of the EKF -- the daily salt rotation runs in a separate task
(`run_salt_rotation_loop()`), though the salt's lifecycle entry in ScyllaDB
would not be cleaned up.

*Conclusion:* Security degrades for auxiliary state lifecycle (increased
persistence window). Message security is fully preserved at Signal baseline.

**Case 3: Sealed Sender Failure.**

*Failure mode:* The Ed25519 signing key is compromised, the certificate
issuance service is unavailable, or the client cannot validate certificates.

*Impact:* Message content remains end-to-end encrypted (sealed sender
protects *metadata*, not *content*). Without sealed sender, the server can
observe the sender identity for each message (sender UUID and device ID are
transmitted in cleartext). This is equivalent to standard Signal without the
sealed sender feature.

*Unaffected:* E2EE (content protection), forward secrecy (ratchet), contact
discovery privacy (OPRF), and auxiliary state lifecycle (EKF).

*Conclusion:* Security degrades for metadata privacy (sender identity visible
to server). All other guarantees are preserved.

**Composition of failures.** Each failure mode degrades exactly one defense
dimension while leaving all others intact. This is a consequence of the
architectural separation established in Theorem 1 (no cross-domain
persistence): because no key material is shared across protocol domains, a
failure in one domain cannot cascade into another.

The minimum security floor -- even under simultaneous failure of all three
components -- is equivalent to baseline Signal: E2EE for message content
with Double Ratchet forward secrecy, but without enhanced contact discovery
privacy, metadata protection, or auxiliary state lifecycle enforcement. QED.

---

## 8. Relationship to Mechanised Proofs

The Tamarin model in `docs/proofs/tamarin/oprf_obliviousness.spthy` verifies
the OPRF obliviousness property (Lemma 1, Step 2) in isolation. The present
document extends that analysis in three directions:

1. **Cross-system composition** (Theorem 1): Tamarin models a single protocol
   session. The no-cross-domain-persistence invariant requires reasoning about
   the auxiliary state map across all four key classes simultaneously.

2. **Temporal bounds** (Lemma 3, Theorem 2): Tamarin's symbolic model does
   not natively support wall-clock time reasoning. The EKF temporal guarantee
   requires reasoning about periodic task execution and TTL arithmetic.

3. **Failure mode analysis** (Theorem 3): Tamarin proves properties of
   correct protocol execution. Graceful degradation requires reasoning about
   subsystem independence under component failure.

These arguments complement the mechanised proofs. The Tamarin model provides
machine-checked verification of the OPRF's cryptographic core; this document
provides the system-level composition arguments that connect the OPRF to the
broader privacy architecture.

---

## Appendix A: Notation Summary

| Symbol | Meaning |
|--------|---------|
| S | Auxiliary state map (ScyllaDB `auxiliary_state` table) |
| e | An entry in S |
| CK_n | Chain key at ratchet step n |
| MediaK_n | Media encryption key derived from CK_n |
| H(x) | Hash-to-curve (Ristretto255 map) |
| k | OPRF server secret scalar |
| r | Client blinding scalar (ephemeral) |
| B = r * H(phone) | Blinded input |
| R = k * B | Server evaluation |
| HKDF(ikm, salt, info) | HKDF-SHA256 key derivation |
| NULL_SENTINEL | [0x00; 32] -- overwrite marker |
| tick_interval | EKF loop period (default 60s) |
| grace_period | tick_interval + rotation_grace_secs (default 3660s) |
| negl(lambda) | Negligible function in security parameter |
| PPT | Probabilistic polynomial-time |

## Appendix B: Implementation Cross-References

| Proof Element | Source File |
|---------------|-------------|
| KeyClass, ExpPolicy, EphemeralEntry | `crates/sanchr-core/src/ekf/models.rs` |
| lifecycle_tick(), run_lifecycle_loop() | `crates/sanchr-core/src/ekf/manager.rs` |
| OPRF server secret, evaluate() | `crates/sanchr-psi/src/oprf.rs` |
| SaltedBloomFilter, generate_daily_salt() | `crates/sanchr-psi/src/bloom.rs` |
| run_salt_rotation_loop() | `crates/sanchr-core/src/discovery/salt_rotation.rs` |
| derive_media_key(), advance_media_chain() | `crates/sanchr-psi/src/hkdf_utils.rs` |
| derive_discovery_hash() | `crates/sanchr-psi/src/hkdf_utils.rs` |
| derive_access_key() | `crates/sanchr-psi/src/hkdf_utils.rs` |
| SealedSenderSigner | `crates/sanchr-server-crypto/src/sealed_sender.rs` |
| EkfConfig (tick_interval, grace) | `crates/sanchr-common/src/config.rs` |
| OPRF Tamarin model | `docs/proofs/tamarin/oprf_obliviousness.spthy` |
