# Sanchr Protocol Formal Verification (Tamarin Prover)

Three standalone Tamarin models that mechanically verify core privacy
and security properties of the Sanchr protocol suite.

## Models

### 1. oprf_obliviousness.spthy -- OPRF Contact Discovery

Verifies server obliviousness in the OPRF-PSI private contact discovery
protocol.  The client blinds H(phone) with a random scalar before
sending it to the server; the server evaluates the PRF on the blinded
point and returns the result.  The client unblinds to obtain the
deterministic output.

**Key lemma:** `server_obliviousness` -- the server cannot determine
which phone number produced a given blinded point.

**Attack baseline:** A naive (unblinded) variant is included.  The lemma
`naive_server_learns_phone` is expected to be falsified, demonstrating
that without blinding the server trivially recovers phone numbers via
dictionary attack.

### 2. ekf_temporal_bounding.spthy -- EKF Lifecycle Tick

Verifies temporal bounding of ephemeral key fabric entries.  Entries are
created with a TTL and an expiry policy (Delete, Overwrite, Rotate).  A
periodic tick enforces expiry.

**Key lemma:** `no_entry_survives_beyond_bound` -- once a tick fires
after created_at + ttl + grace, the entry has been removed.

**Additional lemmas:** policy-specific termination, zero-fill-before-
removal for Overwrite, publish-before-removal for Rotate.

### 3. mediak_ratchet_binding.spthy -- Media Key Forward Secrecy

Verifies forward secrecy of the parallel HKDF media key chain.  Chain
keys advance via a one-way KDF; media keys are derived from each chain
key and a file hash.

**Key lemma:** `media_key_forward_secrecy` -- compromise of CK_{n+1}
does not reveal MediaK_n (or any earlier media key).

**Sanity check:** `compromise_reveals_current_media_key` is expected to
be falsified, confirming that compromise of CK_n does reveal MediaK_n
(the model is not vacuously secure).

## Running the proofs

Install the Tamarin prover (https://tamarin-prover.com/) and run:

```bash
# Verify all lemmas in a single model
tamarin-prover --prove oprf_obliviousness.spthy

# Verify a specific lemma
tamarin-prover --prove=server_obliviousness oprf_obliviousness.spthy

# Launch the interactive GUI (useful for inspecting attack traces)
tamarin-prover interactive oprf_obliviousness.spthy
```

Repeat for each `.spthy` file.  Expected results:

| Lemma | Expected |
|---|---|
| `server_obliviousness` | verified |
| `naive_server_learns_phone` | **falsified** (attack found) |
| `no_entry_survives_beyond_bound` | verified |
| `delete/overwrite/rotate_policy_terminates` | verified (exists-trace) |
| `media_key_forward_secrecy` | verified |
| `chain_key_secrecy_before_compromise` | verified |
| `compromise_reveals_current_media_key` | **falsified** (expected) |
| `chain_functional_correctness` | verified (exists-trace) |

## Assumptions

1. **DDH on Ristretto255.**  Tamarin's symbolic Diffie-Hellman model
   captures the DDH assumption: given (G, G^a, G^b), the adversary
   cannot compute G^(ab) without knowing a or b.  This underpins the
   OPRF obliviousness proof.

2. **HKDF as random oracle.**  The `advance()` and `derive_media()`
   functions are modeled as uninterpreted (no inverse, no algebraic
   relations).  This is the standard random-oracle treatment of HKDF
   in symbolic analysis.

3. **Symbolic model limitations.**  These proofs reason about protocol
   logic, not implementation.  Side channels, timing leaks, and
   computational hardness reductions are out of scope.  The symbolic
   model is sound but not complete -- a verified lemma means no
   logical attack exists, but does not rule out computational attacks
   beyond the assumed hardness.

## Interpretation of results

- **Verified** means Tamarin exhaustively explored all possible
  protocol traces and found no execution that violates the lemma.

- **Falsified** means Tamarin found a concrete attack trace.  For
  lemmas marked "expected attack" this confirms the model is not
  vacuous and that the defended protocol is strictly stronger than
  the baseline.

- If a lemma neither verifies nor falsifies within a reasonable time
  bound, try `--heuristic=O` or add source lemmas to guide the
  prover.  The models are designed to terminate in under 60 seconds
  on a modern machine.
