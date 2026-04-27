//! Derives the sealed-sender trust-root pubkey from a 32-byte seed and prints
//! it base64-encoded. Used by the ops/release pipeline to bake the value into
//! the Android `BuildConfig.SEALED_SENDER_TRUST_ROOT` (and the iOS equivalent)
//! before shipping a client release that talks to a backend running the
//! corresponding `auth.sealed_sender_key`.
//!
//! Reads the seed (base64-encoded, 32 bytes after decoding) from stdin so the
//! secret never reaches the process argv (which is world-readable on most
//! systems).
//!
//! Example:
//!     echo -n "$SANCHR_SEALED_SENDER_KEY_B64" | \
//!       cargo run -p sanchr-server-crypto --bin print-trust-root
//!
//! Or against the running k8s secret:
//!     kubectl get secret -n default sanchr -o jsonpath='{.data.SANCHR_AUTH__SEALED_SENDER_KEY}' \
//!       | base64 -d \
//!       | cargo run -p sanchr-server-crypto --bin print-trust-root

use base64::{engine::general_purpose::STANDARD, Engine};
use sanchr_server_crypto::sealed_sender::SealedSenderSigner;
use std::io::{self, Read};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut buf = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut buf) {
        eprintln!("failed to read seed from stdin: {e}");
        return ExitCode::from(2);
    }
    let trimmed = buf.trim();
    let seed_bytes = match STANDARD.decode(trimmed) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "stdin must be base64-encoded 32-byte seed (got {} chars): {e}",
                trimmed.len()
            );
            return ExitCode::from(2);
        }
    };
    let seed: [u8; 32] = match seed_bytes.try_into() {
        Ok(s) => s,
        Err(v) => {
            eprintln!(
                "decoded seed must be exactly 32 bytes; got {} bytes",
                v.len()
            );
            return ExitCode::from(2);
        }
    };

    // key_id is irrelevant for the pubkey derivation — pubkey is a function of
    // the private key alone. Use 1 to match the production `build_sealed_sender_signer`.
    let signer = SealedSenderSigner::from_seed(&seed, 1);
    let pubkey_b64 = STANDARD.encode(signer.trust_root_public_key_bytes());
    println!("{pubkey_b64}");
    ExitCode::SUCCESS
}
