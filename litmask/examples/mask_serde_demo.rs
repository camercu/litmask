//! EXPERIMENTAL (`unstable-serde`): mask serde field and struct names
//! at compile time, decrypt on first serialization.
//!
//! Plain `#[derive(serde::Serialize)]` embeds every field name and the
//! struct name as cleartext `&'static str` in the compiled binary's
//! `.rodata` — `strings(1)` reveals the full schema vocabulary even
//! when every field *value* is masked. `#[derive(MaskSerialize)]`
//! routes the names through the same AEAD pipeline as `mask!`, while
//! the serialized output stays byte-identical to the plain derive.
//! Prove it to yourself:
//!
//! ```sh
//! cargo build --release --features unstable-serde --example mask_serde_demo
//! strings target/release/examples/mask_serde_demo | grep activation_token
//! # (no output — the field names are absent from the binary)
//!
//! ./target/release/examples/mask_serde_demo
//! # prints the full JSON, field names decrypted at runtime
//! ```
//!
//! No explicit `init!` is needed here: the default Embedded seal tier
//! lazily initializes on the first decrypt, exactly as with `mask!`.
//! Higher seal tiers must run `init!` before the first serialization.
//!
//! CAUTION: adding a plain `#[derive(serde::Deserialize)]` (or plain
//! `Debug` — use `#[derive(MaskDebug)]` instead) to the same struct
//! re-embeds every name in the binary and defeats the masking.

use litmask::{MaskDebug, MaskSerialize, mask};

// `MaskDebug` paired with `MaskSerialize`, as the docs recommend —
// this binary is scrub-tested, so the pairing is proven to keep every
// name out of `.rodata`.
#[derive(MaskSerialize, MaskDebug)]
struct ClandestineTelemetryManifest {
    covert_endpoint_quux: String,
    activation_token_xyzzy: String,
    heartbeat_jitter_millis: u32,
}

fn main() {
    let manifest = ClandestineTelemetryManifest {
        covert_endpoint_quux: mask!("https://beacon.fabrikam-exfil.example/v1"),
        activation_token_xyzzy: mask!("correct-horse-battery-staple"),
        heartbeat_jitter_millis: 250,
    };
    println!("{}", serde_json::to_string(&manifest).unwrap());
    println!("{manifest:?}");
}
