//! Mask `Debug` type, field, and variant names at compile time,
//! decrypt during formatting.
//!
//! Plain `#[derive(Debug)]` embeds the type name, every field name,
//! and every enum variant name as cleartext `&'static str` in the
//! compiled binary's `.rodata` — `strings(1)` reveals the full type
//! vocabulary even when every field *value* is masked.
//! `#[derive(MaskDebug)]` routes the names through the same AEAD
//! pipeline as `mask!`, while `{:?}` / `{:#?}` output stays
//! byte-identical to the plain derive. Prove it to yourself:
//!
//! ```sh
//! cargo build --release --example mask_debug_demo
//! strings target/release/examples/mask_debug_demo | grep activation_token
//! # (no output — the field names are absent from the binary)
//!
//! ./target/release/examples/mask_debug_demo
//! # prints the full Debug output, names decrypted at runtime
//! ```
//!
//! No explicit `init!` is needed here: the default Embedded seal tier
//! lazily initializes on the first decrypt, exactly as with `mask!`.
//! Higher seal tiers must run `init!` before the first formatting.
//!
//! CAUTION: adding a plain `#[derive(Debug)]` (or `serde::Serialize`
//! / `Deserialize`) to the same type re-embeds every name in the
//! binary and defeats the masking.

use litmask::{MaskDebug, mask};

#[derive(MaskDebug)]
struct CovertBeaconManifest {
    rendezvous_url_quux: String,
    activation_token_xyzzy: String,
    phase: BeaconPhase,
}

#[derive(MaskDebug)]
enum BeaconPhase {
    DormantUntilDawn,
    ExfilWindowOpen { jitter_millis_zzyzx: u32 },
}

fn main() {
    let manifest = CovertBeaconManifest {
        rendezvous_url_quux: mask!("https://beacon.fabrikam-exfil.example/v1"),
        activation_token_xyzzy: mask!("correct-horse-battery-staple"),
        phase: BeaconPhase::ExfilWindowOpen {
            jitter_millis_zzyzx: 250,
        },
    };
    println!("{manifest:?}");
    println!("{manifest:#?}");
    println!("{:?}", BeaconPhase::DormantUntilDawn);
}
