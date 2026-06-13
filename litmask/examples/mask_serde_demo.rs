//! EXPERIMENTAL (`unstable-serde`): mask serde field and struct names
//! at compile time, decrypt on first use.
//!
//! Plain `#[derive(serde::Serialize)]` embeds every field name and the
//! struct name as cleartext `&'static str` in the compiled binary's
//! `.rodata` — `strings(1)` reveals the full schema vocabulary even
//! when every field *value* is masked. Plain
//! `#[derive(serde::Deserialize)]` is a larger leak: `FIELDS` arrays,
//! field-matching arms, and `missing field` diagnostics all carry the
//! names. `#[derive(MaskSerialize, MaskDeserialize)]` routes the names
//! through the same AEAD pipeline as `mask!`, while wire format and
//! error messages stay identical to the plain derives. Prove it to
//! yourself:
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
//! Higher seal tiers must run `init!` before the first
//! (de)serialization.
//!
//! CAUTION: adding a plain serde derive (or plain `Debug` — use
//! `#[derive(MaskDebug)]` instead) to the same struct re-embeds every
//! name in the binary and defeats the masking.

use litmask::{MaskDebug, MaskDeserialize, MaskSerialize, mask};

// All three masking derives paired, as the docs recommend — this
// binary is scrub-tested, so the combination is proven to keep every
// name out of `.rodata`.
#[derive(MaskSerialize, MaskDeserialize, MaskDebug)]
struct ClandestineTelemetryManifest {
    // `#[serde(rename)]` / `#[serde(alias)]` values are masked too: the
    // wire name (`renamed_marker_qwxz`) and accepted alias
    // (`alt_endpoint_zzyx`) go through the same AEAD pipeline as the
    // ident-derived names, so neither lands in `.rodata`.
    #[serde(alias = "alt_endpoint_zzyx")]
    covert_endpoint_quux: String,
    activation_token_xyzzy: String,
    heartbeat_jitter_millis: u32,
    #[serde(rename = "renamed_marker_qwxz")]
    schema_marker: u8,
    uplink_channel_state: UplinkChannelState,
}

// Enum variant names are masked too — self-describing formats print
// and match them as the externally-tagged key, so the plain derives
// would embed each as cleartext.
#[derive(MaskSerialize, MaskDeserialize, MaskDebug)]
enum UplinkChannelState {
    DormantUntilDawnZzyzx,
    ActiveRelayWindow { relay_handle_quux: String },
}

fn main() {
    let manifest = ClandestineTelemetryManifest {
        covert_endpoint_quux: mask!("https://beacon.fabrikam-exfil.example/v1"),
        activation_token_xyzzy: mask!("correct-horse-battery-staple"),
        heartbeat_jitter_millis: 250,
        schema_marker: 1,
        uplink_channel_state: UplinkChannelState::ActiveRelayWindow {
            relay_handle_quux: mask!("relay-handle-7-zzyzx"),
        },
    };
    let json = serde_json::to_string(&manifest).unwrap();
    println!("{json}");
    println!("{manifest:?}");
    println!(
        "{}",
        serde_json::to_string(&UplinkChannelState::DormantUntilDawnZzyzx).unwrap()
    );

    // Round-trip through MaskDeserialize: field and variant names are
    // matched against runtime-decrypted names, never cleartext arms.
    let restored: ClandestineTelemetryManifest = serde_json::from_str(&json).unwrap();
    println!("restored: {restored:?}");
}
