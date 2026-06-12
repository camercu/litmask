//! Integration tests for `#[derive(MaskedSerialize)]` (serde feature).
//!
//! Output-identity contract: a struct deriving `MaskedSerialize` must
//! produce byte-identical `serde_json` output to the same struct shape
//! deriving plain `serde::Serialize` — masking field names changes the
//! binary's `.rodata`, never the serialized wire format.

#![cfg(feature = "unstable-serde")]

mod common;

use litmask::MaskedSerialize;

#[derive(MaskedSerialize)]
struct MaskedConfig {
    license_server_url: String,
    activation_count: u32,
}

#[derive(serde::Serialize)]
struct PlainConfig {
    license_server_url: String,
    activation_count: u32,
}

#[test]
fn masked_serialize_json_matches_plain_derive() {
    common::init_once();
    let masked = MaskedConfig {
        license_server_url: "https://license.example.com".to_string(),
        activation_count: 7,
    };
    let plain = PlainConfig {
        license_server_url: "https://license.example.com".to_string(),
        activation_count: 7,
    };
    let masked_json = serde_json::to_string(&masked).expect("masked serialization failed");
    let plain_json = serde_json::to_string(&plain).expect("plain serialization failed");
    assert_eq!(masked_json, plain_json);
    assert_eq!(
        masked_json,
        r#"{"license_server_url":"https://license.example.com","activation_count":7}"#
    );
}

#[test]
fn masked_serialize_repeat_calls_are_stable() {
    common::init_once();
    let masked = MaskedConfig {
        license_server_url: "u".to_string(),
        activation_count: 1,
    };
    // Second call exercises the cached-name path (OnceLock hit).
    let first = serde_json::to_string(&masked).expect("first serialization failed");
    let second = serde_json::to_string(&masked).expect("second serialization failed");
    assert_eq!(first, second);
}
