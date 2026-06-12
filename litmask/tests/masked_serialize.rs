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

#[derive(MaskedSerialize)]
struct MaskedEnvelope<T> {
    sequence_marker_zzyzx: u64,
    payload: T,
}

#[derive(serde::Serialize)]
struct PlainEnvelope<T> {
    sequence_marker_zzyzx: u64,
    payload: T,
}

#[test]
fn masked_serialize_generic_struct_matches_plain_derive() {
    common::init_once();
    let masked = MaskedEnvelope {
        sequence_marker_zzyzx: 42,
        payload: vec!["a".to_string(), "b".to_string()],
    };
    let plain = PlainEnvelope {
        sequence_marker_zzyzx: 42,
        payload: vec!["a".to_string(), "b".to_string()],
    };
    assert_eq!(
        serde_json::to_string(&masked).expect("masked serialization failed"),
        serde_json::to_string(&plain).expect("plain serialization failed"),
    );
}

#[derive(MaskedSerialize)]
struct MaskedBorrowed<'a, T> {
    borrowed_label_qwxz: &'a str,
    payload: T,
}

#[test]
fn masked_serialize_lifetime_and_type_params() {
    common::init_once();
    let masked = MaskedBorrowed {
        borrowed_label_qwxz: "tag",
        payload: 9u8,
    };
    assert_eq!(
        serde_json::to_string(&masked).expect("masked serialization failed"),
        r#"{"borrowed_label_qwxz":"tag","payload":9}"#
    );
}

#[derive(MaskedSerialize)]
struct MaskedRawIdent {
    r#type: String,
}

#[derive(serde::Serialize)]
struct PlainRawIdent {
    r#type: String,
}

#[test]
fn masked_serialize_raw_ident_field_unraws_like_plain_derive() {
    common::init_once();
    let masked = MaskedRawIdent {
        r#type: "beacon".to_string(),
    };
    let plain = PlainRawIdent {
        r#type: "beacon".to_string(),
    };
    let masked_json = serde_json::to_string(&masked).expect("masked serialization failed");
    assert_eq!(
        masked_json,
        serde_json::to_string(&plain).expect("plain serialization failed"),
    );
    assert_eq!(masked_json, r#"{"type":"beacon"}"#);
}

#[derive(MaskedSerialize)]
struct MaskedEmpty {}

#[test]
fn masked_serialize_empty_struct_serializes_as_empty_object() {
    common::init_once();
    assert_eq!(
        serde_json::to_string(&MaskedEmpty {}).expect("masked serialization failed"),
        "{}"
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
