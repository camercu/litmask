//! Integration tests for `#[derive(MaskSerialize)]` (serde feature).
//!
//! Output-identity contract: a struct deriving `MaskSerialize` must
//! produce byte-identical `serde_json` output to the same struct shape
//! deriving plain `serde::Serialize` — masking field names changes the
//! binary's `.rodata`, never the serialized wire format.

#![cfg(feature = "unstable-serde")]

mod common;

use litmask::MaskSerialize;

#[derive(MaskSerialize)]
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
fn mask_serialize_json_matches_plain_derive() {
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

#[derive(MaskSerialize)]
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
fn mask_serialize_generic_struct_matches_plain_derive() {
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

#[derive(MaskSerialize)]
struct MaskedBorrowed<'a, T> {
    borrowed_label_qwxz: &'a str,
    payload: T,
}

#[test]
fn mask_serialize_lifetime_and_type_params() {
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

#[derive(MaskSerialize)]
struct MaskedRawIdent {
    r#type: String,
}

#[derive(serde::Serialize)]
struct PlainRawIdent {
    r#type: String,
}

#[test]
fn mask_serialize_raw_ident_field_unraws_like_plain_derive() {
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

#[derive(MaskSerialize)]
struct MaskedUnitBeacon;

#[derive(serde::Serialize)]
struct PlainUnitBeacon;

#[test]
fn mask_serialize_unit_struct_matches_plain_derive() {
    common::init_once();
    let masked_json =
        serde_json::to_string(&MaskedUnitBeacon).expect("masked serialization failed");
    assert_eq!(
        masked_json,
        serde_json::to_string(&PlainUnitBeacon).expect("plain serialization failed"),
    );
    assert_eq!(masked_json, "null");
}

#[derive(MaskSerialize)]
struct MaskedToken(String);

#[derive(serde::Serialize)]
struct PlainToken(String);

#[test]
fn mask_serialize_newtype_struct_matches_plain_derive() {
    common::init_once();
    let masked_json = serde_json::to_string(&MaskedToken("opaque-handle".to_string()))
        .expect("masked serialization failed");
    assert_eq!(
        masked_json,
        serde_json::to_string(&PlainToken("opaque-handle".to_string()))
            .expect("plain serialization failed"),
    );
    assert_eq!(masked_json, r#""opaque-handle""#);
}

#[derive(MaskSerialize)]
struct MaskedBeaconPair(String, u32);

#[derive(serde::Serialize)]
struct PlainBeaconPair(String, u32);

#[test]
fn mask_serialize_tuple_struct_matches_plain_derive() {
    common::init_once();
    let masked_json = serde_json::to_string(&MaskedBeaconPair("relay-7".to_string(), 31))
        .expect("masked serialization failed");
    assert_eq!(
        masked_json,
        serde_json::to_string(&PlainBeaconPair("relay-7".to_string(), 31))
            .expect("plain serialization failed"),
    );
    assert_eq!(masked_json, r#"["relay-7",31]"#);
}

#[derive(MaskSerialize)]
struct MaskedEmptyTuple();

#[derive(serde::Serialize)]
struct PlainEmptyTuple();

#[test]
fn mask_serialize_empty_tuple_struct_matches_plain_derive() {
    common::init_once();
    assert_eq!(
        serde_json::to_string(&MaskedEmptyTuple()).expect("masked serialization failed"),
        serde_json::to_string(&PlainEmptyTuple()).expect("plain serialization failed"),
    );
}

#[derive(MaskSerialize)]
struct MaskedGenericWrapper<T>(T);

#[test]
fn mask_serialize_generic_newtype_struct() {
    common::init_once();
    assert_eq!(
        serde_json::to_string(&MaskedGenericWrapper(vec![1u8, 2]))
            .expect("masked serialization failed"),
        "[1,2]"
    );
}

#[derive(MaskSerialize)]
struct MaskedEmpty {}

#[test]
fn mask_serialize_empty_struct_serializes_as_empty_object() {
    common::init_once();
    assert_eq!(
        serde_json::to_string(&MaskedEmpty {}).expect("masked serialization failed"),
        "{}"
    );
}

#[test]
fn mask_serialize_repeat_calls_are_stable() {
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

/// The docs recommend pairing `MaskDebug` with `MaskSerialize` (a
/// plain `Debug` derive would re-embed the names); the pair must
/// expand cleanly on one type and preserve both output contracts.
#[derive(MaskSerialize, litmask::MaskDebug)]
struct MaskedCombined {
    relay_endpoint_qwxz: String,
    retry_budget: u32,
}

mod plain {
    #[derive(serde::Serialize, Debug)]
    pub struct MaskedCombined {
        pub relay_endpoint_qwxz: String,
        pub retry_budget: u32,
    }
}

#[test]
fn mask_serialize_combines_with_mask_debug_on_one_type() {
    common::init_once();
    let masked = MaskedCombined {
        relay_endpoint_qwxz: "wss://relay.example".to_string(),
        retry_budget: 3,
    };
    let plain = plain::MaskedCombined {
        relay_endpoint_qwxz: "wss://relay.example".to_string(),
        retry_budget: 3,
    };
    assert_eq!(
        serde_json::to_string(&masked).expect("masked serialization failed"),
        serde_json::to_string(&plain).expect("plain serialization failed"),
    );
    assert_eq!(format!("{masked:?}"), format!("{plain:?}"));
    assert_eq!(format!("{masked:#?}"), format!("{plain:#?}"));
}
