//! Integration tests for `#[derive(MaskDeserialize)]` (serde feature).
//!
//! Behavior-identity contract: a type deriving `MaskDeserialize` must
//! accept exactly the inputs the same shape deriving plain
//! `serde::Deserialize` accepts, produce equal values, and produce
//! byte-identical error messages — masking names changes the binary's
//! `.rodata`, never the deserialization behavior.
//!
//! Plain-derive twins live in `mod plain` under the SAME type idents,
//! so `expecting()` texts ("struct DeConfig") and error strings match
//! exactly and any divergence is the derive's fault, not the fixture's.

#![cfg(feature = "unstable-serde")]

mod common;

use litmask::MaskDeserialize;

#[derive(MaskDeserialize, Debug, PartialEq)]
struct DeConfig {
    license_server_url: String,
    activation_count: u32,
}

#[derive(MaskDeserialize, Debug, PartialEq)]
struct DeOptional {
    relay_endpoint: String,
    retry_budget: Option<u32>,
}

mod plain {
    #[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq)]
    pub struct DeConfig {
        pub license_server_url: String,
        pub activation_count: u32,
    }

    #[derive(serde::Deserialize, Debug, PartialEq)]
    pub struct DeOptional {
        pub relay_endpoint: String,
        pub retry_budget: Option<u32>,
    }
}

#[test]
fn mask_deserialize_json_matches_plain_derive() {
    common::init_once();
    let input = r#"{"license_server_url":"https://license.example.com","activation_count":7}"#;
    let masked: DeConfig = serde_json::from_str(input).expect("masked deserialization failed");
    let plain: plain::DeConfig = serde_json::from_str(input).expect("plain deserialization failed");
    assert_eq!(masked.license_server_url, plain.license_server_url);
    assert_eq!(masked.activation_count, plain.activation_count);
}

/// serde_json deserializes a struct from a JSON array via `visit_seq`
/// — same entry point non-self-describing formats use.
#[test]
fn mask_deserialize_json_array_form_matches_plain_derive() {
    common::init_once();
    let input = r#"["https://license.example.com",7]"#;
    let masked: DeConfig = serde_json::from_str(input).expect("masked deserialization failed");
    assert_eq!(masked.license_server_url, "https://license.example.com");
    assert_eq!(masked.activation_count, 7);
}

/// Non-self-describing formats deserialize structs positionally —
/// byte-level round-trip through postcard proves the `visit_seq`
/// path preserves field declaration order.
#[test]
fn mask_deserialize_postcard_round_trip() {
    common::init_once();
    let plain = plain::DeConfig {
        license_server_url: "https://license.example.com".to_string(),
        activation_count: 7,
    };
    let bytes = postcard::to_stdvec(&plain).expect("plain serialization failed");
    let masked: DeConfig = postcard::from_bytes(&bytes).expect("masked deserialization failed");
    assert_eq!(masked.license_server_url, plain.license_server_url);
    assert_eq!(masked.activation_count, plain.activation_count);
}

/// Default serde behavior: unknown fields are skipped, not errors.
#[test]
fn mask_deserialize_ignores_unknown_fields_like_plain_derive() {
    common::init_once();
    let input = r#"{"license_server_url":"u","unknown_extra":[1,2],"activation_count":1}"#;
    let masked: DeConfig = serde_json::from_str(input).expect("masked deserialization failed");
    let plain: plain::DeConfig = serde_json::from_str(input).expect("plain deserialization failed");
    assert_eq!(masked.activation_count, plain.activation_count);
}

#[test]
fn mask_deserialize_missing_field_error_matches_plain_derive() {
    common::init_once();
    let input = r#"{"activation_count":1}"#;
    let masked_err = serde_json::from_str::<DeConfig>(input)
        .expect_err("masked deserialization must fail")
        .to_string();
    let plain_err = serde_json::from_str::<plain::DeConfig>(input)
        .expect_err("plain deserialization must fail")
        .to_string();
    assert_eq!(masked_err, plain_err);
    assert!(
        masked_err.contains("missing field `license_server_url`"),
        "unexpected error text: {masked_err}"
    );
}

#[test]
fn mask_deserialize_duplicate_field_error_matches_plain_derive() {
    common::init_once();
    let input = r#"{"license_server_url":"a","license_server_url":"b","activation_count":1}"#;
    let masked_err = serde_json::from_str::<DeConfig>(input)
        .expect_err("masked deserialization must fail")
        .to_string();
    let plain_err = serde_json::from_str::<plain::DeConfig>(input)
        .expect_err("plain deserialization must fail")
        .to_string();
    assert_eq!(masked_err, plain_err);
    assert!(
        masked_err.contains("duplicate field `license_server_url`"),
        "unexpected error text: {masked_err}"
    );
}

/// `expecting()` parity: a too-short seq reports `invalid length N,
/// expected struct DeConfig with 2 elements` — the masked derive must
/// reproduce the type name in the message at runtime.
#[test]
fn mask_deserialize_invalid_length_error_matches_plain_derive() {
    common::init_once();
    let input = r#"["https://license.example.com"]"#;
    let masked_err = serde_json::from_str::<DeConfig>(input)
        .expect_err("masked deserialization must fail")
        .to_string();
    let plain_err = serde_json::from_str::<plain::DeConfig>(input)
        .expect_err("plain deserialization must fail")
        .to_string();
    assert_eq!(masked_err, plain_err);
    assert!(
        masked_err.contains("struct DeConfig with 2 elements"),
        "unexpected error text: {masked_err}"
    );
}

/// Wrong-shape input exercises the visitor's `expecting()` text
/// ("struct DeConfig"), which the masked derive renders at runtime.
#[test]
fn mask_deserialize_wrong_type_error_matches_plain_derive() {
    common::init_once();
    let input = "3";
    let masked_err = serde_json::from_str::<DeConfig>(input)
        .expect_err("masked deserialization must fail")
        .to_string();
    let plain_err = serde_json::from_str::<plain::DeConfig>(input)
        .expect_err("plain deserialization must fail")
        .to_string();
    assert_eq!(masked_err, plain_err);
    assert!(
        masked_err.contains("expected struct DeConfig"),
        "unexpected error text: {masked_err}"
    );
}

/// Plain-derive parity: a missing `Option<T>` field deserializes as
/// `None`, not a `missing field` error.
#[test]
fn mask_deserialize_missing_option_field_is_none() {
    common::init_once();
    let input = r#"{"relay_endpoint":"wss://relay.example"}"#;
    let masked: DeOptional = serde_json::from_str(input).expect("masked deserialization failed");
    let plain: plain::DeOptional =
        serde_json::from_str(input).expect("plain deserialization failed");
    assert_eq!(masked.retry_budget, None);
    assert_eq!(plain.retry_budget, None);
}

#[derive(MaskDeserialize, Debug, PartialEq)]
struct DeUnitBeacon;

#[derive(MaskDeserialize, Debug, PartialEq)]
struct DeToken(String);

#[derive(MaskDeserialize, Debug, PartialEq)]
struct DeBeaconPair(String, u32);

#[derive(MaskDeserialize, Debug, PartialEq)]
struct DeEmptyTuple();

mod plain_shapes {
    #[derive(serde::Deserialize, Debug, PartialEq)]
    pub struct DeUnitBeacon;

    #[derive(serde::Deserialize, Debug, PartialEq)]
    pub struct DeToken(pub String);

    #[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq)]
    pub struct DeBeaconPair(pub String, pub u32);

    #[derive(serde::Deserialize, Debug, PartialEq)]
    pub struct DeEmptyTuple();
}

#[test]
fn mask_deserialize_unit_struct_matches_plain_derive() {
    common::init_once();
    let masked: DeUnitBeacon = serde_json::from_str("null").expect("masked failed");
    assert_eq!(masked, DeUnitBeacon);
    let masked_err = serde_json::from_str::<DeUnitBeacon>("3")
        .expect_err("masked must fail")
        .to_string();
    let plain_err = serde_json::from_str::<plain_shapes::DeUnitBeacon>("3")
        .expect_err("plain must fail")
        .to_string();
    assert_eq!(masked_err, plain_err);
    assert!(
        masked_err.contains("expected unit struct DeUnitBeacon"),
        "unexpected error text: {masked_err}"
    );
}

#[test]
fn mask_deserialize_newtype_struct_matches_plain_derive() {
    common::init_once();
    let masked: DeToken = serde_json::from_str(r#""opaque-handle""#).expect("masked failed");
    assert_eq!(masked, DeToken("opaque-handle".to_string()));
    // serde_json's `deserialize_newtype_struct` delegates straight to
    // the inner type, so the error text comes from `String`'s visitor
    // ("expected a string") for plain and masked alike — parity is the
    // assertion, not any particular wording.
    let masked_err = serde_json::from_str::<DeToken>("{}")
        .expect_err("masked must fail")
        .to_string();
    let plain_err = serde_json::from_str::<plain_shapes::DeToken>("{}")
        .expect_err("plain must fail")
        .to_string();
    assert_eq!(masked_err, plain_err);
}

#[test]
fn mask_deserialize_tuple_struct_matches_plain_derive() {
    common::init_once();
    let masked: DeBeaconPair = serde_json::from_str(r#"["relay-7",31]"#).expect("masked failed");
    assert_eq!(masked, DeBeaconPair("relay-7".to_string(), 31));
}

#[test]
fn mask_deserialize_tuple_struct_postcard_round_trip() {
    common::init_once();
    let bytes = postcard::to_stdvec(&plain_shapes::DeBeaconPair("relay-7".to_string(), 31))
        .expect("plain serialization failed");
    let masked: DeBeaconPair = postcard::from_bytes(&bytes).expect("masked failed");
    assert_eq!(masked, DeBeaconPair("relay-7".to_string(), 31));
}

#[test]
fn mask_deserialize_tuple_struct_invalid_length_error_matches_plain_derive() {
    common::init_once();
    let input = r#"["relay-7"]"#;
    let masked_err = serde_json::from_str::<DeBeaconPair>(input)
        .expect_err("masked must fail")
        .to_string();
    let plain_err = serde_json::from_str::<plain_shapes::DeBeaconPair>(input)
        .expect_err("plain must fail")
        .to_string();
    assert_eq!(masked_err, plain_err);
    assert!(
        masked_err.contains("tuple struct DeBeaconPair with 2 elements"),
        "unexpected error text: {masked_err}"
    );
}

#[test]
fn mask_deserialize_empty_tuple_struct_matches_plain_derive() {
    common::init_once();
    let masked: DeEmptyTuple = serde_json::from_str("[]").expect("masked failed");
    assert_eq!(masked, DeEmptyTuple());
    let plain: plain_shapes::DeEmptyTuple = serde_json::from_str("[]").expect("plain failed");
    assert_eq!(plain, plain_shapes::DeEmptyTuple());
}

#[test]
fn mask_deserialize_repeat_calls_are_stable() {
    common::init_once();
    let input = r#"{"license_server_url":"u","activation_count":1}"#;
    // Second call exercises the cached-name path (OnceLock hit).
    let first: DeConfig = serde_json::from_str(input).expect("first deserialization failed");
    let second: DeConfig = serde_json::from_str(input).expect("second deserialization failed");
    assert_eq!(first, second);
}
