//! Integration tests for `#[derive(MaskDeserialize)]` (serde feature).
//!
//! Behavior-identity contract: a type deriving `MaskDeserialize` must
//! accept exactly the inputs the same shape deriving plain
//! `serde::Deserialize` accepts, produce equal values, and produce
//! byte-identical error messages — masking names changes the binary's
//! `.rodata`, never the deserialization behavior.
//!
//! Plain-derive twins live in `mod plain` under the SAME type idents,
//! so `expecting()` texts ("struct `DeConfig`") and error strings match
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
    let input = r#"{"license_server_url":"https://license.example.com","activation_count":7}"#;
    let masked: DeConfig = serde_json::from_str(input).expect("masked deserialization failed");
    let plain: plain::DeConfig = serde_json::from_str(input).expect("plain deserialization failed");
    assert_eq!(masked.license_server_url, plain.license_server_url);
    assert_eq!(masked.activation_count, plain.activation_count);
}

/// `serde_json` deserializes a struct from a JSON array via `visit_seq`
/// — same entry point non-self-describing formats use.
#[test]
fn mask_deserialize_json_array_form_matches_plain_derive() {
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
    let input = r#"{"license_server_url":"u","unknown_extra":[1,2],"activation_count":1}"#;
    let masked: DeConfig = serde_json::from_str(input).expect("masked deserialization failed");
    let plain: plain::DeConfig = serde_json::from_str(input).expect("plain deserialization failed");
    assert_eq!(masked.activation_count, plain.activation_count);
}

#[test]
fn mask_deserialize_missing_field_error_matches_plain_derive() {
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
/// ("struct `DeConfig`"), which the masked derive renders at runtime.
#[test]
fn mask_deserialize_wrong_type_error_matches_plain_derive() {
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
    let masked: DeBeaconPair = serde_json::from_str(r#"["relay-7",31]"#).expect("masked failed");
    assert_eq!(masked, DeBeaconPair("relay-7".to_string(), 31));
}

#[test]
fn mask_deserialize_tuple_struct_postcard_round_trip() {
    let bytes = postcard::to_stdvec(&plain_shapes::DeBeaconPair("relay-7".to_string(), 31))
        .expect("plain serialization failed");
    let masked: DeBeaconPair = postcard::from_bytes(&bytes).expect("masked failed");
    assert_eq!(masked, DeBeaconPair("relay-7".to_string(), 31));
}

#[test]
fn mask_deserialize_tuple_struct_invalid_length_error_matches_plain_derive() {
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
    let masked: DeEmptyTuple = serde_json::from_str("[]").expect("masked failed");
    assert_eq!(masked, DeEmptyTuple());
    let plain: plain_shapes::DeEmptyTuple = serde_json::from_str("[]").expect("plain failed");
    assert_eq!(plain, plain_shapes::DeEmptyTuple());
}

#[derive(MaskDeserialize, Debug, PartialEq)]
enum DeChannelState {
    DormantUntilDusk,
    RelayHandle(String),
    JitterWindow(u32, u32),
    ActiveBeacon { uplink_url: String, burst_quota: u8 },
}

/// Empty bracketed variants are NOT unit variants to serde: `V()` is
/// a zero-arity tuple variant, `V {}` a zero-field struct variant.
#[derive(MaskDeserialize, Debug, PartialEq)]
enum DeEmptyVariants {
    BareDrop,
    HollowTuple(),
    HollowStruct {},
}

/// Uninhabited enums must still derive — the plain serde derive
/// generates an impl whose `visit_enum` proves unreachability.
#[derive(MaskDeserialize)]
enum DeNever {}

mod plain_enums {
    #[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq)]
    pub enum DeChannelState {
        DormantUntilDusk,
        RelayHandle(String),
        JitterWindow(u32, u32),
        ActiveBeacon { uplink_url: String, burst_quota: u8 },
    }

    #[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq)]
    pub enum DeEmptyVariants {
        BareDrop,
        HollowTuple(),
        HollowStruct {},
    }
}

fn channel_state_json_fixtures() -> Vec<(&'static str, DeChannelState)> {
    vec![
        (r#""DormantUntilDusk""#, DeChannelState::DormantUntilDusk),
        (
            r#"{"RelayHandle":"relay-9"}"#,
            DeChannelState::RelayHandle("relay-9".to_string()),
        ),
        (
            r#"{"JitterWindow":[50,250]}"#,
            DeChannelState::JitterWindow(50, 250),
        ),
        (
            r#"{"ActiveBeacon":{"uplink_url":"wss://uplink.example","burst_quota":4}}"#,
            DeChannelState::ActiveBeacon {
                uplink_url: "wss://uplink.example".to_string(),
                burst_quota: 4,
            },
        ),
    ]
}

#[test]
fn mask_deserialize_enum_variants_match_plain_derive_json() {
    for (input, expected) in channel_state_json_fixtures() {
        let masked: DeChannelState =
            serde_json::from_str(input).unwrap_or_else(|e| panic!("masked failed on {input}: {e}"));
        assert_eq!(masked, expected);
    }
}

/// Non-self-describing formats encode the variant *index* — postcard
/// round-trip proves declaration-order variant indices are preserved.
#[test]
fn mask_deserialize_enum_postcard_round_trip() {
    let plains = [
        plain_enums::DeChannelState::DormantUntilDusk,
        plain_enums::DeChannelState::RelayHandle("relay-9".to_string()),
        plain_enums::DeChannelState::JitterWindow(50, 250),
        plain_enums::DeChannelState::ActiveBeacon {
            uplink_url: "wss://uplink.example".to_string(),
            burst_quota: 4,
        },
    ];
    let expected = channel_state_json_fixtures();
    for (plain, (_, want)) in plains.iter().zip(expected) {
        let bytes = postcard::to_stdvec(plain).expect("plain serialization failed");
        let masked: DeChannelState =
            postcard::from_bytes(&bytes).expect("masked deserialization failed");
        assert_eq!(masked, want);
    }
}

#[test]
fn mask_deserialize_unknown_variant_error_matches_plain_derive() {
    let input = r#"{"NoSuchVariant":1}"#;
    let masked_err = serde_json::from_str::<DeChannelState>(input)
        .expect_err("masked must fail")
        .to_string();
    let plain_err = serde_json::from_str::<plain_enums::DeChannelState>(input)
        .expect_err("plain must fail")
        .to_string();
    assert_eq!(masked_err, plain_err);
    assert!(
        masked_err.contains("unknown variant `NoSuchVariant`")
            && masked_err.contains("`DormantUntilDusk`"),
        "unexpected error text: {masked_err}"
    );
}

/// Out-of-range variant index (non-self-describing path): postcard
/// encodes the variant tag as a varint; index 9 exceeds the 4-variant
/// enum and must produce the plain derive's `invalid_value` text.
#[test]
fn mask_deserialize_out_of_range_variant_index_error_matches_plain_derive() {
    let bytes = [9u8];
    let masked_err = postcard::from_bytes::<DeChannelState>(&bytes)
        .expect_err("masked must fail")
        .to_string();
    let plain_err = postcard::from_bytes::<plain_enums::DeChannelState>(&bytes)
        .expect_err("plain must fail")
        .to_string();
    assert_eq!(masked_err, plain_err);
}

#[test]
fn mask_deserialize_tuple_variant_invalid_length_error_matches_plain_derive() {
    let input = r#"{"JitterWindow":[50]}"#;
    let masked_err = serde_json::from_str::<DeChannelState>(input)
        .expect_err("masked must fail")
        .to_string();
    let plain_err = serde_json::from_str::<plain_enums::DeChannelState>(input)
        .expect_err("plain must fail")
        .to_string();
    assert_eq!(masked_err, plain_err);
    assert!(
        masked_err.contains("tuple variant DeChannelState::JitterWindow with 2 elements"),
        "unexpected error text: {masked_err}"
    );
}

#[test]
fn mask_deserialize_struct_variant_missing_field_error_matches_plain_derive() {
    let input = r#"{"ActiveBeacon":{"burst_quota":4}}"#;
    let masked_err = serde_json::from_str::<DeChannelState>(input)
        .expect_err("masked must fail")
        .to_string();
    let plain_err = serde_json::from_str::<plain_enums::DeChannelState>(input)
        .expect_err("plain must fail")
        .to_string();
    assert_eq!(masked_err, plain_err);
    assert!(
        masked_err.contains("missing field `uplink_url`"),
        "unexpected error text: {masked_err}"
    );
}

#[test]
fn mask_deserialize_enum_wrong_type_error_matches_plain_derive() {
    let input = "3";
    let masked_err = serde_json::from_str::<DeChannelState>(input)
        .expect_err("masked must fail")
        .to_string();
    let plain_err = serde_json::from_str::<plain_enums::DeChannelState>(input)
        .expect_err("plain must fail")
        .to_string();
    assert_eq!(masked_err, plain_err);
}

#[test]
fn mask_deserialize_empty_variants_match_plain_derive() {
    let pairs = [
        (r#""BareDrop""#, DeEmptyVariants::BareDrop),
        (r#"{"HollowTuple":[]}"#, DeEmptyVariants::HollowTuple()),
        (r#"{"HollowStruct":{}}"#, DeEmptyVariants::HollowStruct {}),
    ];
    for (input, expected) in pairs {
        let masked: DeEmptyVariants =
            serde_json::from_str(input).unwrap_or_else(|e| panic!("masked failed on {input}: {e}"));
        assert_eq!(masked, expected);
        // Same input must round-trip through the plain twin too —
        // guards against fixtures drifting from serde's wire shapes.
        serde_json::from_str::<plain_enums::DeEmptyVariants>(input)
            .unwrap_or_else(|e| panic!("plain failed on {input}: {e}"));
    }
}

#[test]
fn mask_deserialize_uninhabited_enum_derives() {
    fn assert_deserialize<T: for<'de> serde::Deserialize<'de>>() {}
    assert_deserialize::<DeNever>();
}

#[derive(MaskDeserialize, Debug, PartialEq)]
struct DeEnvelope<T> {
    sequence_marker: u64,
    payload: T,
}

#[derive(MaskDeserialize, Debug, PartialEq)]
struct DeGenericWrapper<T>(T);

#[derive(MaskDeserialize, Debug, PartialEq)]
enum DeGenericEvent<T> {
    Payload(T),
}

/// serde auto-borrows `&str` / `&[u8]` fields, bounding `'de` by the
/// field's lifetime — the masked derive must mirror that bound or
/// borrowed structs won't compile at all.
#[derive(MaskDeserialize, Debug, PartialEq)]
struct DeBorrowed<'a> {
    borrowed_label: &'a str,
    payload: u8,
}

/// serde also auto-borrows `&[u8]` fields. JSON cannot borrow bytes, so
/// this round-trips through postcard (zero-copy byte slices); the plain
/// `Serialize` derive just produces the wire bytes for the test.
#[derive(MaskDeserialize, serde::Serialize, Debug, PartialEq)]
struct DeBorrowedBytes<'a> {
    borrowed_blob: &'a [u8],
    payload: u8,
}

/// The borrow detection unwraps `Option`, so an `Option<&str>` field
/// still contributes its lifetime to the `'de: 'a` bound.
#[derive(MaskDeserialize, Debug, PartialEq)]
struct DeOptionBorrowed<'a> {
    maybe_label: Option<&'a str>,
    payload: u8,
}

#[derive(MaskDeserialize, Debug, PartialEq)]
struct DeRawIdent {
    r#type: String,
}

#[derive(MaskDeserialize, Debug, PartialEq)]
enum DeRawVariant {
    r#Loop { r#fn: u8 },
}

/// Hygiene: user field names that collide with the expansion's
/// internal vocabulary must not shadow generated locals.
#[derive(MaskDeserialize, Debug, PartialEq)]
struct DeHygiene {
    __seq: u8,
    __map: u8,
    __value: u8,
    __field0: u8,
    deserializer: u8,
}

#[test]
fn mask_deserialize_generic_struct_round_trips() {
    let input = r#"{"sequence_marker":42,"payload":["a","b"]}"#;
    let masked: DeEnvelope<Vec<String>> = serde_json::from_str(input).expect("masked failed");
    assert_eq!(masked.sequence_marker, 42);
    assert_eq!(masked.payload, vec!["a".to_string(), "b".to_string()]);
}

#[test]
fn mask_deserialize_generic_newtype_round_trips() {
    let masked: DeGenericWrapper<Vec<u8>> = serde_json::from_str("[1,2]").expect("masked failed");
    assert_eq!(masked, DeGenericWrapper(vec![1u8, 2]));
}

#[test]
fn mask_deserialize_generic_enum_round_trips() {
    let masked: DeGenericEvent<Vec<u8>> =
        serde_json::from_str(r#"{"Payload":[7]}"#).expect("masked failed");
    assert_eq!(masked, DeGenericEvent::Payload(vec![7u8]));
}

#[test]
fn mask_deserialize_borrowed_str_field_round_trips() {
    let input = r#"{"borrowed_label":"tag","payload":9}"#;
    let masked: DeBorrowed<'_> = serde_json::from_str(input).expect("masked failed");
    assert_eq!(masked.borrowed_label, "tag");
    assert_eq!(masked.payload, 9);
}

#[test]
fn mask_deserialize_borrowed_bytes_field_round_trips() {
    // postcard borrows `&[u8]` zero-copy from the input buffer; this
    // only compiles if the derive adds the `'de: 'a` bound for the
    // `&[u8]` field (the `is_slice_u8` borrow-detection branch).
    let blob: &[u8] = &[1, 2, 3];
    let original = DeBorrowedBytes {
        borrowed_blob: blob,
        payload: 9,
    };
    let bytes = postcard::to_stdvec(&original).expect("serialization failed");
    let restored: DeBorrowedBytes<'_> = postcard::from_bytes(&bytes).expect("masked failed");
    assert_eq!(restored, original);
}

#[test]
fn mask_deserialize_option_borrowed_str_field_round_trips() {
    // Present borrows `&str` through the `Option`; absent resolves the
    // missing field to `None`. Both rely on the lifetime being detected
    // through the `Option` wrapper.
    let present: DeOptionBorrowed<'_> =
        serde_json::from_str(r#"{"maybe_label":"tag","payload":9}"#).expect("present failed");
    assert_eq!(
        present,
        DeOptionBorrowed {
            maybe_label: Some("tag"),
            payload: 9,
        }
    );
    let absent: DeOptionBorrowed<'_> =
        serde_json::from_str(r#"{"payload":9}"#).expect("absent failed");
    assert_eq!(
        absent,
        DeOptionBorrowed {
            maybe_label: None,
            payload: 9,
        }
    );
}

/// Raw identifiers deserialize unraw'd (`r#type` ← `"type"`),
/// matching the plain derive.
#[test]
fn mask_deserialize_raw_ident_field_unraws_like_plain_derive() {
    let masked: DeRawIdent = serde_json::from_str(r#"{"type":"beacon"}"#).expect("masked failed");
    assert_eq!(masked.r#type, "beacon");
}

#[test]
fn mask_deserialize_raw_ident_variant_unraws_like_plain_derive() {
    let masked: DeRawVariant = serde_json::from_str(r#"{"Loop":{"fn":1}}"#).expect("masked failed");
    assert_eq!(masked, DeRawVariant::r#Loop { r#fn: 1 });
}

#[test]
fn mask_deserialize_hygiene_against_user_field_names() {
    let input = r#"{"__seq":1,"__map":2,"__value":3,"__field0":4,"deserializer":5}"#;
    let masked: DeHygiene = serde_json::from_str(input).expect("masked failed");
    assert_eq!(
        masked,
        DeHygiene {
            __seq: 1,
            __map: 2,
            __value: 3,
            __field0: 4,
            deserializer: 5,
        }
    );
}

/// The docs recommend pairing all three masking derives; they must
/// expand cleanly on one type and round-trip through each other.
#[derive(litmask::MaskSerialize, MaskDeserialize, litmask::MaskDebug, PartialEq)]
struct DeCombined {
    relay_endpoint: String,
    retry_budget: u32,
}

#[test]
fn mask_deserialize_round_trips_mask_serialize_output() {
    let original = DeCombined {
        relay_endpoint: "wss://relay.example".to_string(),
        retry_budget: 3,
    };
    let json = serde_json::to_string(&original).expect("masked serialization failed");
    let restored: DeCombined = serde_json::from_str(&json).expect("masked deserialization failed");
    assert!(restored == original);
    let bytes = postcard::to_stdvec(&original).expect("masked serialization failed");
    let restored: DeCombined = postcard::from_bytes(&bytes).expect("masked deserialization failed");
    assert!(restored == original);
}

#[test]
fn mask_deserialize_repeat_calls_are_stable() {
    let input = r#"{"license_server_url":"u","activation_count":1}"#;
    // Second call exercises the cached-name path (OnceLock hit).
    let first: DeConfig = serde_json::from_str(input).expect("first deserialization failed");
    let second: DeConfig = serde_json::from_str(input).expect("second deserialization failed");
    assert_eq!(first, second);
}
