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

#[derive(MaskSerialize)]
enum MaskedChannelState {
    DormantUntilDusk,
    RelayHandle(String),
    JitterWindow(u32, u32),
    ActiveBeacon {
        uplink_url_zzyzx: String,
        burst_quota: u8,
    },
}

#[derive(serde::Serialize)]
enum PlainChannelState {
    DormantUntilDusk,
    RelayHandle(String),
    JitterWindow(u32, u32),
    ActiveBeacon {
        uplink_url_zzyzx: String,
        burst_quota: u8,
    },
}

fn channel_state_pairs() -> Vec<(MaskedChannelState, PlainChannelState)> {
    vec![
        (
            MaskedChannelState::DormantUntilDusk,
            PlainChannelState::DormantUntilDusk,
        ),
        (
            MaskedChannelState::RelayHandle("relay-9".to_string()),
            PlainChannelState::RelayHandle("relay-9".to_string()),
        ),
        (
            MaskedChannelState::JitterWindow(50, 250),
            PlainChannelState::JitterWindow(50, 250),
        ),
        (
            MaskedChannelState::ActiveBeacon {
                uplink_url_zzyzx: "wss://uplink.example".to_string(),
                burst_quota: 4,
            },
            PlainChannelState::ActiveBeacon {
                uplink_url_zzyzx: "wss://uplink.example".to_string(),
                burst_quota: 4,
            },
        ),
    ]
}

#[test]
fn mask_serialize_enum_variants_match_plain_derive_json() {
    common::init_once();
    for (masked, plain) in channel_state_pairs() {
        assert_eq!(
            serde_json::to_string(&masked).expect("masked serialization failed"),
            serde_json::to_string(&plain).expect("plain serialization failed"),
        );
    }
}

/// Non-self-describing formats encode the variant *index*, not its
/// name — byte-identity here proves the masked derive preserves
/// declaration-order variant indices (§E.2.1).
#[test]
fn mask_serialize_enum_variants_match_plain_derive_postcard() {
    common::init_once();
    for (masked, plain) in channel_state_pairs() {
        assert_eq!(
            postcard::to_stdvec(&masked).expect("masked serialization failed"),
            postcard::to_stdvec(&plain).expect("plain serialization failed"),
        );
    }
}

/// Empty bracketed variants are NOT unit variants to serde: `V()` is
/// a zero-arity tuple variant, `V {}` a zero-field struct variant,
/// and self-describing formats give each a distinct wire shape.
#[derive(MaskSerialize)]
enum MaskedEmptyVariants {
    BareDrop,
    HollowTuple(),
    HollowStruct {},
}

#[derive(serde::Serialize)]
enum PlainEmptyVariants {
    BareDrop,
    HollowTuple(),
    HollowStruct {},
}

#[test]
fn mask_serialize_empty_variants_match_plain_derive() {
    common::init_once();
    let pairs = [
        (MaskedEmptyVariants::BareDrop, PlainEmptyVariants::BareDrop),
        (
            MaskedEmptyVariants::HollowTuple(),
            PlainEmptyVariants::HollowTuple(),
        ),
        (
            MaskedEmptyVariants::HollowStruct {},
            PlainEmptyVariants::HollowStruct {},
        ),
    ];
    for (masked, plain) in pairs {
        assert_eq!(
            serde_json::to_string(&masked).expect("masked serialization failed"),
            serde_json::to_string(&plain).expect("plain serialization failed"),
        );
        assert_eq!(
            postcard::to_stdvec(&masked).expect("masked serialization failed"),
            postcard::to_stdvec(&plain).expect("plain serialization failed"),
        );
    }
}

#[derive(MaskSerialize)]
enum MaskedRawVariant {
    r#Loop { r#fn: u8 },
}

#[derive(serde::Serialize)]
enum PlainRawVariant {
    r#Loop { r#fn: u8 },
}

#[test]
fn mask_serialize_raw_ident_variant_unraws_like_plain_derive() {
    common::init_once();
    let masked_json = serde_json::to_string(&MaskedRawVariant::r#Loop { r#fn: 1 })
        .expect("masked serialization failed");
    assert_eq!(
        masked_json,
        serde_json::to_string(&PlainRawVariant::r#Loop { r#fn: 1 })
            .expect("plain serialization failed"),
    );
    assert_eq!(masked_json, r#"{"Loop":{"fn":1}}"#);
}

#[derive(MaskSerialize)]
enum MaskedGenericEvent<T> {
    Payload(T),
}

#[test]
fn mask_serialize_generic_enum() {
    common::init_once();
    assert_eq!(
        serde_json::to_string(&MaskedGenericEvent::Payload(vec![7u8]))
            .expect("masked serialization failed"),
        r#"{"Payload":[7]}"#
    );
}

/// Uninhabited enums must still derive — the plain serde derive
/// generates `match *self {}`, and so must the masked one.
#[derive(MaskSerialize)]
enum MaskedNever {}

#[test]
fn mask_serialize_uninhabited_enum_derives() {
    fn assert_serialize<T: serde::Serialize>() {}
    assert_serialize::<MaskedNever>();
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
