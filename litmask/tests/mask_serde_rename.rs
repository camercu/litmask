//! `#[serde(rename = ...)]` support in `MaskSerialize` / `MaskDeserialize`
//! (`serde`). Each masked type is compared against a
//! structurally-identical plain-serde twin: serialized output must be
//! byte-identical, and deserialization must accept the renamed wire
//! names — the masking only moves the resolved name into the AEAD blob,
//! never changes which name appears on the wire (§E.2.1/§E.2.6).

#![cfg(feature = "serde")]

mod common;

use litmask::{MaskDeserialize, MaskSerialize};

#[derive(MaskSerialize, MaskDeserialize, PartialEq, Debug)]
struct MaskedField {
    #[serde(rename = "url")]
    endpoint: String,
    activation_count: u32,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
struct PlainField {
    #[serde(rename = "url")]
    endpoint: String,
    activation_count: u32,
}

#[test]
fn field_rename_matches_plain_derive() {
    let masked = MaskedField {
        endpoint: "https://x".to_string(),
        activation_count: 4,
    };
    let plain = PlainField {
        endpoint: "https://x".to_string(),
        activation_count: 4,
    };
    let json = serde_json::to_string(&masked).expect("serialize");
    assert_eq!(
        json,
        serde_json::to_string(&plain).expect("plain serialize")
    );
    assert_eq!(json, r#"{"url":"https://x","activation_count":4}"#);
    let back: MaskedField = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, masked);
}

#[derive(MaskSerialize, MaskDeserialize, PartialEq, Debug)]
#[serde(rename = "Renamed")]
struct MaskedContainer {
    value: u8,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
#[serde(rename = "Renamed")]
struct PlainContainer {
    value: u8,
}

#[test]
fn container_rename_matches_plain_derive() {
    let masked = MaskedContainer { value: 9 };
    let plain = PlainContainer { value: 9 };
    // The container name is invisible in JSON output, but its
    // round-trip and any name-bearing error text must still match.
    assert_eq!(
        serde_json::to_string(&masked).expect("serialize"),
        serde_json::to_string(&plain).expect("plain serialize"),
    );
    let back: MaskedContainer = serde_json::from_str(r#"{"value":9}"#).expect("deserialize");
    assert_eq!(back, masked);
}

#[derive(MaskSerialize, MaskDeserialize, PartialEq, Debug)]
struct MaskedSplit {
    #[serde(rename(serialize = "ser_name", deserialize = "de_name"))]
    field: u32,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
struct PlainSplit {
    #[serde(rename(serialize = "ser_name", deserialize = "de_name"))]
    field: u32,
}

#[test]
fn split_rename_matches_plain_derive() {
    let masked = MaskedSplit { field: 1 };
    let masked_json = serde_json::to_string(&masked).expect("serialize");
    assert_eq!(
        masked_json,
        serde_json::to_string(&PlainSplit { field: 1 }).expect("plain serialize"),
    );
    assert_eq!(masked_json, r#"{"ser_name":1}"#);
    // Deserialize accepts the deserialize-side name, not the serialize one.
    let back: MaskedSplit = serde_json::from_str(r#"{"de_name":7}"#).expect("deserialize");
    assert_eq!(back, MaskedSplit { field: 7 });
}

#[derive(MaskSerialize, MaskDeserialize, PartialEq, Debug)]
enum MaskedEnum {
    #[serde(rename = "dns")]
    Dns {
        #[serde(rename = "host")]
        hostname: String,
    },
    #[serde(rename = "raw")]
    Raw(u32),
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
enum PlainEnum {
    #[serde(rename = "dns")]
    Dns {
        #[serde(rename = "host")]
        hostname: String,
    },
    #[serde(rename = "raw")]
    Raw(u32),
}

#[test]
fn variant_and_variant_field_rename_match_plain_derive() {
    for (masked, plain) in [
        (
            MaskedEnum::Dns {
                hostname: "h".to_string(),
            },
            PlainEnum::Dns {
                hostname: "h".to_string(),
            },
        ),
        (MaskedEnum::Raw(3), PlainEnum::Raw(3)),
    ] {
        let json = serde_json::to_string(&masked).expect("serialize");
        assert_eq!(
            json,
            serde_json::to_string(&plain).expect("plain serialize")
        );
        let back: MaskedEnum = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, masked);
    }
}
