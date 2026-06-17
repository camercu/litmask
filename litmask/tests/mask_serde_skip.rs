//! `#[serde(skip)]` / `skip_serializing` / `skip_deserializing` support
//! in `MaskSerialize` / `MaskDeserialize` (`serde`). Each
//! masked type is compared against a structurally-identical plain-serde
//! twin to pin field-count and Default-fill behavior byte-for-byte
//! (§E.2.1/§E.2.6).

#![cfg(feature = "serde")]

mod common;

use litmask::{MaskDeserialize, MaskSerialize};

#[derive(MaskSerialize, MaskDeserialize, PartialEq, Debug, Default)]
struct MaskedSkip {
    kept: u32,
    #[serde(skip)]
    internal: String,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Default)]
struct PlainSkip {
    kept: u32,
    #[serde(skip)]
    internal: String,
}

#[test]
fn skip_both_matches_plain_derive() {
    let masked = MaskedSkip {
        kept: 7,
        internal: "secret".to_string(),
    };
    let json = serde_json::to_string(&masked).expect("serialize");
    // Skipped field is absent from the wire entirely.
    assert_eq!(json, r#"{"kept":7}"#);
    assert_eq!(
        json,
        serde_json::to_string(&PlainSkip {
            kept: 7,
            internal: "secret".to_string(),
        })
        .expect("plain"),
    );
    // Deserialize fills the skipped field with Default.
    let back: MaskedSkip = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        back,
        MaskedSkip {
            kept: 7,
            internal: String::new(),
        },
    );
}

#[derive(MaskSerialize, MaskDeserialize, PartialEq, Debug, Default)]
struct MaskedSplitSkip {
    always: u8,
    #[serde(skip_serializing)]
    de_only: u8,
    #[serde(skip_deserializing)]
    ser_only: u8,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Default)]
struct PlainSplitSkip {
    always: u8,
    #[serde(skip_serializing)]
    de_only: u8,
    #[serde(skip_deserializing)]
    ser_only: u8,
}

#[test]
fn skip_serializing_and_deserializing_split() {
    let masked = MaskedSplitSkip {
        always: 1,
        de_only: 2,
        ser_only: 3,
    };
    let json = serde_json::to_string(&masked).expect("serialize");
    // `de_only` (skip_serializing) absent; `ser_only` (skip_deserializing) present.
    assert_eq!(
        json,
        serde_json::to_string(&PlainSplitSkip {
            always: 1,
            de_only: 2,
            ser_only: 3,
        })
        .expect("plain"),
    );
    assert_eq!(json, r#"{"always":1,"ser_only":3}"#);
    // Deserializing the masked output: `ser_only` is skip_deserializing
    // → Default (0); `de_only` read from input.
    let masked_back: MaskedSplitSkip =
        serde_json::from_str(r#"{"always":1,"de_only":2,"ser_only":3}"#).expect("deserialize");
    let plain_back: PlainSplitSkip =
        serde_json::from_str(r#"{"always":1,"de_only":2,"ser_only":3}"#).expect("plain");
    assert_eq!(masked_back.always, plain_back.always);
    assert_eq!(masked_back.de_only, plain_back.de_only);
    assert_eq!(masked_back.ser_only, plain_back.ser_only);
    assert_eq!(masked_back.ser_only, 0);
}

#[derive(MaskSerialize, MaskDeserialize, PartialEq, Debug)]
enum MaskedEnum {
    Channel {
        endpoint: String,
        #[serde(skip)]
        cached: u64,
    },
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
enum PlainEnum {
    Channel {
        endpoint: String,
        #[serde(skip)]
        cached: u64,
    },
}

#[test]
fn skip_in_struct_variant_matches_plain_derive() {
    let masked = MaskedEnum::Channel {
        endpoint: "e".to_string(),
        cached: 99,
    };
    let json = serde_json::to_string(&masked).expect("serialize");
    assert_eq!(
        json,
        serde_json::to_string(&PlainEnum::Channel {
            endpoint: "e".to_string(),
            cached: 99,
        })
        .expect("plain"),
    );
    let back: MaskedEnum = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        back,
        MaskedEnum::Channel {
            endpoint: "e".to_string(),
            cached: 0,
        },
    );
}
