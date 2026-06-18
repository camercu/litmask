//! `#[serde(skip_serializing_if = "path")]` support in `MaskSerialize`
//! (`unstable-serde`). The masked type is compared against a
//! plain-serde twin to pin the dynamic struct-length behavior
//! byte-for-byte (§E.2.1).

#![cfg(feature = "unstable-serde")]

mod common;

use litmask::{MaskDeserialize, MaskSerialize};

#[derive(MaskSerialize, MaskDeserialize, PartialEq, Debug)]
struct MaskedOpt {
    always: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    maybe: Option<u32>,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
struct PlainOpt {
    always: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    maybe: Option<u32>,
}

#[test]
fn skip_serializing_if_none_omits_field() {
    let masked = MaskedOpt {
        always: 1,
        maybe: None,
    };
    let json = serde_json::to_string(&masked).expect("serialize");
    assert_eq!(json, r#"{"always":1}"#);
    assert_eq!(
        json,
        serde_json::to_string(&PlainOpt {
            always: 1,
            maybe: None,
        })
        .expect("plain"),
    );
    let back: MaskedOpt = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        back,
        MaskedOpt {
            always: 1,
            maybe: None
        }
    );
}

#[test]
fn skip_serializing_if_some_keeps_field() {
    let masked = MaskedOpt {
        always: 2,
        maybe: Some(9),
    };
    let json = serde_json::to_string(&masked).expect("serialize");
    assert_eq!(json, r#"{"always":2,"maybe":9}"#);
    assert_eq!(
        json,
        serde_json::to_string(&PlainOpt {
            always: 2,
            maybe: Some(9),
        })
        .expect("plain"),
    );
    let back: MaskedOpt = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        back,
        MaskedOpt {
            always: 2,
            maybe: Some(9),
        },
    );
}

// All fields conditionally skipped → empty object, length 0.
#[derive(MaskSerialize, PartialEq, Debug)]
struct MaskedAllOptional {
    #[serde(skip_serializing_if = "Option::is_none")]
    a: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    b: Option<u8>,
}

#[derive(serde::Serialize, PartialEq, Debug)]
struct PlainAllOptional {
    #[serde(skip_serializing_if = "Option::is_none")]
    a: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    b: Option<u8>,
}

#[test]
fn skip_serializing_if_all_skipped_is_empty() {
    let masked = MaskedAllOptional { a: None, b: None };
    let json = serde_json::to_string(&masked).expect("serialize");
    assert_eq!(json, "{}");
    assert_eq!(
        json,
        serde_json::to_string(&PlainAllOptional { a: None, b: None }).expect("plain"),
    );
}

// In a struct variant.
#[derive(MaskSerialize, PartialEq, Debug)]
enum MaskedEnum {
    Beacon {
        id: u8,
        #[serde(skip_serializing_if = "Option::is_none")]
        nonce: Option<u64>,
    },
}

#[derive(serde::Serialize, PartialEq, Debug)]
enum PlainEnum {
    Beacon {
        id: u8,
        #[serde(skip_serializing_if = "Option::is_none")]
        nonce: Option<u64>,
    },
}

#[test]
fn skip_serializing_if_in_struct_variant() {
    for (m, p) in [
        (
            MaskedEnum::Beacon { id: 1, nonce: None },
            PlainEnum::Beacon { id: 1, nonce: None },
        ),
        (
            MaskedEnum::Beacon {
                id: 2,
                nonce: Some(7),
            },
            PlainEnum::Beacon {
                id: 2,
                nonce: Some(7),
            },
        ),
    ] {
        assert_eq!(
            serde_json::to_string(&m).expect("serialize"),
            serde_json::to_string(&p).expect("plain"),
        );
    }
}
