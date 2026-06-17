//! `#[serde(alias = ...)]` and `#[serde(deny_unknown_fields)]` support
//! in `MaskDeserialize` (`serde`). Compared against plain-serde
//! twins so accepted inputs and error messages match (§E.2.6).

#![cfg(feature = "serde")]

mod common;

use litmask::{MaskDeserialize, MaskSerialize};

#[derive(MaskSerialize, MaskDeserialize, PartialEq, Debug)]
struct MaskedAlias {
    #[serde(alias = "id", alias = "identifier")]
    primary_key: u32,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
struct PlainAlias {
    #[serde(alias = "id", alias = "identifier")]
    primary_key: u32,
}

#[test]
fn alias_accepts_each_name() {
    for input in [r#"{"primary_key":5}"#, r#"{"id":5}"#, r#"{"identifier":5}"#] {
        let masked: MaskedAlias = serde_json::from_str(input).expect("masked de");
        let plain: PlainAlias = serde_json::from_str(input).expect("plain de");
        assert_eq!(masked.primary_key, plain.primary_key);
        assert_eq!(masked.primary_key, 5);
    }
    // Serialization still uses the primary name.
    let json = serde_json::to_string(&MaskedAlias { primary_key: 5 }).expect("ser");
    assert_eq!(json, r#"{"primary_key":5}"#);
}

#[derive(MaskDeserialize, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
struct MaskedDeny {
    known: u8,
}

#[derive(serde::Deserialize, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
struct PlainDeny {
    known: u8,
}

#[test]
fn deny_unknown_fields_accepts_known() {
    let masked: MaskedDeny = serde_json::from_str(r#"{"known":3}"#).expect("masked de");
    assert_eq!(masked, MaskedDeny { known: 3 });
}

#[test]
fn deny_unknown_fields_rejects_unknown_like_plain() {
    let input = r#"{"known":3,"surprise":9}"#;
    let masked_err = serde_json::from_str::<MaskedDeny>(input).expect_err("masked must reject");
    let plain_err = serde_json::from_str::<PlainDeny>(input).expect_err("plain must reject");
    // Error message must be byte-identical to the plain derive's.
    assert_eq!(masked_err.to_string(), plain_err.to_string());
    assert!(
        masked_err.to_string().contains("unknown field `surprise`"),
        "got: {masked_err}",
    );
}

#[derive(MaskDeserialize, PartialEq, Debug)]
enum MaskedEnum {
    Channel {
        #[serde(alias = "host")]
        endpoint: String,
    },
}

#[derive(serde::Deserialize, PartialEq, Debug)]
enum PlainEnum {
    Channel {
        #[serde(alias = "host")]
        endpoint: String,
    },
}

#[test]
fn alias_in_struct_variant() {
    for input in [
        r#"{"Channel":{"endpoint":"e"}}"#,
        r#"{"Channel":{"host":"e"}}"#,
    ] {
        let masked: MaskedEnum = serde_json::from_str(input).expect("masked de");
        let plain: PlainEnum = serde_json::from_str(input).expect("plain de");
        let (MaskedEnum::Channel { endpoint: m }, PlainEnum::Channel { endpoint: p }) =
            (&masked, &plain);
        assert_eq!(m, p);
        assert_eq!(m, "e");
    }
}
