//! `#[serde(with)]` / `serialize_with` / `deserialize_with` support in
//! `MaskSerialize` / `MaskDeserialize` (`serde`). The field
//! value is routed through user functions; compared against a
//! plain-serde twin (§E.2.1/§E.2.6).

#![cfg(feature = "serde")]
// serde's serialize_with signature dictates `&T` even for `Copy` / where
// `&str` would do — these helpers must match it, so the lints don't apply.
#![allow(clippy::trivially_copy_pass_by_ref, clippy::ptr_arg)]

mod common;

use litmask::{MaskDeserialize, MaskSerialize};

// A `with` module: serialize a bool as 0/1, deserialize the same.
mod bool_as_int {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &bool, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(u8::from(*value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
        Ok(u8::deserialize(deserializer)? != 0)
    }
}

fn serialize_upper<S: serde::Serializer>(value: &String, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_uppercase())
}

fn deserialize_lower<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<String, D::Error> {
    use serde::Deserialize;
    Ok(String::deserialize(deserializer)?.to_lowercase())
}

#[derive(MaskSerialize, MaskDeserialize, PartialEq, Debug)]
struct MaskedWith {
    #[serde(with = "bool_as_int")]
    flag: bool,
    #[serde(
        serialize_with = "serialize_upper",
        deserialize_with = "deserialize_lower"
    )]
    label: String,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
struct PlainWith {
    #[serde(with = "bool_as_int")]
    flag: bool,
    #[serde(
        serialize_with = "serialize_upper",
        deserialize_with = "deserialize_lower"
    )]
    label: String,
}

#[test]
fn with_functions_match_plain_derive_serialize() {
    let masked = MaskedWith {
        flag: true,
        label: "hi".to_string(),
    };
    let json = serde_json::to_string(&masked).expect("serialize");
    assert_eq!(json, r#"{"flag":1,"label":"HI"}"#);
    assert_eq!(
        json,
        serde_json::to_string(&PlainWith {
            flag: true,
            label: "hi".to_string(),
        })
        .expect("plain"),
    );
}

#[test]
fn with_functions_match_plain_derive_deserialize() {
    let input = r#"{"flag":0,"label":"WORLD"}"#;
    let masked: MaskedWith = serde_json::from_str(input).expect("masked de");
    let plain: PlainWith = serde_json::from_str(input).expect("plain de");
    assert_eq!(masked.flag, plain.flag);
    assert_eq!(masked.label, plain.label);
    // deserialize_with lowercased the label; with-module parsed the int.
    assert!(!masked.flag);
    assert_eq!(masked.label, "world");
}

// Case A — a `with`-fn on a *concrete* field of a *generic* container.
// The adapter never names `T`, but the old blanket reject fired on any
// generic container carrying a with-field. This is the common unblock.
#[derive(MaskSerialize, MaskDeserialize, PartialEq, Debug)]
struct GenericContainer<T> {
    #[serde(with = "bool_as_int")]
    flag: bool,
    value: T,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
struct PlainContainer<T> {
    #[serde(with = "bool_as_int")]
    flag: bool,
    value: T,
}

#[test]
fn with_on_concrete_field_in_generic_container_matches_plain() {
    let masked = GenericContainer {
        flag: true,
        value: "hi".to_string(),
    };
    let json = serde_json::to_string(&masked).expect("ser");
    assert_eq!(
        json,
        serde_json::to_string(&PlainContainer {
            flag: true,
            value: "hi".to_string(),
        })
        .expect("plain ser"),
    );
    let back: GenericContainer<String> = serde_json::from_str(&json).expect("de");
    assert_eq!(back, masked);
}

// Case B — a `with`-fn on a *generic-typed* field. serde drops the auto
// `T: Serialize` bound on a with-field, so the user supplies it via
// `#[serde(bound)]`; the masking adapter must carry that same bound (a
// local item cannot name the outer `T`). `passthrough` is wire-identity.
mod passthrough {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<T: Serialize, S: Serializer>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.serialize(serializer)
    }

    pub fn deserialize<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        T::deserialize(deserializer)
    }
}

#[derive(MaskSerialize, MaskDeserialize, PartialEq, Debug)]
#[serde(bound(
    serialize = "T: serde::Serialize",
    deserialize = "T: serde::Deserialize<'de>"
))]
struct GenericWithField<T> {
    #[serde(with = "passthrough")]
    value: T,
    plain: u8,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
#[serde(bound(
    serialize = "T: serde::Serialize",
    deserialize = "T: serde::Deserialize<'de>"
))]
struct PlainWithField<T> {
    #[serde(with = "passthrough")]
    value: T,
    plain: u8,
}

#[test]
fn with_on_generic_field_matches_plain() {
    // T = String
    let masked = GenericWithField {
        value: "hi".to_string(),
        plain: 7,
    };
    let json = serde_json::to_string(&masked).expect("ser");
    assert_eq!(
        json,
        serde_json::to_string(&PlainWithField {
            value: "hi".to_string(),
            plain: 7,
        })
        .expect("plain ser"),
    );
    let back: GenericWithField<String> = serde_json::from_str(&json).expect("de");
    assert_eq!(back, masked);

    // T = u32 — a second instantiation through the same adapter.
    let m2 = GenericWithField {
        value: 42u32,
        plain: 1,
    };
    let j2 = serde_json::to_string(&m2).expect("ser");
    assert_eq!(
        j2,
        serde_json::to_string(&PlainWithField {
            value: 42u32,
            plain: 1,
        })
        .expect("plain ser"),
    );
    let b2: GenericWithField<u32> = serde_json::from_str(&j2).expect("de");
    assert_eq!(b2, m2);
}
