//! `#[serde(transparent)]` support in `MaskSerialize` /
//! `MaskDeserialize` (`serde`): the struct (de)serializes as
//! its single field with no wrapper on the wire. Compared against a
//! plain-serde twin (§E.2.1/§E.2.6).

#![cfg(feature = "serde")]

mod common;

use litmask::{MaskDeserialize, MaskSerialize};

#[derive(MaskSerialize, MaskDeserialize, PartialEq, Debug)]
#[serde(transparent)]
struct MaskedNamed {
    inner: u32,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
#[serde(transparent)]
struct PlainNamed {
    inner: u32,
}

#[test]
fn transparent_named_serializes_as_inner() {
    let masked = MaskedNamed { inner: 42 };
    let json = serde_json::to_string(&masked).expect("serialize");
    // No struct wrapper — just the inner value.
    assert_eq!(json, "42");
    assert_eq!(
        json,
        serde_json::to_string(&PlainNamed { inner: 42 }).expect("plain"),
    );
    let back: MaskedNamed = serde_json::from_str("42").expect("deserialize");
    assert_eq!(back, masked);
}

#[derive(MaskSerialize, MaskDeserialize, PartialEq, Debug)]
#[serde(transparent)]
struct MaskedTuple(String);

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
#[serde(transparent)]
struct PlainTuple(String);

#[test]
fn transparent_tuple_serializes_as_inner() {
    let masked = MaskedTuple("hello".to_string());
    let json = serde_json::to_string(&masked).expect("serialize");
    assert_eq!(json, r#""hello""#);
    assert_eq!(
        json,
        serde_json::to_string(&PlainTuple("hello".to_string())).expect("plain"),
    );
    let back: MaskedTuple = serde_json::from_str(r#""hello""#).expect("deserialize");
    assert_eq!(back, masked);
}
