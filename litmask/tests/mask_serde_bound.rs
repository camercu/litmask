//! `#[serde(bound = "...")]` where-clause override in `MaskSerialize` /
//! `MaskDeserialize` (`unstable-serde`). An empty bound drops the
//! default `T: Serialize` / `T: Deserialize<'de>` predicate, so a type
//! parameter that implements neither still compiles — proving the
//! override replaces (not augments) the generated bounds. Compared
//! against a plain-serde twin (§E.2.1/§E.2.6).

#![cfg(feature = "unstable-serde")]

mod common;

use core::marker::PhantomData;

use litmask::{MaskDeserialize, MaskSerialize};

// Implements neither Serialize nor Deserialize.
#[derive(PartialEq, Debug, Default)]
struct Unconstrained;

#[derive(MaskSerialize, MaskDeserialize, PartialEq, Debug)]
#[serde(bound = "")]
struct Wrapper<T> {
    value: u8,
    #[serde(skip)]
    marker: PhantomData<T>,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
#[serde(bound = "")]
struct PlainWrapper<T> {
    value: u8,
    #[serde(skip)]
    marker: PhantomData<T>,
}

#[test]
fn empty_bound_drops_default_and_matches_plain() {
    common::init_once();
    let masked: Wrapper<Unconstrained> = Wrapper {
        value: 7,
        marker: PhantomData,
    };
    let json = serde_json::to_string(&masked).expect("serialize");
    assert_eq!(json, r#"{"value":7}"#);
    assert_eq!(
        json,
        serde_json::to_string(&PlainWrapper::<Unconstrained> {
            value: 7,
            marker: PhantomData,
        })
        .expect("plain"),
    );
    let back: Wrapper<Unconstrained> = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, masked);
}

// Split bound form: only the relevant direction's predicate is supplied.
#[derive(MaskSerialize, MaskDeserialize, PartialEq, Debug)]
#[serde(bound(serialize = "", deserialize = ""))]
struct SplitWrapper<T> {
    tag: u16,
    #[serde(skip)]
    marker: PhantomData<T>,
}

#[test]
fn split_bound_compiles_and_round_trips() {
    common::init_once();
    let masked: SplitWrapper<Unconstrained> = SplitWrapper {
        tag: 42,
        marker: PhantomData,
    };
    let json = serde_json::to_string(&masked).expect("serialize");
    assert_eq!(json, r#"{"tag":42}"#);
    let back: SplitWrapper<Unconstrained> = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, masked);
}
