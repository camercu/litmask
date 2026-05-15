//! Round-trip integration tests for `mask!(concat!(...))` and
//! `mask!(include_str!(...))`. The proc-macro flattens these
//! invocations into the same encryption pipeline as a bare literal,
//! so the runtime return value is identical to what `mask!("literal")`
//! would produce — even though the on-disk ciphertext differs
//! (per-call nonce).

mod common;

use litmask::{KeyError, KeyProvider, UnlockKey, init_with, mask};
use std::sync::Once;

struct StaticProvider {
    key_b64: String,
}

impl KeyProvider for StaticProvider {
    fn unlock_key(&self) -> Result<UnlockKey, KeyError> {
        UnlockKey::from_base64url(&self.key_b64)
    }
}

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        let key = common::read_unlock_key(&common::config_path(common::Profile::Debug));
        let provider = StaticProvider { key_b64: key };
        init_with!(provider).expect("init_with succeeded");
    });
}

#[test]
fn mask_concat_of_string_literals_round_trips() {
    setup();
    let s: String = mask!(concat!("a", "b", "c"));
    assert_eq!(s, "abc");
}

#[test]
fn mask_concat_with_nested_concat_flattens() {
    setup();
    let s: String = mask!(concat!("foo-", concat!("bar-", "baz")));
    assert_eq!(s, "foo-bar-baz");
}

#[test]
fn mask_concat_with_single_arg() {
    setup();
    let s: String = mask!(concat!("only"));
    assert_eq!(s, "only");
}

#[test]
fn mask_include_str_round_trips_file_contents() {
    setup();
    // Path is resolved relative to CARGO_MANIFEST_DIR, not the source
    // file containing the invocation.
    let s: String = mask!(include_str!("examples/fixtures/quote.txt"));
    assert!(s.contains("vermillion-axolotl-7e2d4a"));
}

#[test]
fn mask_concat_empty_round_trips_to_empty_string() {
    setup();
    let s: String = mask!(concat!());
    assert!(s.is_empty());
}

#[test]
fn mask_concat_mixes_include_str_with_literal() {
    setup();
    let s: String = mask!(concat!(
        "prefix-",
        include_str!("examples/fixtures/quote.txt")
    ));
    assert!(s.starts_with("prefix-"));
    assert!(s.contains("vermillion-axolotl-7e2d4a"));
}

/// Two `mask!(include_str!("same.txt"))` invocations must each get a
/// unique nonce (per the per-call `CALL_COUNTER` derivation) and
/// round-trip to the same plaintext. A regression that hoisted
/// `include_str` resolution into a per-file cache without re-encrypting
/// would still pass round-trip but lose nonce uniqueness — the
/// existence of two distinct call sites here keeps the contract
/// visible.
#[test]
fn mask_include_str_two_invocations_round_trip_independently() {
    setup();
    let a: String = mask!(include_str!("examples/fixtures/quote.txt"));
    let b: String = mask!(include_str!("examples/fixtures/quote.txt"));
    assert_eq!(a, b);
    assert!(a.contains("vermillion-axolotl-7e2d4a"));
}
