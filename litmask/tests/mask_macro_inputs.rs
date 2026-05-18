//! Round-trip integration tests for `mask!(concat!(...))` and
//! `mask!(include_str!(...))`. The proc-macro flattens these
//! invocations into the same encryption pipeline as a bare literal,
//! so the runtime return value is identical to what `mask!("literal")`
//! would produce — even though the on-disk ciphertext differs
//! (per-call nonce).

mod common;

use litmask::mask;

#[test]
fn mask_concat_of_string_literals_round_trips() {
    common::init_once();
    let s: String = mask!(concat!("a", "b", "c"));
    assert_eq!(s, "abc");
}

#[test]
fn mask_concat_with_nested_concat_flattens() {
    common::init_once();
    let s: String = mask!(concat!("foo-", concat!("bar-", "baz")));
    assert_eq!(s, "foo-bar-baz");
}

#[test]
fn mask_concat_with_single_arg() {
    common::init_once();
    let s: String = mask!(concat!("only"));
    assert_eq!(s, "only");
}

#[test]
fn mask_include_str_round_trips_file_contents() {
    common::init_once();
    // Two paths to one file: mask!'s include_str! is
    // CARGO_MANIFEST_DIR-relative ("examples/fixtures/...") whereas
    // std's include_str! is source-file-relative ("../examples/..."
    // from tests/). Both resolve to the same on-disk byte sequence,
    // so the equality assertion locks "no mutation, no truncation"
    // and the fixture only lives in one place.
    let s: String = mask!(include_str!("examples/fixtures/quote.txt"));
    assert_eq!(s, include_str!("../examples/fixtures/quote.txt"));
}

#[test]
fn mask_concat_empty_round_trips_to_empty_string() {
    common::init_once();
    let s: String = mask!(concat!());
    assert!(s.is_empty());
}

#[test]
fn mask_concat_mixes_include_str_with_literal() {
    common::init_once();
    let s: String = mask!(concat!(
        "prefix-",
        include_str!("examples/fixtures/quote.txt")
    ));
    assert_eq!(
        s,
        concat!("prefix-", include_str!("../examples/fixtures/quote.txt"))
    );
}

/// Each `mask!(include_str!(...))` call site is its own AEAD blob —
/// resolving the same file at two sites must still produce two
/// independently-decryptable values that agree on plaintext. Nonce
/// uniqueness across the two blobs comes from the distinct
/// `(file, line, column)` source positions keyed into the per-call-
/// site nonce derivation (spec §1.5.2); not asserted here (the
/// runtime values would be identical even on nonce reuse).
#[test]
fn mask_include_str_decrypts_at_every_call_site() {
    common::init_once();
    let a: String = mask!(include_str!("examples/fixtures/quote.txt"));
    let b: String = mask!(include_str!("examples/fixtures/quote.txt"));
    assert_eq!(a, b);
    assert_eq!(a, include_str!("../examples/fixtures/quote.txt"));
}
