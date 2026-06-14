//! Integration tests for the Embedded seal tier (§2.5.5). The default
//! [`EmbeddedProvider`] holds no secret: it recomputes `unlock_key`
//! from the embedded wrapper's public nonce, so an Embedded build
//! opens with nothing stored in the binary beyond the cleartext nonce.
//!
//! Byte-level derivation is pinned by the unit tests in
//! `litmask::provider::embedded`; this integration test pins the public
//! contract: an Embedded build self-initializes on the first `mask!()`
//! (no `init!`) and round-trips the same `mask!` literals.

use litmask::mask;

#[test]
fn embedded_round_trips_via_lazy_self_init() {
    assert_eq!(
        mask!("embedded-provider-fixture"),
        "embedded-provider-fixture"
    );
}
