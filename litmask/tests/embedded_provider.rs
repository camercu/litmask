//! Integration tests for the Embedded seal tier (§2.5.5). The default
//! [`EmbeddedProvider`] holds no secret: it recomputes `unlock_key`
//! from the embedded wrapper's public nonce, so an Embedded build
//! opens with nothing stored in the binary beyond the cleartext nonce.
//!
//! Byte-level derivation is pinned by the unit tests in
//! `litmask::provider::embedded`; this integration test pins the public
//! contract: `init!()` succeeds under an Embedded build and round-trips
//! the same `mask!` literals.

use litmask::{init, mask};

#[test]
fn embedded_init_against_build_succeeds() {
    init!().expect("Embedded init! round-trips the build wrapper");
    assert_eq!(
        mask!("embedded-provider-fixture"),
        "embedded-provider-fixture"
    );
}
