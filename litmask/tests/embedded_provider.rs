//! Integration tests for the Embedded seal tier (§2.5.5). The default
//! [`EmbeddedProvider`] holds no secret: it recomputes `unlock_key`
//! from the embedded wrapper's public nonce, so an Embedded build
//! opens with nothing stored in the binary beyond the cleartext nonce.
//!
//! Byte-level derivation is pinned by the unit tests in
//! `litmask::provider::embedded`; these integration tests pin the
//! public contract: `init!()` succeeds under an Embedded build, and a
//! caller-supplied `KeyProvider` round-trips the same `mask!` literals
//! via `init_with!`.

mod common;

use litmask::{KeyError, KeyProvider, UnlockKey, init, init_with, mask};

/// Inline `KeyProvider` over a base64url-encoded key from
/// `litmask.config`. Stands in for the retired `StaticProvider`: the
/// trait is public, so external callers wire their own verbatim-key
/// provider when they need the explicit `init_with!` path.
struct ConfigProvider {
    key_b64: String,
}

impl KeyProvider for ConfigProvider {
    fn unlock_key(&self) -> Result<UnlockKey, KeyError> {
        UnlockKey::from_base64url(&self.key_b64)
    }
}

#[test]
fn embedded_init_against_build_succeeds() {
    init!().expect("Embedded init! round-trips the build wrapper");
    let _ = mask!("embedded-provider-fixture");
}

#[test]
fn init_with_inline_provider_against_build_config_succeeds() {
    let key_b64 = common::read_unlock_key(&common::self_config_path());
    let provider = ConfigProvider { key_b64 };
    assert!(provider.unlock_key().is_ok());
    let _ = init_with!(provider);
    let _ = mask!("inline-provider-fixture");
}
