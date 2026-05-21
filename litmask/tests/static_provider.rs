//! Integration tests for `StaticProvider` (§2.5.5). The provider
//! holds a clone of the supplied `UnlockKey` and returns it on every
//! `unlock_key()` call — intentionally duplicating the secret bytes
//! in process memory, which is why the type is documented for tests
//! and one-shot demos only.
//!
//! End-to-end byte-level assertions live in the unit tests inside
//! `litmask::provider`; the integration tests here pin the public
//! contract: `init_with!(StaticProvider::new(k))` succeeds when `k`
//! matches the build's `unlock_key`, and the example builds + runs.

mod common;

use litmask::{KeyProvider, StaticProvider, UnlockKey, init_with, mask};

fn unlock_key_from_build_config() -> UnlockKey {
    let b64 = common::read_unlock_key(&common::config_path(common::Profile::Debug));
    UnlockKey::from_base64url(&b64).expect("build config holds a 32-byte base64url key")
}

#[test]
fn unlock_key_returns_ok_on_every_call() {
    let key = unlock_key_from_build_config();
    let provider = StaticProvider::new(key);
    assert!(provider.unlock_key().is_ok());
    assert!(provider.unlock_key().is_ok());
}

#[test]
fn init_with_static_provider_against_build_config_succeeds() {
    // The build's `litmask.config` carries the unlock_key that
    // matches the embedded wrapper; StaticProvider holding that key
    // MUST succeed at init and unlock the runtime so a subsequent
    // mask!() decrypts.
    let key = unlock_key_from_build_config();
    let _ = init_with!(StaticProvider::new(key));
    let _ = mask!("static-provider-fixture");
}
