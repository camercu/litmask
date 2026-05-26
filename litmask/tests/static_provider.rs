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

use litmask::{EnvVarProvider, KeyProvider, StaticProvider, init_with, mask};

#[test]
fn unlock_key_returns_ok_on_every_call() {
    let key = common::unlock_key_from_config();
    let provider = StaticProvider::new(key);
    assert!(provider.unlock_key().is_ok());
    assert!(provider.unlock_key().is_ok());
}

#[test]
fn init_with_static_provider_against_build_config_succeeds() {
    let key = common::unlock_key_from_config();
    let _ = init_with!(StaticProvider::new(key));
    let _ = mask!("static-provider-fixture");
}

#[test]
fn key_provider_is_object_safe() {
    let _: Box<dyn KeyProvider> = Box::new(EnvVarProvider::default());
}
