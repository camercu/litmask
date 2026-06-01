//! Integration tests for `MachineIdProvider` (§2.5.4).
//!
//! The provider derives a 32-byte unlock key from the host machine ID
//! via BLAKE3-keyed-hash. The hash is deterministic per host, so two
//! consecutive `unlock_key()` calls on a stable-machine-id host
//! return `Ok(_)` reliably. Byte-level identity / salt-discrimination
//! tests live as unit tests inside `litmask::provider` where the
//! recovered key bytes are reachable without exposing them through
//! the public API.
//!
//! `machine-uid::get()` can fail on container runtimes,
//! `/etc/machine-id`-less embedded Linux, and OpenBSD by default
//! (§1.6.5). Tests that exercise the failure path live in the unit
//! tests, where the error surface is reachable without depending on
//! a host with a broken machine-uid path.

#![cfg(feature = "machine-id")]

use litmask::{KeyError, KeyProvider, MachineIdProvider};

/// Environment-probing test, not a correctness gate: both Ok and
/// Err(Provider) are valid outcomes depending on host capabilities.
#[test]
fn unlock_key_on_supported_host_or_returns_provider_error() {
    // Hosts in the workspace's CI matrix split into two camps:
    // standard Linux/macOS/Windows where machine-uid succeeds, and
    // OpenBSD / container runtimes without /etc/machine-id where it
    // fails. Both outcomes are documented in §1.6.5 — assert one of
    // the two and surface unexpected error shapes loudly.
    match MachineIdProvider::new().unlock_key() {
        Ok(_) => {}
        Err(KeyError::Provider(inner)) => {
            // The Display message must be non-empty so operators
            // have a chance to identify the upstream failure
            // (machine-uid's documented error text).
            let msg = format!("{inner}");
            assert!(!msg.is_empty(), "Provider error Display is empty");
        }
        Err(other) => panic!("unexpected KeyError variant on machine-id failure: {other:?}"),
    }
}

#[test]
fn key_provider_error_is_send_and_sync_so_it_crosses_thread_boundaries() {
    // The `Box<dyn Error + Send + Sync>` bound is load-bearing for
    // applications that retrieve the provider error in one task and
    // log it from another. A type that lost `Send` or `Sync` would
    // not compile inside `std::thread::spawn`'s closure — the
    // assertion here is the static bound check.
    let err: KeyError =
        KeyError::Provider(Box::new(std::io::Error::other("machine-uid: simulated")));
    let handle = std::thread::spawn(move || format!("{err}"));
    let s = handle.join().expect("thread joined cleanly");
    assert!(!s.is_empty());
}
