//! The debug-only init-after-lazy guard must be per-wrapper accurate
//! (ADR-0001, transparent masking).
//!
//! The guard exists to catch an `init!` that arrives *after* the lazy
//! first-`mask!()` path already unlocked the *same* wrapper — a latent
//! ordering bug that a higher-tier reseal turns into a refusal. With the
//! per-wrapper mask-key cache, a host that explicitly `init!`s its own
//! wrapper while a transitive library lazy-unlocks a *different* wrapper
//! is a valid configuration: the guard must not fire on the host's
//! repeat-`init!` just because some other crate lazy-unlocked first.
//!
//! These run only in debug (the guard compiles to nothing in release).

#![cfg(all(feature = "std", debug_assertions))]

use litmask::__internal::{__decrypt, __init_with_wrapper};
use litmask::EmbeddedProvider;
use litmask_internal::test_util::{build_blob, build_embedded_wrapper};
use litmask_internal::{KEY_LEN, NONCE_LEN};

#[test]
fn repeat_init_is_silent_when_a_different_wrapper_lazy_inits() {
    // Library wrapper A: lazy-unlocked by a transitive `mask!()`.
    let mask_key_a = [0x31u8; KEY_LEN];
    let wrapper_a = build_embedded_wrapper(&mask_key_a, &[0xC1u8; KEY_LEN]);
    let blob_a = build_blob(&mask_key_a, &[3u8; NONCE_LEN], b"lib-secret-aaaa");
    assert_eq!(
        __decrypt(&blob_a, &wrapper_a, "embedded"),
        b"lib-secret-aaaa"
    );

    // Host wrapper B: explicitly init'd, twice. The repeat is an
    // idempotent no-op — not an init-after-lazy on B (the lazy install
    // was A). The former process-global flag false-positived here.
    let mask_key_b = [0x32u8; KEY_LEN];
    let wrapper_b = build_embedded_wrapper(&mask_key_b, &[0xC2u8; KEY_LEN]);
    __init_with_wrapper(EmbeddedProvider::new(&wrapper_b), &wrapper_b).expect("first init");
    __init_with_wrapper(EmbeddedProvider::new(&wrapper_b), &wrapper_b).expect("repeat init");
}

#[test]
#[should_panic = "init!() ran after a mask!()"]
fn init_after_lazy_on_the_same_wrapper_fires_guard() {
    // Lazy-unlock wrapper D via a `mask!()`-equivalent decrypt, then run
    // an explicit `init!` on the *same* wrapper: the real ordering bug.
    let mask_key_d = [0x41u8; KEY_LEN];
    let wrapper_d = build_embedded_wrapper(&mask_key_d, &[0xD1u8; KEY_LEN]);
    let blob_d = build_blob(&mask_key_d, &[4u8; NONCE_LEN], b"lib-secret-dddd");
    assert_eq!(
        __decrypt(&blob_d, &wrapper_d, "embedded"),
        b"lib-secret-dddd"
    );

    let _ = __init_with_wrapper(EmbeddedProvider::new(&wrapper_d), &wrapper_d);
}
