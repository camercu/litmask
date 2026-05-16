//! Locks the §1.9.5 tampering panic policy for `mask!`:
//! - AC 1: a tampered per-string blob panics at the call site.
//! - AC 4: no `.expect("...")` or `panic!("...")` with a custom
//!   message survives in the `mask!` decryption path.

mod common;

/// `catch_unwind` rather than `#[should_panic]` so the assertion does
/// not depend on `panic!()`'s default message text ("explicit panic"
/// is a stable-but-implementation-detail string in `core`). Any
/// future Rust release that changes the default panic message leaves
/// this test green; the only thing we assert is that the call
/// unwinds.
#[test]
fn decrypt_str_panics_on_tampered_blob() {
    // `init_once` populates the process-global mask key cell from the
    // production unlock key. The subsequent blob is the minimum valid
    // shape (nonce + zero-byte ciphertext + tag) but zero-filled, so
    // AEAD authentication fails — the panic this asserts is the
    // §1.9.5 tampering-detection panic, not a lazy-init env-var
    // miss that would also surface as an unwind.
    common::init_once();

    // Silence the panic message during catch_unwind; without the noop
    // hook the test output is polluted by stderr from std's default
    // panic hook. The race window with other concurrent tests'
    // panic output is acceptable — this is test infrastructure, not
    // production state.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let outcome = std::panic::catch_unwind(|| {
        let blob: [u8; 28] = [0u8; 28];
        let _ = ::litmask::__internal::__decrypt_str(&blob, ::litmask::__wrapper_bytes!());
    });

    std::panic::set_hook(prev_hook);

    assert!(
        outcome.is_err(),
        "expected __decrypt_str to panic on tampered blob"
    );
}

/// Scans `runtime.rs` for `.expect("msg")` and `panic!("msg"` patterns
/// — the two ways a litmask-specific string would leak into a binary
/// from the decryption path. Adding any new helper in `runtime.rs`
/// must use the match-Ok-Err-panic!() form documented in §1.9.5.
#[test]
fn no_custom_panic_messages_in_mask_decryption_path() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let src =
        std::fs::read_to_string(format!("{manifest}/src/runtime.rs")).expect("read runtime.rs");

    let custom_panic =
        regex::Regex::new(r#"\.expect\("[^"]+"\)|panic!\("[^"]+""#).expect("regex compiles");

    let hits: Vec<(usize, &str)> = src
        .lines()
        .enumerate()
        .filter(|(_, line)| custom_panic.is_match(line))
        .map(|(i, line)| (i + 1, line))
        .collect();

    assert!(
        hits.is_empty(),
        "runtime.rs leaks custom panic-message text in the decryption path: {hits:?}",
    );
}
