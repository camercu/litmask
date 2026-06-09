//! Profile-split failure diagnostics (§5.4).
//!
//! Every runtime decryption failure routes through one of the entry
//! points here, which is the single home for the §5.4 profile split:
//!
//! - **Release** (`cfg(not(debug_assertions))`) — a bare `panic!()` with
//!   no message, so no litmask-identifying string reaches `.rodata` (the
//!   opacity contract in the `runtime` module header).
//! - **Debug** (`cfg(debug_assertions)`) — a loud, actionable panic that
//!   names the likely cause, so init/decrypt failures surface on the
//!   developer's own machine before any artifact ships.
//!
//! Centralizing the split here keeps the call sites in `runtime` free of
//! per-site `cfg` branching and guarantees the two profiles cannot drift
//! apart. The actionable message literals live behind
//! `cfg(debug_assertions)`, so they are never compiled into a release
//! artifact. A debug binary is self-decrypting at the Embedded floor
//! *and* prints these diagnostics, so it MUST NOT be distributed (§7.1).

use crate::error::InitError;

/// Map an init / lazy-init failure to an actionable hint. Pure (no
/// panic, no I/O) so the mapping is unit-testable; [`init_failure`]
/// wraps it in the panic. Debug-only: the strings must not reach a
/// release artifact.
#[cfg(debug_assertions)]
fn init_hint(err: &InitError) -> &'static str {
    match err {
        InitError::KeyProvider(_) => {
            "key provider could not source unlock material — is the key channel \
             (e.g. LITMASK_UNLOCK_KEY) set, readable, and well-formed?"
        }
        InitError::Decryption => {
            "the runtime-sourced key did not open the build-sealed wrapper — provider \
             material, machine id, or init! form disagrees with the tier this build \
             was sealed under"
        }
        InitError::UnsupportedFormat => {
            "the wrapper's format-version byte is unrecognized — litmask build/runtime \
             version mismatch"
        }
    }
}

/// Diverge on an init / lazy-init failure.
pub(crate) fn init_failure(err: &InitError) -> ! {
    #[cfg(debug_assertions)]
    panic!("litmask: init failed: {}", init_hint(err));
    #[cfg(not(debug_assertions))]
    {
        let _ = err;
        panic!();
    }
}

/// Diverge on a per-string `mask!()` blob decrypt failure.
pub(crate) fn blob_failure() -> ! {
    #[cfg(debug_assertions)]
    panic!(
        "litmask: could not decrypt a mask!() literal — the mask key is wrong or the \
         ciphertext was tampered"
    );
    #[cfg(not(debug_assertions))]
    panic!();
}

/// Diverge when a `weak_mask!("...")` decode does not yield valid UTF-8.
pub(crate) fn weak_utf8_failure() -> ! {
    #[cfg(debug_assertions)]
    panic!(
        "litmask: weak_mask!() decoded to invalid UTF-8 — the obfuscated bytes or the \
         wrapper were tampered in process"
    );
    #[cfg(not(debug_assertions))]
    panic!();
}

/// Diverge when a `weak_mask!(c"...")` decode contains an interior NUL.
#[cfg(feature = "std")]
pub(crate) fn weak_cstr_failure() -> ! {
    #[cfg(debug_assertions)]
    panic!(
        "litmask: weak_mask!() C-string decode hit an interior NUL — the obfuscated \
         bytes or the wrapper were tampered in process"
    );
    #[cfg(not(debug_assertions))]
    panic!();
}

// Debug-only: locks the actionable-message contract the release arm
// deliberately drops. `cfg(debug_assertions)` because the assertions
// inspect text that only exists in debug.
#[cfg(all(test, debug_assertions, feature = "std"))]
mod tests {
    use super::*;
    use crate::error::KeyError;
    use std::string::{String, ToString};

    // Avoids string-bearing `.expect(...)` / `panic!(...)` so the
    // `tamper_panic` decryption-path scan stays satisfied even though it
    // reads this whole file (test code included).
    fn panic_message(f: impl FnOnce() + std::panic::UnwindSafe) -> String {
        let prev = std::panic::take_hook();
        std::panic::set_hook(std::boxed::Box::new(|_| {}));
        let payload = std::panic::catch_unwind(f).err().unwrap();
        std::panic::set_hook(prev);
        if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else if let Some(s) = payload.downcast_ref::<&str>() {
            (*s).to_string()
        } else {
            unreachable!()
        }
    }

    #[test]
    fn init_hint_distinguishes_each_cause() {
        let provider = init_hint(&InitError::KeyProvider(KeyError::NotFound));
        let decryption = init_hint(&InitError::Decryption);
        let format = init_hint(&InitError::UnsupportedFormat);

        assert!(provider.contains("key channel"));
        assert!(decryption.contains("build-sealed wrapper"));
        assert!(format.contains("version mismatch"));
        assert_ne!(provider, decryption);
        assert_ne!(decryption, format);
    }

    /// Every debug entry point panics with the `litmask:` prefix the
    /// integration tests (and operators) key off. Locking it here keeps
    /// a wording edit from silently dropping the prefix.
    #[test]
    fn every_entry_point_carries_litmask_prefix() {
        assert!(panic_message(|| init_failure(&InitError::Decryption)).contains("litmask:"));
        assert!(panic_message(|| blob_failure()).contains("litmask:"));
        assert!(panic_message(|| weak_utf8_failure()).contains("litmask:"));
        assert!(panic_message(|| weak_cstr_failure()).contains("litmask:"));
    }
}
