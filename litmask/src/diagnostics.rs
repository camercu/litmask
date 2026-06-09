//! Debug-build failure diagnostics (§5.4).
//!
//! The panic-message hygiene that keeps litmask-identifying strings out
//! of `.rodata` (see the `runtime` module header) protects **shipped**
//! binaries, so it applies to **release** alone. This module holds the
//! loud, actionable counterpart for **debug** builds: each runtime
//! failure maps to a hint the developer can act on. The whole module is
//! `#[cfg(debug_assertions)]`-gated, so its identifying strings are never
//! compiled into a release artifact — the matching release arms in
//! `runtime` take a bare `panic!()` instead.
//!
//! A debug binary is self-decrypting at the Embedded floor *and* now
//! prints these diagnostics, so it MUST NOT be distributed (§7.1).

use crate::error::InitError;

/// Map an init / lazy-init failure to an actionable hint. Pure (no
/// panic, no I/O) so the mapping is unit-testable; [`init_failure`]
/// wraps it in the panic.
pub(crate) fn init_hint(err: &InitError) -> &'static str {
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

/// Panic on an init / lazy-init failure with the [`init_hint`] text.
pub(crate) fn init_failure(err: &InitError) -> ! {
    panic!("litmask: init failed: {}", init_hint(err));
}

/// Panic on a per-string `mask!()` blob decrypt failure.
pub(crate) fn blob_failure() -> ! {
    panic!(
        "litmask: could not decrypt a mask!() literal — the mask key is wrong or the \
         ciphertext was tampered"
    );
}

/// Panic when a `weak_mask!("...")` decode does not yield valid UTF-8.
pub(crate) fn weak_utf8_failure() -> ! {
    panic!(
        "litmask: weak_mask!() decoded to invalid UTF-8 — the obfuscated bytes or the \
         wrapper were tampered in process"
    );
}

/// Panic when a `weak_mask!(c"...")` decode contains an interior NUL.
#[cfg(feature = "std")]
pub(crate) fn weak_cstr_failure() -> ! {
    panic!(
        "litmask: weak_mask!() C-string decode hit an interior NUL — the obfuscated \
         bytes or the wrapper were tampered in process"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::KeyError;

    #[test]
    fn init_hint_distinguishes_each_cause() {
        let provider = init_hint(&InitError::KeyProvider(KeyError::NotFound));
        let decryption = init_hint(&InitError::Decryption);
        let format = init_hint(&InitError::UnsupportedFormat);

        // Each cause yields a distinct, actionable hint.
        assert!(provider.contains("key channel"));
        assert!(decryption.contains("build-sealed wrapper"));
        assert!(format.contains("version mismatch"));
        assert_ne!(provider, decryption);
        assert_ne!(decryption, format);
    }
}
