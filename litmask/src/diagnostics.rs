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

/// Diverge when the lazy first-`mask!()` path runs on a non-Embedded
/// seal — i.e. a `mask!()` reached the runtime before the `init!(...)`
/// the higher tier requires. The debug message names the init-ordering
/// cause (and the offending tier) so the fix is obvious; the release arm
/// stays bare to preserve opacity. Distinct from [`init_failure`]'s
/// generic decryption hint, which an unguarded lazy path would otherwise
/// surface for this same bug.
pub(crate) fn lazy_init_wrong_tier(tier: &str) -> ! {
    #[cfg(debug_assertions)]
    panic!(
        "litmask: a mask!() reached the runtime before init!() — this build is sealed \
         `{tier}` (above the Embedded floor), so it must call the matching init!(...) form \
         before the first mask!()"
    );
    #[cfg(not(debug_assertions))]
    {
        let _ = tier;
        panic!();
    }
}

/// Diverge when an `init!` / `init_with!` seam runs AFTER a lazy
/// first-`mask!()` already installed the mask key. Debug-only: on the
/// Embedded floor (the only tier where the lazy path succeeds) the lazy
/// key equals the `init!()` key, so release builds keep the silent
/// idempotent `Ok(())` (§2.6.1.4) — but the ordering is a latent bug
/// that turns into the §2.1.1.12a runtime refusal the moment the
/// consumer reseals at a higher tier. Fail loudly on the developer's
/// machine instead, naming the fix (move `init!` ahead of the first
/// `mask!()`).
#[cfg(debug_assertions)]
pub(crate) fn init_after_lazy() -> ! {
    // The line-level cfg is redundant with the fn-level one but
    // load-bearing for the `tamper_panic` scan, which exempts a
    // message-bearing panic only when the gate sits directly above it.
    #[cfg(debug_assertions)]
    panic!(
        "litmask: init!() ran after a mask!() had already lazily initialized the runtime — \
         move init!() ahead of the first mask!(); on a build sealed above the Embedded floor \
         this ordering would refuse to decrypt at the first mask!()"
    );
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
        assert!(panic_message(|| lazy_init_wrong_tier("external")).contains("litmask:"));
        assert!(panic_message(|| init_after_lazy()).contains("litmask:"));
    }

    /// The init-after-lazy refusal must name the ordering cause and the
    /// fix (move `init!` ahead of the first `mask!()`) — not read like
    /// the generic init-failure hints, since no decryption failed.
    #[test]
    fn init_after_lazy_names_ordering_and_fix() {
        let msg = panic_message(|| init_after_lazy());
        assert!(msg.contains("after"));
        assert!(msg.contains("mask!"));
        assert!(msg.contains("ahead of the first mask!"));
    }

    /// The lazy-tier refusal must point at the init-ordering cause (so an
    /// operator calls `init!` first) and name the offending tier — not
    /// read like the generic decryption hint, which is the misleading
    /// message an unguarded lazy path would have surfaced for this bug.
    #[test]
    fn lazy_init_wrong_tier_names_ordering_and_tier() {
        let msg = panic_message(|| lazy_init_wrong_tier("external"));
        assert!(msg.contains("before init!()"));
        assert!(msg.contains("external"));
        assert_ne!(msg, init_hint(&InitError::Decryption));
    }
}
