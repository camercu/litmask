//! `#[doc(hidden)] #[macro_export]` plumbing macros emitted into proc-macro
//! expansions.
//!
//! These are not part of the stable API. They live apart from the crate
//! root so `lib.rs` stays the user-facing surface (docs, re-exports, the
//! public `mask_write!` / `mask_println!` family) while the feature-gated
//! std / `machine-id` dispatch arms concentrate here. `#[macro_export]`
//! hoists each to the crate-root namespace regardless of the defining
//! module, and the generated code calls them by absolute path
//! (`::litmask::__wrapper_bytes!()`), so this relocation changes no
//! resolution.

/// Internal helper: expand to `include_bytes!(...)` for the embedded
/// encrypted-`mask_key` wrapper at the caller's `OUT_DIR`. Shared by
/// [`init!`](crate::init) and the `mask!` proc-macro to avoid duplicating
/// the path literal at both call sites.
#[doc(hidden)]
#[macro_export]
macro_rules! __wrapper_bytes {
    () => {
        ::core::include_bytes!(::core::concat!(
            ::core::env!("OUT_DIR"),
            "/litmask_wrapper.bin"
        ))
    };
}

/// Internal helper: expand to the build-sealed tier tag string
/// (`LITMASK_SEAL_TIER`, set by `litmask_build::emit`). Read at the
/// consumer's compile time — the same `cargo:rustc-env` the `init!`
/// proc-macro cross-checks against — and passed into [`__internal::__decrypt`](crate::__internal)
/// so the lazy first-`mask!()` path can refuse to derive the Embedded
/// key on a higher-tier seal (an init-ordering bug) instead of failing
/// the wrapper AEAD check with a misleading decryption error.
#[doc(hidden)]
#[macro_export]
macro_rules! __seal_tier {
    () => {
        ::core::env!("LITMASK_SEAL_TIER")
    };
}

/// Internal dispatch for `mask!(c"...")` expansion. With the `std`
/// feature, wraps the runtime's [`__internal::__decrypt`](crate::__internal) return in
/// `CString::new(...).unwrap()`; without it, emits a `compile_error!`
/// pointing at the user's `mask!(c"...")` call site.
///
/// Lives at the crate root (not inside [`__internal`](crate::__internal)) because the
/// proc-macro can't read the consumer's feature flags — gating must
/// happen here, in `litmask`'s own cfg context. The c-string-specific
/// construction lives in this shim rather than in a dedicated runtime
/// helper because it is the only kind whose return type is `std`-only.
///
/// `CString::new(...)` only returns `NulError` if the input contains
/// an interior NUL byte. Two layers rule this out at compile + runtime:
/// `LitCStr` rejects interior NUL at parse time (so the encrypted
/// blob never carries one), and AEAD authentication rejects any
/// tampering that could introduce one. The bare `.unwrap()` is
/// therefore unreachable in practice — and stays bare (no message)
/// to keep the unwind path free of litmask-identifying plaintext.
/// The unwind point is the user's `mask!(c"...")` call site, not
/// inside the litmask crate.
#[cfg(feature = "std")]
#[doc(hidden)]
#[macro_export]
macro_rules! __decrypt_cstring_call {
    ($blob:expr, $wrapper:expr) => {
        ::std::ffi::CString::new($crate::__internal::__decrypt(
            $blob,
            $wrapper,
            $crate::__seal_tier!(),
        ))
        .unwrap()
    };
}

#[cfg(not(feature = "std"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __decrypt_cstring_call {
    ($blob:expr, $wrapper:expr) => {
        ::core::compile_error!(
            "mask!(c\"...\") requires the `std` feature on the `litmask` crate; \
             enable it via `litmask = { features = [\"std\"] }`"
        )
    };
}

/// Internal dispatch for `weak_mask!(c"...")` expansion. Under `std`,
/// allocates a per-call-site `WeakCStrCell` cache and decodes via
/// `__weak_decode_cstr`. Under `no_std`, emits a `compile_error!`.
#[cfg(feature = "std")]
#[doc(hidden)]
#[macro_export]
macro_rules! __weak_decode_cstr_call {
    ($obf:expr, $wrapper:expr) => {{
        static __WEAK_CACHE: $crate::__internal::WeakCStrCell =
            $crate::__internal::WeakCStrCell::new();
        $crate::__internal::__weak_decode_cstr($obf, $wrapper, &__WEAK_CACHE)
    }};
}

#[cfg(not(feature = "std"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __weak_decode_cstr_call {
    ($obf:expr, $wrapper:expr) => {
        ::core::compile_error!(
            "weak_mask!(c\"...\") requires the `std` feature on the `litmask` crate; \
             enable it via `litmask = { features = [\"std\"] }`"
        )
    };
}

/// Internal dispatch for `init!(bind_to_machine)` expansion. The seal tier is
/// chosen at build time by `LITMASK_MACHINE_ID` presence, independent of
/// this crate's `machine-id` feature, so a `machine`-sealed build can pass
/// `init!`'s form↔tier cross-check while the feature is off. Without this
/// guard the expansion would reference the feature-gated
/// `__govern_machine` and fail with an opaque "cannot find function";
/// here the missing feature surfaces a directed message instead.
#[cfg(feature = "machine-id")]
#[doc(hidden)]
#[macro_export]
macro_rules! __govern_machine_call {
    ($wrapper:expr) => {
        $crate::__internal::__govern_machine($wrapper)
    };
}

#[cfg(not(feature = "machine-id"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __govern_machine_call {
    ($wrapper:expr) => {
        ::core::compile_error!(
            "init!(bind_to_machine) requires the `machine-id` feature on the `litmask` crate; \
             enable it via `litmask = { features = [\"machine-id\"] }`"
        )
    };
}

/// Internal dispatch for `init!(bind_to_machine + <provider>)` expansion. Like
/// [`__govern_machine_call!`](crate::__govern_machine_call), the two-factor seal tier is chosen at
/// build time by env-var presence, independent of this crate's
/// `machine-id` feature, so the form↔tier cross-check can pass while the
/// feature is off. This guard turns that case into a directed message
/// instead of an opaque "cannot find function" against the feature-gated
/// `__govern_machine_external`.
#[cfg(feature = "machine-id")]
#[doc(hidden)]
#[macro_export]
macro_rules! __govern_machine_external_call {
    ($wrapper:expr, $external:expr) => {
        $crate::__internal::__govern_machine_external($wrapper, $external)
    };
}

#[cfg(not(feature = "machine-id"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __govern_machine_external_call {
    ($wrapper:expr, $external:expr) => {
        ::core::compile_error!(
            "init!(bind_to_machine + provider) requires the `machine-id` feature on the `litmask` \
             crate; enable it via `litmask = { features = [\"machine-id\"] }`"
        )
    };
}

#[cfg(test)]
mod tests {
    /// `__wrapper_bytes!` hardcodes the wrapper filename inside a
    /// `concat!`, which needs a literal token and so cannot reference
    /// `litmask_internal::WRAPPER_ARTIFACT`. Pin the literal to that const
    /// — a const rename that overlooked this macro would desync the
    /// runtime read from the build write. Scrapes this file's own source
    /// (the const value appears only in the macro, never in this test).
    #[test]
    fn wrapper_bytes_literal_matches_artifact_const() {
        let src = include_str!("macro_plumbing.rs");
        assert!(
            src.contains(crate::internal::WRAPPER_ARTIFACT),
            "__wrapper_bytes! must embed the WRAPPER_ARTIFACT filename literally",
        );
    }
}
