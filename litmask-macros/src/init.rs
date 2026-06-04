//! `init!` proc-macro: no-arg Embedded-tier runtime initialization with
//! a build-authoritative form↔tier cross-check.
//!
//! `init!()` is the no-argument form and is valid ONLY when the build
//! sealed the default **Embedded** tier. `litmask_build::emit` records
//! the sealed tier in the `LITMASK_SEAL_TIER` rustc-env var; this macro
//! reads it at expansion time and emits a §1.9.6 `compile_error!` when
//! the form and the sealed tier disagree — catching, at compile time,
//! an `init!()` against a binary sealed for a higher tier (or one with
//! no litmask build wiring at all). A `macro_rules!` form cannot read an
//! env var and branch to `compile_error!`, which is why `init!` is a
//! proc-macro.

use proc_macro::TokenStream;
use quote::quote;

use crate::common::{FailTag, compile_error};

const MACRO_NAME: &str = "init";

/// rustc-env var carrying the build-sealed tier tag. Set by
/// `litmask_build::emit`; MUST match the build side byte-for-byte.
const SEAL_TIER_VAR: &str = "LITMASK_SEAL_TIER";

/// Tier tag whose seal the no-arg `init!()` form unlocks.
const EMBEDDED_TIER: &str = "embedded";

/// Decide whether the build-sealed `tier` permits the no-arg `init!()`
/// form. Returns `Ok(())` for the Embedded tier, else the §1.9.6 error
/// detail naming the form↔tier mismatch. Pure so the cross-check is
/// unit-testable without mutating the process environment (the
/// workspace `forbid(unsafe_code)` rules out `env::set_var`).
pub(crate) fn check_embedded_tier(tier: Option<&str>) -> Result<(), String> {
    match tier {
        Some(EMBEDDED_TIER) => Ok(()),
        Some(other) => Err(format!(
            "init!() unlocks the `{EMBEDDED_TIER}` seal tier, but this build sealed `{other}`"
        )),
        None => Err(format!(
            "{SEAL_TIER_VAR} is unset; this build did not run litmask_build::emit() in build.rs"
        )),
    }
}

/// Expand `init!()`. Rejects arguments (the arg-taking forms land in a
/// later tier task), then reads `LITMASK_SEAL_TIER` and cross-checks the
/// form against the sealed tier before emitting the Embedded init call.
pub(crate) fn expand(input: &TokenStream) -> TokenStream {
    let span = proc_macro::Span::call_site().into();
    if !input.is_empty() {
        return compile_error(
            span,
            MACRO_NAME,
            FailTag::ArgsNotAllowed,
            "init!() takes no arguments",
        )
        .to_compile_error()
        .into();
    }
    let tier = std::env::var(SEAL_TIER_VAR).ok();
    if let Err(detail) = check_embedded_tier(tier.as_deref()) {
        return compile_error(span, MACRO_NAME, FailTag::TierMismatch, &detail)
            .to_compile_error()
            .into();
    }
    // Bind the embedded wrapper once: `EmbeddedProvider` reads its
    // cleartext nonce, then the runtime decrypts the same bytes.
    quote! {{
        let __litmask_wrapper = ::litmask::__wrapper_bytes!();
        ::litmask::__internal::__init_with_wrapper(
            ::litmask::EmbeddedProvider::new(__litmask_wrapper),
            __litmask_wrapper,
        )
    }}
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_tier_is_accepted() {
        assert!(check_embedded_tier(Some(EMBEDDED_TIER)).is_ok());
    }

    #[test]
    fn other_tier_is_rejected_naming_both_tiers() {
        let detail = check_embedded_tier(Some("machine")).unwrap_err();
        assert!(detail.contains(EMBEDDED_TIER));
        assert!(detail.contains("machine"));
    }

    #[test]
    fn absent_tier_is_rejected_naming_the_env_var() {
        let detail = check_embedded_tier(None).unwrap_err();
        assert!(detail.contains(SEAL_TIER_VAR));
    }
}
