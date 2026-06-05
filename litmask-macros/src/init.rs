//! `init!` proc-macro: runtime initialization with a
//! build-authoritative form↔tier cross-check.
//!
//! Two forms, each valid only against the matching sealed tier:
//!
//! - `init!()` — no-argument **Embedded** form (keyless default).
//! - `init!(<provider-expr>)` — **External** form taking a
//!   [`KeyProvider`] value (env, file, custom).
//!
//! `litmask_build::emit` records the sealed tier in the
//! `LITMASK_SEAL_TIER` rustc-env var; this macro reads it at expansion
//! time and emits a §1.9.6 `compile_error!` when the form and the
//! sealed tier disagree — catching, at compile time, an `init!()`
//! against an externally-sealed binary (or vice-versa), or a build with
//! no litmask wiring at all. A `macro_rules!` form cannot read an env
//! var and branch to `compile_error!`, which is why `init!` is a
//! proc-macro.
//!
//! [`KeyProvider`]: litmask::KeyProvider

use proc_macro::TokenStream;
use quote::quote;

use crate::common::{FailTag, compile_error};

const MACRO_NAME: &str = "init";

/// rustc-env var carrying the build-sealed tier tag. Set by
/// `litmask_build::emit`; MUST match the build side byte-for-byte.
const SEAL_TIER_VAR: &str = "LITMASK_SEAL_TIER";

/// Tier tag whose seal the no-arg `init!()` form unlocks.
const EMBEDDED_TIER: &str = "embedded";

/// Tier tag whose seal the `init!(<provider>)` form unlocks.
const EXTERNAL_TIER: &str = "external";

/// The `init!` call form, selected by whether the macro received a
/// provider expression. Each form unlocks exactly one sealed tier.
#[derive(Clone, Copy)]
pub(crate) enum Form {
    /// `init!()` — keyless Embedded default.
    Embedded,
    /// `init!(<provider-expr>)` — External tier.
    External,
}

impl Form {
    /// The sealed tier tag this form is allowed to unlock.
    fn tier(self) -> &'static str {
        match self {
            Self::Embedded => EMBEDDED_TIER,
            Self::External => EXTERNAL_TIER,
        }
    }

    /// Human-readable call syntax for the form↔tier mismatch message.
    fn syntax(self) -> &'static str {
        match self {
            Self::Embedded => "init!()",
            Self::External => "init!(provider)",
        }
    }
}

/// Decide whether the build-sealed `tier` permits the given call `form`.
/// Returns `Ok(())` when they match, else the §1.9.6 error detail naming
/// the form↔tier mismatch. Pure so the cross-check is unit-testable
/// without mutating the process environment (the workspace
/// `forbid(unsafe_code)` rules out `env::set_var`).
pub(crate) fn check_tier(form: Form, tier: Option<&str>) -> Result<(), String> {
    let want = form.tier();
    match tier {
        Some(t) if t == want => Ok(()),
        Some(other) => Err(format!(
            "{} unlocks the `{want}` seal tier, but this build sealed `{other}`",
            form.syntax()
        )),
        None => Err(format!(
            "{SEAL_TIER_VAR} is unset; this build did not run litmask_build::emit() in build.rs"
        )),
    }
}

/// Expand `init!()` or `init!(<provider>)`. The presence of an argument
/// selects the form; the macro then reads `LITMASK_SEAL_TIER` and
/// cross-checks the form against the sealed tier before emitting the
/// matching init call.
pub(crate) fn expand(input: &TokenStream) -> TokenStream {
    let span = proc_macro::Span::call_site().into();
    let form = if input.is_empty() {
        Form::Embedded
    } else {
        Form::External
    };
    let tier = std::env::var(SEAL_TIER_VAR).ok();
    if let Err(detail) = check_tier(form, tier.as_deref()) {
        return compile_error(span, MACRO_NAME, FailTag::TierMismatch, &detail)
            .to_compile_error()
            .into();
    }
    match form {
        // Bind the embedded wrapper once: `EmbeddedProvider` reads its
        // cleartext nonce, then the runtime decrypts the same bytes.
        Form::Embedded => quote! {{
            let __litmask_wrapper = ::litmask::__wrapper_bytes!();
            ::litmask::__internal::__init_with_wrapper(
                ::litmask::EmbeddedProvider::new(__litmask_wrapper),
                __litmask_wrapper,
            )
        }}
        .into(),
        // The external provider supplies the unlock material; the
        // wrapper bytes are still the embedded ones (only the key
        // source differs between tiers).
        Form::External => {
            let provider: proc_macro2::TokenStream = input.clone().into();
            quote! {{
                ::litmask::__internal::__init_with_wrapper(
                    #provider,
                    ::litmask::__wrapper_bytes!(),
                )
            }}
            .into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_form_accepts_embedded_seal() {
        assert!(check_tier(Form::Embedded, Some(EMBEDDED_TIER)).is_ok());
    }

    #[test]
    fn external_form_accepts_external_seal() {
        assert!(check_tier(Form::External, Some(EXTERNAL_TIER)).is_ok());
    }

    #[test]
    fn embedded_form_rejects_external_seal_naming_both() {
        let detail = check_tier(Form::Embedded, Some(EXTERNAL_TIER)).unwrap_err();
        assert!(detail.contains(EMBEDDED_TIER));
        assert!(detail.contains(EXTERNAL_TIER));
    }

    #[test]
    fn external_form_rejects_embedded_seal_naming_both() {
        let detail = check_tier(Form::External, Some(EMBEDDED_TIER)).unwrap_err();
        assert!(detail.contains(EXTERNAL_TIER));
        assert!(detail.contains(EMBEDDED_TIER));
    }

    #[test]
    fn absent_tier_is_rejected_naming_the_env_var() {
        let detail = check_tier(Form::Embedded, None).unwrap_err();
        assert!(detail.contains(SEAL_TIER_VAR));
    }
}
