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

/// Tier tag whose seal the `init!(machine_id)` keyword form unlocks.
const MACHINE_TIER: &str = "machine";

/// Tier tag whose seal the `init!(machine_id + <provider>)` two-factor
/// form unlocks.
const MACHINE_EXTERNAL_TIER: &str = "machine_external";

/// The bare keyword that selects the Machine form: `init!(machine_id)`.
const MACHINE_ID_KEYWORD: &str = "machine_id";

/// The `init!` call form, selected by the macro argument. Each form
/// unlocks exactly one sealed tier.
#[derive(Clone, Copy)]
pub(crate) enum Form {
    /// `init!()` — keyless Embedded default.
    Embedded,
    /// `init!(<provider-expr>)` — External tier.
    External,
    /// `init!(machine_id)` — Machine tier (bare keyword, not a provider
    /// expression).
    Machine,
    /// `init!(machine_id + <provider-expr>)` — `MachineExternal` two-factor
    /// tier. The `machine_id` keyword selects the machine factor; the
    /// provider expression after `+` supplies the external factor.
    MachineExternal,
}

impl Form {
    /// The sealed tier tag this form is allowed to unlock.
    fn tier(self) -> &'static str {
        match self {
            Self::Embedded => EMBEDDED_TIER,
            Self::External => EXTERNAL_TIER,
            Self::Machine => MACHINE_TIER,
            Self::MachineExternal => MACHINE_EXTERNAL_TIER,
        }
    }

    /// Human-readable call syntax for the form↔tier mismatch message.
    fn syntax(self) -> &'static str {
        match self {
            Self::Embedded => "init!()",
            Self::External => "init!(provider)",
            Self::Machine => "init!(machine_id)",
            Self::MachineExternal => "init!(machine_id + provider)",
        }
    }
}

/// Classify the `init!` argument into its call form, returning — for the
/// two provider-bearing forms — the external provider expression tokens.
///
/// Grammar:
/// - empty → [`Form::Embedded`].
/// - a bare `machine_id` keyword (single ident) → [`Form::Machine`].
/// - a leading `machine_id` keyword followed by `+` → the two-factor
///   [`Form::MachineExternal`]; the tokens after `+` are the external
///   provider. An empty tail is a grammar error (the `+` promises a
///   provider that is absent).
/// - anything else → [`Form::External`], the whole input being the
///   provider expression.
///
/// A leading `machine_id` followed by tokens other than `+` falls through
/// to External: a consumer that genuinely names a provider value
/// `machine_id` pays the deliberate cost of the keyword being reserved
/// only in the bare and `+`-prefixed positions.
fn classify(input: &TokenStream) -> Result<(Form, Option<proc_macro2::TokenStream>), String> {
    if input.is_empty() {
        return Ok((Form::Embedded, None));
    }
    let mut tokens = input.clone().into_iter();
    let leading_machine_id = matches!(
        tokens.next(),
        Some(proc_macro::TokenTree::Ident(id)) if id.to_string() == MACHINE_ID_KEYWORD
    );
    if leading_machine_id {
        match tokens.next() {
            None => return Ok((Form::Machine, None)),
            Some(proc_macro::TokenTree::Punct(p)) if p.as_char() == '+' => {
                let rest: TokenStream = tokens.collect();
                if rest.is_empty() {
                    return Err(format!(
                        "`{}` requires a provider expression after `+`",
                        Form::MachineExternal.syntax(),
                    ));
                }
                return Ok((Form::MachineExternal, Some(rest.into())));
            }
            _ => {}
        }
    }
    Ok((Form::External, Some(input.clone().into())))
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
    let (form, provider) = match classify(input) {
        Ok(parsed) => parsed,
        Err(detail) => {
            return compile_error(span, MACRO_NAME, FailTag::Grammar, &detail)
                .to_compile_error()
                .into();
        }
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
            let provider = provider.expect("External form carries a provider expression");
            quote! {{
                ::litmask::__internal::__init_with_wrapper(
                    #provider,
                    ::litmask::__wrapper_bytes!(),
                )
            }}
            .into()
        }
        // The machine provider is `pub(crate)` and cannot be named in the
        // consumer crate, so the seam fn constructs it from the wrapper
        // nonce in-crate. Routed through `__init_machine_id_call!` rather
        // than the seam fn directly: the macro carries a feature-off
        // variant that emits a directed `compile_error!`, since a
        // `machine`-sealed build can reach this arm with the `machine-id`
        // feature disabled.
        Form::Machine => quote! {{
            let __litmask_wrapper = ::litmask::__wrapper_bytes!();
            ::litmask::__init_machine_id_call!(__litmask_wrapper)
        }}
        .into(),
        // Two-factor: the machine factor is reconstructed in-crate from the
        // wrapper nonce (its provider is `pub(crate)`), and composed with
        // the external provider's key. Routed through
        // `__init_machine_id_external_call!` for the same reason as the
        // Machine arm — the macro carries a feature-off variant that emits
        // a directed `compile_error!` when `machine-id` is disabled.
        Form::MachineExternal => {
            let provider =
                provider.expect("MachineExternal form carries an external provider expression");
            quote! {{
                let __litmask_wrapper = ::litmask::__wrapper_bytes!();
                ::litmask::__init_machine_id_external_call!(__litmask_wrapper, #provider)
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

    #[test]
    fn machine_form_accepts_machine_seal() {
        assert!(check_tier(Form::Machine, Some(MACHINE_TIER)).is_ok());
    }

    #[test]
    fn machine_form_rejects_embedded_seal_naming_both() {
        let detail = check_tier(Form::Machine, Some(EMBEDDED_TIER)).unwrap_err();
        assert!(detail.contains(MACHINE_TIER));
        assert!(detail.contains(EMBEDDED_TIER));
    }

    #[test]
    fn machine_external_form_accepts_machine_external_seal() {
        assert!(check_tier(Form::MachineExternal, Some(MACHINE_EXTERNAL_TIER)).is_ok());
    }

    #[test]
    fn machine_external_form_rejects_machine_seal_naming_both() {
        let detail = check_tier(Form::MachineExternal, Some(MACHINE_TIER)).unwrap_err();
        assert!(detail.contains(MACHINE_EXTERNAL_TIER));
        assert!(detail.contains(MACHINE_TIER));
    }

    #[test]
    fn machine_external_form_rejects_external_seal_naming_both() {
        let detail = check_tier(Form::MachineExternal, Some(EXTERNAL_TIER)).unwrap_err();
        assert!(detail.contains(MACHINE_EXTERNAL_TIER));
        assert!(detail.contains(EXTERNAL_TIER));
    }
}
