//! `init!` proc-macro: install a governing provider, with a
//! build-authoritative form↔tier cross-check.
//!
//! Every form *governs* (ADR-0001) — there is no bare `init!()`; the
//! Embedded tier self-initializes lazily on the first `mask!()`. Each
//! form is valid only against the matching sealed tier:
//!
//! - `init!(<provider-expr>)` — `External`, taking a [`KeyProvider`].
//! - `init!(bind_to_machine)` — `Machine`.
//! - `init!(bind_to_machine + <provider-expr>)` — `MachineExternal`.
//!
//! `litmask_build::emit` records the sealed tier in the
//! `LITMASK_SEAL_TIER` rustc-env var; this macro reads it at expansion
//! time and emits a §1.9.6 `compile_error!` when the form and the
//! sealed tier disagree — catching, at compile time, an `init!(provider)`
//! against a machine-sealed binary (or vice-versa), or a build with no
//! litmask wiring at all. A `macro_rules!` form cannot read an env var
//! and branch to `compile_error!`, which is why `init!` is a proc-macro.
//!
//! [`KeyProvider`]: litmask::KeyProvider

use litmask_internal::SealTierTag;
use proc_macro::TokenStream;
use quote::quote;

use crate::common::{FailTag, compile_error};

const MACRO_NAME: &str = "init";

/// rustc-env var carrying the build-sealed tier tag. Set by
/// `litmask_build::emit`; the tier spelling is the shared
/// [`SealTierTag`] vocabulary, so build and macro cannot drift.
const SEAL_TIER_VAR: &str = "LITMASK_SEAL_TIER";

/// The bare keyword that selects the Machine form:
/// `init!(bind_to_machine)`.
const BIND_TO_MACHINE_KEYWORD: &str = "bind_to_machine";

/// The `init!` call form, selected by the macro argument. Each form
/// unlocks exactly one sealed tier.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Form {
    /// `init!(<provider-expr>)` — External tier.
    External,
    /// `init!(bind_to_machine)` — Machine tier (bare keyword, not a
    /// provider expression).
    Machine,
    /// `init!(bind_to_machine + <provider-expr>)` — `MachineExternal`
    /// two-factor tier. The `bind_to_machine` keyword selects the machine
    /// factor; the provider expression after `+` supplies the external
    /// factor.
    MachineExternal,
}

impl Form {
    /// The sealed tier this form is allowed to unlock.
    fn tier(self) -> SealTierTag {
        match self {
            Self::External => SealTierTag::External,
            Self::Machine => SealTierTag::Machine,
            Self::MachineExternal => SealTierTag::MachineExternal,
        }
    }

    /// Human-readable call syntax for the form↔tier mismatch message.
    fn syntax(self) -> &'static str {
        match self {
            Self::External => "init!(provider)",
            Self::Machine => "init!(bind_to_machine)",
            Self::MachineExternal => "init!(bind_to_machine + provider)",
        }
    }
}

/// Classify the `init!` argument into its call form, returning — for the
/// two provider-bearing forms — the external provider expression tokens.
///
/// Grammar:
/// - empty → error: bare `init!()` was removed (the Embedded tier
///   self-initializes lazily on the first `mask!()`).
/// - a bare `bind_to_machine` keyword (single ident) → [`Form::Machine`].
/// - a leading `bind_to_machine` keyword followed by a lone `+` → the
///   two-factor [`Form::MachineExternal`]; the tokens after `+` are the
///   external provider. An empty tail is a grammar error (the `+`
///   promises a provider that is absent).
/// - anything else → [`Form::External`], the whole input being the
///   provider expression.
///
/// A leading `bind_to_machine` followed by tokens other than a lone `+`
/// falls through to External: a consumer that genuinely names a provider
/// value `bind_to_machine` pays the deliberate cost of the keyword being
/// reserved only in the bare and `+`-prefixed positions. The `+` must be
/// [`Spacing::Alone`] — a joint `+` is the lead of a compound operator
/// like `+=`, which is not the two-factor operator.
///
/// [`Spacing::Alone`]: proc_macro2::Spacing::Alone
fn classify(
    input: &proc_macro2::TokenStream,
) -> Result<(Form, Option<proc_macro2::TokenStream>), String> {
    if input.is_empty() {
        return Err(
            "bare init!() was removed: the Embedded tier self-initializes on the first mask!() — \
             drop the call, or use init!(provider) / init!(bind_to_machine) to govern the graph"
                .to_string(),
        );
    }
    let mut tokens = input.clone().into_iter();
    let leading_bind_to_machine = matches!(
        tokens.next(),
        Some(proc_macro2::TokenTree::Ident(id)) if id == BIND_TO_MACHINE_KEYWORD
    );
    if leading_bind_to_machine {
        match tokens.next() {
            None => return Ok((Form::Machine, None)),
            Some(proc_macro2::TokenTree::Punct(p))
                if p.as_char() == '+' && p.spacing() == proc_macro2::Spacing::Alone =>
            {
                let rest: proc_macro2::TokenStream = tokens.collect();
                if rest.is_empty() {
                    return Err(format!(
                        "`{}` requires a provider expression after `+`",
                        Form::MachineExternal.syntax(),
                    ));
                }
                return Ok((Form::MachineExternal, Some(rest)));
            }
            _ => {}
        }
    }
    Ok((Form::External, Some(input.clone())))
}

/// Decide whether the build-sealed `tier` permits the given call `form`.
/// Returns `Ok(())` when they match, else the §1.9.6 error detail naming
/// the form↔tier mismatch. Pure so the cross-check is unit-testable
/// without mutating the process environment (the workspace
/// `forbid(unsafe_code)` rules out `env::set_var`).
pub(crate) fn check_tier(form: Form, tier: Option<&str>) -> Result<(), String> {
    let want = form.tier();
    match tier {
        Some(t) if SealTierTag::parse(t) == Some(want) => Ok(()),
        Some(other) => Err(format!(
            "{} unlocks the `{}` seal tier, but this build sealed `{other}`",
            form.syntax(),
            want.as_str(),
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
    let (form, provider) = match classify(&input.clone().into()) {
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
        // The external provider becomes the process-global governing
        // provider (ADR-0001): it unlocks the host's own wrapper eagerly
        // and every transitive crate's wrapper lazily. The wrapper bytes
        // are still the embedded ones (only the key source differs).
        Form::External => {
            let provider = provider.expect("External form carries a provider expression");
            quote! {{
                ::litmask::__internal::__govern_external(
                    #provider,
                    ::litmask::__wrapper_bytes!(),
                )
            }}
            .into()
        }
        // The machine provider is `pub(crate)` and cannot be named in the
        // consumer crate, so the seam fn constructs it from the wrapper
        // nonce in-crate. Routed through `__govern_machine_call!` rather
        // than the seam fn directly: the macro carries a feature-off
        // variant that emits a directed `compile_error!`, since a
        // `machine`-sealed build can reach this arm with the `machine-id`
        // feature disabled.
        Form::Machine => quote! {{
            let __litmask_wrapper = ::litmask::__wrapper_bytes!();
            ::litmask::__govern_machine_call!(__litmask_wrapper)
        }}
        .into(),
        // Two-factor: the machine factor is reconstructed in-crate from the
        // wrapper nonce (its provider is `pub(crate)`), and composed with
        // the external provider's key. Routed through
        // `__govern_machine_external_call!` for the same reason as the
        // Machine arm — the macro carries a feature-off variant that emits
        // a directed `compile_error!` when `machine-id` is disabled.
        Form::MachineExternal => {
            let provider =
                provider.expect("MachineExternal form carries an external provider expression");
            quote! {{
                let __litmask_wrapper = ::litmask::__wrapper_bytes!();
                ::litmask::__govern_machine_external_call!(__litmask_wrapper, #provider)
            }}
            .into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMBEDDED_TIER: &str = SealTierTag::Embedded.as_str();
    const EXTERNAL_TIER: &str = SealTierTag::External.as_str();
    const MACHINE_TIER: &str = SealTierTag::Machine.as_str();
    const MACHINE_EXTERNAL_TIER: &str = SealTierTag::MachineExternal.as_str();

    #[test]
    fn external_form_accepts_external_seal() {
        assert!(check_tier(Form::External, Some(EXTERNAL_TIER)).is_ok());
    }

    /// An env value that names no known tier is treated as a mismatch,
    /// not silently accepted — a corrupted or future-versioned tag must
    /// fail the cross-check just like the wrong tier does.
    #[test]
    fn unknown_seal_tag_is_rejected() {
        let detail = check_tier(Form::External, Some("hardware")).unwrap_err();
        assert!(detail.contains("hardware"));
        assert!(detail.contains(EXTERNAL_TIER));
    }

    /// The Embedded tier has no `init!` form (it self-initializes
    /// lazily), so an External-form `init!(provider)` against an
    /// Embedded-sealed build is a mismatch naming both.
    #[test]
    fn external_form_rejects_embedded_seal_naming_both() {
        let detail = check_tier(Form::External, Some(EMBEDDED_TIER)).unwrap_err();
        assert!(detail.contains(EXTERNAL_TIER));
        assert!(detail.contains(EMBEDDED_TIER));
    }

    #[test]
    fn absent_tier_is_rejected_naming_the_env_var() {
        let detail = check_tier(Form::External, None).unwrap_err();
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

    fn classify_str(src: &str) -> Result<(Form, Option<proc_macro2::TokenStream>), String> {
        classify(&src.parse().expect("test source tokenizes"))
    }

    #[test]
    fn classify_empty_is_rejected_as_removed() {
        let detail = classify_str("").unwrap_err();
        assert!(detail.contains("removed"));
        assert!(detail.contains("mask!()"));
    }

    #[test]
    fn classify_bare_bind_to_machine_is_machine() {
        let (form, provider) = classify_str("bind_to_machine").unwrap();
        assert_eq!(form, Form::Machine);
        assert!(provider.is_none());
    }

    #[test]
    fn classify_bind_to_machine_plus_provider_is_two_factor() {
        let (form, provider) = classify_str("bind_to_machine + EnvVarProvider::default()").unwrap();
        assert_eq!(form, Form::MachineExternal);
        assert_eq!(
            provider.unwrap().to_string(),
            "EnvVarProvider :: default ()"
        );
    }

    #[test]
    fn classify_bind_to_machine_plus_nothing_is_grammar_error() {
        let detail = classify_str("bind_to_machine +").unwrap_err();
        assert!(detail.contains("provider expression after `+`"));
    }

    #[test]
    fn classify_provider_expr_is_external() {
        let (form, provider) = classify_str("EnvVarProvider::default()").unwrap();
        assert_eq!(form, Form::External);
        assert!(provider.is_some());
    }

    #[test]
    fn classify_bind_to_machine_method_call_is_external() {
        let (form, _) = classify_str("bind_to_machine.into_provider()").unwrap();
        assert_eq!(form, Form::External);
    }

    /// A compound `+=` is the lead of an assignment operator, not the
    /// two-factor `+`. It must NOT be misread as `MachineExternal` with a
    /// malformed `= provider` tail; it falls through to External so the
    /// whole input is reported as one (malformed) provider expression.
    #[test]
    fn classify_bind_to_machine_compound_plus_eq_is_not_two_factor() {
        let (form, _) = classify_str("bind_to_machine += provider").unwrap();
        assert_eq!(form, Form::External);
    }
}
