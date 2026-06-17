//! Stack-buffer cap policy for `mask_stack!`.
//!
//! Owns the single guardrail that keeps a `mask_stack!` literal from
//! sealing an `[u8; N]` large enough to overflow the stack: the env-var
//! sourcing, the default ceiling, and the over-cap decision + diagnostic.
//! Kept apart from the token-emission code in [`super::codegen`] so the
//! cap concern has one home and the pure pieces stay unit-testable.

/// Environment variable overriding the default stack-buffer byte cap.
const STACK_LIMIT_VAR: &str = "LITMASK_STACK_LIMIT";

/// Default cap on a single `mask_stack!` inline `[u8; N]` (bytes).
/// Secrets, tokens, and keys are well under this; a larger literal is
/// almost certainly a `mask!` candidate, and an unbounded one risks a
/// stack overflow. Override with [`STACK_LIMIT_VAR`].
const DEFAULT_STACK_LIMIT: usize = 4096;

/// Resolve the stack-buffer cap from [`STACK_LIMIT_VAR`], defaulting to
/// [`DEFAULT_STACK_LIMIT`] when unset. `Err` carries an actionable message
/// for a present-but-unparsable value (surfaced as a `compile_error!`).
///
/// Read via plain `std::env::var`; rebuild-on-change is declared by
/// `litmask_build::emit()` (`cargo:rerun-if-env-changed`), the same
/// mechanism `LITMASK_RNG_SEED` / `LITMASK_MACHINE_ID` rely on.
pub(crate) fn stack_limit() -> Result<usize, String> {
    match std::env::var(STACK_LIMIT_VAR) {
        Ok(raw) => parse_stack_limit(&raw),
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_STACK_LIMIT),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{STACK_LIMIT_VAR} must be UTF-8")),
    }
}

/// Parse a [`STACK_LIMIT_VAR`] value (the present-and-UTF-8 case). Pure,
/// so the accept/reject contract is unit-testable without mutating the
/// process environment.
fn parse_stack_limit(raw: &str) -> Result<usize, String> {
    raw.trim().parse::<usize>().map_err(|_| {
        format!("{STACK_LIMIT_VAR} must be a byte count (non-negative integer), got {raw:?}")
    })
}

/// Decision for the stack-size guardrail: `Some(message)` when an
/// `N`-byte buffer exceeds `limit`. Split out so it is unit-testable
/// without driving a full macro expansion.
pub(crate) fn over_stack_limit(n: usize, limit: usize) -> Option<String> {
    (n > limit).then(|| {
        format!(
            "mask_stack! literal needs a {n}-byte stack buffer, over the {limit}-byte \
             {STACK_LIMIT_VAR} cap; use mask! for large secrets or raise {STACK_LIMIT_VAR}"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn over_stack_limit_triggers_only_above_cap() {
        assert!(over_stack_limit(4096, 4096).is_none(), "at cap is allowed");
        assert!(over_stack_limit(0, 4096).is_none());
        let msg = over_stack_limit(4097, 4096).unwrap();
        assert!(msg.contains("4097"), "{msg}");
        assert!(msg.contains("4096"), "{msg}");
        assert!(msg.contains(STACK_LIMIT_VAR), "{msg}");
    }

    #[test]
    fn parse_stack_limit_accepts_int_rejects_garbage() {
        assert_eq!(parse_stack_limit("8192"), Ok(8192));
        assert_eq!(parse_stack_limit("  256 "), Ok(256));
        assert!(parse_stack_limit("nan").is_err());
        assert!(parse_stack_limit("-1").is_err());
        assert!(parse_stack_limit("3.5").is_err());
    }
}
