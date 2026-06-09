//! The build-authoritative seal-tier tag — single source of truth for
//! the four keying tiers' wire spelling.
//!
//! `litmask-build` selects a tier from which key channels are present
//! and publishes its tag over `cargo:rustc-env=LITMASK_SEAL_TIER`. The
//! `init!` proc-macro reads that env var and cross-checks it against the
//! call form. Both sides MUST agree on the tag spelling byte-for-byte —
//! a mismatch silently breaks every build. Keeping the spelling here, in
//! the crate both already depend on, makes that agreement a compile-time
//! fact instead of a documented hope.

/// The keying tier a build sealed under, identified by its on-the-wire
/// tag. This is the vocabulary shared between the build seal
/// (`litmask-build`) and the `init!` form↔tier cross-check
/// (`litmask-macros`); each crate keeps its own richer enum (secret
/// material on the build side, provider token streams on the macro side)
/// and maps to/from this tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealTierTag {
    /// Keyless floor: `unlock_key` recomputed from the public wrapper
    /// nonce.
    Embedded,
    /// `unlock_key` derived from operator material (`LITMASK_UNLOCK_KEY`).
    External,
    /// `unlock_key` derived from the host machine id + wrapper nonce.
    Machine,
    /// Two-factor: machine factor composed with external factor (§2.3).
    MachineExternal,
}

impl SealTierTag {
    /// The wire spelling published over `LITMASK_SEAL_TIER`. `const` so
    /// the macro can use it in `const` context and the build side incurs
    /// no runtime cost.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Embedded => "embedded",
            Self::External => "external",
            Self::Machine => "machine",
            Self::MachineExternal => "machine_external",
        }
    }

    /// Parse a wire tag back into a tier, or `None` if it names no known
    /// tier. The inverse of [`as_str`](Self::as_str): every variant's
    /// `as_str` round-trips through `parse`.
    #[must_use]
    pub fn parse(tag: &str) -> Option<Self> {
        match tag {
            "embedded" => Some(Self::Embedded),
            "external" => Some(Self::External),
            "machine" => Some(Self::Machine),
            "machine_external" => Some(Self::MachineExternal),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant's wire spelling must parse back to itself — the
    /// build side writes `as_str`, the macro side reads `parse`, so a
    /// broken round-trip silently desyncs the cross-check.
    #[test]
    fn as_str_round_trips_through_parse() {
        for tag in [
            SealTierTag::Embedded,
            SealTierTag::External,
            SealTierTag::Machine,
            SealTierTag::MachineExternal,
        ] {
            assert_eq!(SealTierTag::parse(tag.as_str()), Some(tag));
        }
    }

    /// Pin the exact wire spellings: these strings are the build↔macro
    /// contract and an unintended rename is a breaking change for every
    /// previously sealed binary, so changing one must break this test.
    #[test]
    fn wire_spellings_are_stable() {
        assert_eq!(SealTierTag::Embedded.as_str(), "embedded");
        assert_eq!(SealTierTag::External.as_str(), "external");
        assert_eq!(SealTierTag::Machine.as_str(), "machine");
        assert_eq!(SealTierTag::MachineExternal.as_str(), "machine_external");
    }

    #[test]
    fn parse_rejects_unknown_tag() {
        assert_eq!(SealTierTag::parse("embedded "), None);
        assert_eq!(SealTierTag::parse(""), None);
        assert_eq!(SealTierTag::parse("hardware"), None);
    }
}
