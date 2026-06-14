//! [`EnvVarProvider`] — reads `unlock_key` from a configurable
//! environment variable. The default reads `LITMASK_UNLOCK_KEY`.

use zeroize::Zeroizing;

use crate::error::KeyError;
use crate::key::UnlockKey;
use crate::provider::KeyProvider;

/// Reads `unlock_key` from a configurable environment variable.
///
/// # Examples
///
/// ```ignore
/// let provider = litmask::EnvVarProvider::new("MY_APP_KEY");
/// litmask::init!(provider)?;
/// ```
///
/// The snippet is `ignore`d rather than compiled: `init!(provider)` is
/// the External form and only compiles against an externally-sealed
/// build, whereas litmask's own doctests build at the Embedded tier.
#[derive(Debug)]
pub struct EnvVarProvider {
    name: &'static str,
}

impl EnvVarProvider {
    /// Construct a provider reading the named environment variable.
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self { name }
    }

    /// The environment variable name this provider was configured with.
    #[must_use]
    pub const fn var_name(&self) -> &'static str {
        self.name
    }
}

impl Default for EnvVarProvider {
    /// Reads from `LITMASK_UNLOCK_KEY`. The variable name itself is
    /// obfuscated against the per-build wrapper header bytes via the
    /// public [`crate::weak_mask!`] macro, so the literal does not
    /// appear in `.rodata` of user binaries.
    fn default() -> Self {
        Self::new(crate::weak_mask!("LITMASK_UNLOCK_KEY"))
    }
}

impl KeyProvider for EnvVarProvider {
    fn unlock_key(&self) -> Result<UnlockKey, KeyError> {
        parse_env_value(read_env_value(self.name))
    }
}

/// Read the named environment variable and wrap its value so the
/// underlying heap buffer wipes on drop. The variable holds raw key
/// material in plaintext; without the [`Zeroizing`] wrapper the buffer
/// would linger after the framework derives the unlock key.
fn read_env_value(name: &str) -> Option<Zeroizing<alloc::string::String>> {
    std::env::var(name).ok().map(Zeroizing::new)
}

/// Pure parser for an environment-variable value: maps the optional
/// owned string to the canonical [`KeyError`] surface. `None`
/// represents "env var unset" and produces [`KeyError::NotFound`];
/// `Some(value)` is normalized into an [`UnlockKey`] via
/// [`UnlockKey::derive`] over the raw bytes (any length, no encoding).
/// `UnlockKey::derive` removes an editor-appended trailing newline as
/// part of the derivation, so the env and file channels agree on one
/// secret without trimming here.
///
/// Takes ownership of a [`Zeroizing<String>`] so the plaintext material
/// is wiped when this function returns, regardless of which branch
/// executed.
///
/// Extracted as a free fn so tests cover the mapping without mutating
/// process-wide environment state (the workspace lint
/// `forbid(unsafe_code)` blocks the `unsafe { std::env::set_var(...) }`
/// pattern that env-mutation tests would otherwise require).
fn parse_env_value(value: Option<Zeroizing<alloc::string::String>>) -> Result<UnlockKey, KeyError> {
    match value {
        None => Err(KeyError::NotFound),
        Some(s) => Ok(UnlockKey::derive(s.as_bytes())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::UnlockKey;
    use alloc::string::{String, ToString};

    fn z(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_string())
    }

    #[test]
    fn debug_shows_var_name() {
        let p = EnvVarProvider::new("MY_KEY");
        let dbg = alloc::format!("{p:?}");
        assert!(dbg.contains("MY_KEY"), "Debug must show the var name");
    }

    #[test]
    fn default_reads_litmask_unlock_key() {
        let p = EnvVarProvider::default();
        assert_eq!(p.var_name(), "LITMASK_UNLOCK_KEY");
    }

    #[test]
    fn read_env_value_returns_zeroizing_string_so_buffer_wipes_on_drop() {
        // Type-asserts the env-read boundary returns a wiped-on-drop
        // wrapper rather than a plain String.
        let _: Option<Zeroizing<String>> = read_env_value("LITMASK_DEFINITELY_NOT_SET_XYZ_42");
    }

    #[test]
    fn parse_env_value_unset_yields_not_found() {
        assert!(matches!(parse_env_value(None), Err(KeyError::NotFound)));
    }

    #[test]
    fn parse_env_value_derives_key_from_material() {
        // Any value is accepted as raw material and normalized through
        // UnlockKey::derive — no base64url decode, no 32-byte length
        // check. The framework's KDF does the normalizing.
        let key = parse_env_value(Some(z("any operator secret"))).expect("derives");
        assert_eq!(key, UnlockKey::derive(b"any operator secret"));
    }

    #[test]
    fn parse_env_value_strips_one_trailing_newline() {
        // An env value carrying a trailing newline derives the same key
        // as the bare secret, so the env and file channels agree on the
        // material for one shared secret.
        let bare = parse_env_value(Some(z("secret"))).expect("derives");
        let newlined = parse_env_value(Some(z("secret\n"))).expect("derives");
        assert_eq!(bare, newlined);
    }
}
