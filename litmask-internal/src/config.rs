//! `litmask.config` field rendering, shared by the build helper and
//! `litmask-cli bind` so the TOML field layout cannot drift between
//! the two producers.

use alloc::string::String;

use crate::{KEY_LEN, NONCE_LEN, WRAPPER_LEN, base64url};

/// Render the data fields of a `litmask.config` TOML file.
///
/// Returns the `unlock_key`, `locator`, and `length` fields as a TOML
/// fragment (no header comments). Callers prepend their own header.
/// Shared by `litmask-build` (build-time) and `litmask-cli bind`
/// (post-build rebind) so the field layout cannot drift between the
/// two producers.
#[must_use]
pub fn render_config_fields(unlock_key: &[u8; KEY_LEN], locator: &[u8; NONCE_LEN]) -> String {
    alloc::format!(
        "unlock_key = \"{}\"\nlocator = \"{}\"\nlength = {WRAPPER_LEN}\n",
        base64url::encode(unlock_key),
        base64url::encode(locator),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_config_fields_contains_all_required_toml_keys() {
        let body = render_config_fields(&[0u8; KEY_LEN], &[0u8; NONCE_LEN]);
        assert!(body.contains("unlock_key = "));
        assert!(body.contains("locator = "));
        assert!(body.contains(&alloc::format!("length = {WRAPPER_LEN}")));
    }

    #[test]
    fn render_config_fields_round_trips_base64url_values() {
        let unlock_key = [0xAAu8; KEY_LEN];
        let locator = [0xBBu8; NONCE_LEN];
        let body = render_config_fields(&unlock_key, &locator);
        let expected_key_b64 = base64url::encode(&unlock_key);
        let expected_loc_b64 = base64url::encode(&locator);
        assert!(body.contains(&expected_key_b64));
        assert!(body.contains(&expected_loc_b64));
    }
}
