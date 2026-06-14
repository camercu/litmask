//! `mask_option_env!("VAR")` reads the env var at proc-macro time
//! and returns `Some(masked String)` when set, `None` when unset.
//! Mirrors stdlib `option_env!`'s contract; the `Some` branch
//! flows through the standard `mask!` encryption pipeline.

mod common;

use litmask::mask_option_env;

#[test]
fn mask_option_env_set_returns_some() {
    // CARGO_PKG_NAME is always set during cargo build.
    let s: Option<String> = mask_option_env!("CARGO_PKG_NAME");
    assert_eq!(s, Some("litmask".to_string()));
}

#[test]
fn mask_option_env_unset_returns_none() {
    let s: Option<String> = mask_option_env!("LITMASK_TRYBUILD_DEFINITELY_UNSET_X9Z42");
    assert_eq!(s, None);
}
