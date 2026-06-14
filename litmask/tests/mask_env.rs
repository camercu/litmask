//! `mask_env!("VAR")` reads the build-time env var at proc-macro
//! time, masks the value, and returns it as a `String` at runtime.

mod common;

use litmask::mask_env;

#[test]
fn mask_env_cargo_pkg_name_round_trips() {
    // `CARGO_PKG_NAME` is always set by cargo at build time, so the
    // proc-macro can resolve it and emit a masked blob.
    let s: String = mask_env!("CARGO_PKG_NAME");
    assert_eq!(s, "litmask");
}

#[test]
fn mask_env_accepts_optional_custom_error_message() {
    // Stdlib `env!("FOO", "custom message")` is legal; the second
    // arg is only consulted if the env var is unset (it becomes
    // the compile-error text). When the var IS set, the second
    // arg is ignored at runtime. mask_env! mirrors this grammar.
    let s: String = mask_env!("CARGO_PKG_NAME", "should never fire");
    assert_eq!(s, "litmask");
}
