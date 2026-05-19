//! `mask_env!("VAR")` reads the build-time env var at proc-macro
//! time, masks the value, and returns it as a `String` at runtime.

mod common;

use litmask::mask_env;

#[test]
fn mask_env_cargo_pkg_name_round_trips() {
    common::init_once();
    // `CARGO_PKG_NAME` is always set by cargo at build time, so the
    // proc-macro can resolve it and emit a masked blob.
    let s: String = mask_env!("CARGO_PKG_NAME");
    assert_eq!(s, "litmask");
}
