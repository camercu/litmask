//! `init!()` is the no-argument form in this release (the arg-taking
//! tier forms land later). Passing any argument is a §1.9.6
//! `init! args-not-allowed` compile error. This path fires before the
//! `LITMASK_SEAL_TIER` cross-check, so it is independent of the build's
//! sealed tier — unlike the tier-mismatch branch, which can't be
//! exercised here because the litmask build's `LITMASK_SEAL_TIER`
//! rustc-env leaks into the trybuild subprocess (see the decision-fn
//! unit tests in `litmask-macros/src/init.rs`).

use litmask::init;

fn main() {
    let _ = init!(some_provider);
}
