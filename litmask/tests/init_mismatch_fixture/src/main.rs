//! Form↔tier mismatch fixture: calls the Machine-form
//! `init!(bind_to_machine)` while the build is sealed at the `external`
//! tier. The `init!` proc-macro reads `LITMASK_SEAL_TIER=external` at
//! expansion and emits a §1.9.6 `init! tier-mismatch` compile error (the
//! form↔tier check fails before any expansion body), so this crate is
//! expected NOT to compile.

fn main() {
    let _ = litmask::init!(bind_to_machine);
}
