//! Form↔tier mismatch fixture: calls the no-arg Embedded-form `init!()`
//! while the build is sealed at the `external` tier. The `init!`
//! proc-macro reads `LITMASK_SEAL_TIER=external` at expansion and emits a
//! §1.9.6 `init! tier-mismatch` compile error, so this crate is expected
//! NOT to compile.

fn main() {
    let _ = litmask::init!();
}
