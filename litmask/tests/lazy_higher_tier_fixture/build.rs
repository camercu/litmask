//! Runs the litmask build helper so the seal-tier env vars and wrapper
//! blob are emitted for this fixture's compilation. With
//! `LITMASK_UNLOCK_KEY` present, `emit()` seals the `external` tier — a
//! higher tier than the keyless Embedded floor.

fn main() {
    litmask_build::emit();
}
