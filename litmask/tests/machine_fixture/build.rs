//! Runs the litmask build helper so the Machine seal-tier env vars and
//! wrapper blobs are emitted for this fixture's compilation. With
//! `LITMASK_MACHINE_ID` present, `emit()` seals the `machine` tier.

fn main() {
    litmask_build::emit();
}
