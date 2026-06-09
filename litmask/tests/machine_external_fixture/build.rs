//! Runs the litmask build helper so the MachineExternal two-factor
//! seal-tier env vars and wrapper blobs are emitted for this fixture's
//! compilation. With both `LITMASK_MACHINE_ID` and `LITMASK_UNLOCK_KEY`
//! present, `emit()` seals the `machine_external` tier.

fn main() {
    litmask_build::emit();
}
