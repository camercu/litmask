//! Runs the litmask build helper so the External seal-tier env vars and
//! wrapper blobs are emitted for this fixture's compilation. With
//! `LITMASK_UNLOCK_KEY` present, `emit()` seals the `external` tier.

fn main() {
    litmask_build::emit();
}
