//! Runs the litmask build helper so the seal-tier env var and wrapper
//! blob are emitted for this fixture. The test builds it with
//! `LITMASK_UNLOCK_KEY` set, so `emit()` seals the `external` tier — which
//! disagrees with the Embedded-form `init!()` in `main.rs`.

fn main() {
    litmask_build::emit();
}
