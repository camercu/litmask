//! Runs the litmask build helper so the seal-tier env vars and wrapper
//! blob are emitted for this fixture's compilation. The e2e harness
//! builds with no key-channel env vars set, so `emit()` seals the
//! keyless Embedded floor — the only tier where the lazy first-`mask!()`
//! path succeeds and a late `init!()` could otherwise no-op silently.

fn main() {
    litmask_build::emit();
}
