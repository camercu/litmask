//! Seals this fixture's wrapper at build time. With `LITMASK_UNLOCK_KEY`
//! present, `emit()` selects the External tier — the tier the runtime
//! benchmarks measure (Task 1 of the bench suite).

fn main() {
    litmask_build::emit();
}
