//! In-repo example binaries (under `litmask/examples/`) share this
//! build context, so running `litmask-build::emit()` from the host
//! crate's build script populates `OUT_DIR` with the key files the
//! `mask!` macro reads at expansion time.

fn main() {
    litmask_build::emit();
}
