//! Example binaries under `litmask/examples/` share this build
//! context, so running the build-script helper from the host crate's
//! build script populates `OUT_DIR` with the key files the `mask!`
//! proc-macro reads at expansion time.

fn main() {
    litmask_build::emit();
}
