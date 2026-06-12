//! `init!(bind_to_machine + <provider>)` is the MachineExternal two-factor
//! form. The `+` promises an external provider expression; omitting it
//! (`init!(bind_to_machine +)`) is a grammar error caught at expansion with a
//! §1.9.6 `init! grammar` — before any seal-tier cross-check, so the
//! rejection is independent of which tier this build sealed.

use litmask::init;

fn main() {
    let _ = init!(bind_to_machine +);
}
