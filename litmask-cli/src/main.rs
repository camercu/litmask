//! `litmask` CLI — companion tool for build-sealed binaries.
//!
//! `main` is responsible only for argument parsing (via `clap`) and
//! mapping each subcommand's result to a sysexits-aligned `ExitCode`.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod exit;

/// Readable diagnostic for a failed machine-id lookup. Kept as a named
/// constant so the message text is pinned by a unit test.
const MACHINE_ID_UNAVAILABLE_MSG: &str = "could not read the machine ID (machine-uid failed)";

/// `litmask` companion tool.
#[derive(Parser, Debug)]
#[command(name = "litmask", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print this host's machine ID — the exact bytes a machine-tier
    /// build feeds into its key derivation.
    ///
    /// The enrollment primitive for machine-tier deployments: a target
    /// host runs `show-machine-id` and reports the value, letting the
    /// vendor seal a build against it off-box (see `docs/DEPLOYMENT.md`).
    ///
    /// Exit codes:
    /// - 0 on success (prints the machine ID to stdout)
    /// - 69 on machine-id lookup failure (diagnostic to stderr)
    ShowMachineId,
}

fn main() -> ExitCode {
    // `try_parse` so we can surface clap's "usage / argument" exits
    // through our sysexits-aligned `EX_USAGE` code instead of
    // clap's default `2`. Help / version requests still print +
    // exit cleanly; clap distinguishes them via `ErrorKind`.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            use clap::error::ErrorKind;
            let kind = err.kind();
            // `print` writes to stdout for help/version, stderr
            // for genuine errors — matches `--help` UX.
            let _ = err.print();
            return match kind {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => ExitCode::SUCCESS,
                _ => ExitCode::from(exit::USAGE),
            };
        }
    };

    match cli.command {
        Command::ShowMachineId => dispatch_show_machine_id(),
    }
}

/// Where a `show-machine-id` result should be written and with which
/// exit code. Pure so both branches are unit-testable without a
/// host machine-id lookup: the imperative shell only routes the
/// fields to stdout/stderr.
struct MachineIdReport {
    stdout: Option<String>,
    stderr: Option<String>,
    code: u8,
}

/// Map a machine-id lookup to its presentation. The ID is a
/// non-secret host identifier — the pre-KDF input a machine-tier seal
/// feeds into its key derivation — so it goes to stdout for capture. A
/// lookup failure is an error and goes to stderr (exit 69), keeping
/// stdout clean for callers piping the ID.
fn report_machine_id<E>(lookup: Result<String, E>) -> MachineIdReport {
    match lookup {
        Ok(id) => MachineIdReport {
            stdout: Some(id),
            stderr: None,
            code: exit::OK,
        },
        Err(_) => MachineIdReport {
            stdout: None,
            stderr: Some(MACHINE_ID_UNAVAILABLE_MSG.to_string()),
            code: exit::UNAVAILABLE,
        },
    }
}

fn dispatch_show_machine_id() -> ExitCode {
    let report = report_machine_id(machine_uid::get());
    if let Some(id) = report.stdout {
        println!("{id}");
    }
    if let Some(msg) = report.stderr {
        eprintln!("litmask: {msg}");
    }
    ExitCode::from(report.code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_argv(argv: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("litmask").chain(argv.iter().copied()))
    }

    #[test]
    fn report_machine_id_success_goes_to_stdout_with_ok_code() {
        let r = report_machine_id(Ok::<_, std::io::Error>("ABC-123".to_string()));
        assert_eq!(r.stdout.as_deref(), Some("ABC-123"));
        assert_eq!(r.stderr, None);
        assert_eq!(r.code, exit::OK);
    }

    #[test]
    fn report_machine_id_failure_goes_to_stderr_with_unavailable_code() {
        // A lookup failure is an error: the diagnostic belongs on
        // stderr, leaving stdout empty so a caller capturing the ID
        // never mistakes the error text for a machine ID.
        let r = report_machine_id(Err(std::io::Error::other("boom")));
        assert_eq!(r.stdout, None);
        assert_eq!(r.stderr.as_deref(), Some(MACHINE_ID_UNAVAILABLE_MSG));
        assert_eq!(r.code, exit::UNAVAILABLE);
    }

    #[test]
    fn parses_show_machine_id() {
        let cli = parse_argv(&["show-machine-id"]).unwrap();
        assert!(matches!(cli.command, Command::ShowMachineId));
    }

    #[test]
    fn rejects_show_machine_id_trailing_positional() {
        // `show-machine-id` takes no arguments; a trailing token is a
        // typo, not silent input.
        assert!(parse_argv(&["show-machine-id", "extra"]).is_err());
    }

    #[test]
    fn rejects_missing_subcommand() {
        assert!(parse_argv(&[]).is_err());
    }

    #[test]
    fn rejects_unknown_subcommand() {
        assert!(parse_argv(&["nope"]).is_err());
    }

    #[test]
    fn help_request_kind_is_display_help() {
        // Pin clap's contract: `--help` is reported as
        // `ErrorKind::DisplayHelp`. main() maps this to
        // ExitCode::SUCCESS so `litmask --help` exits 0, not 64.
        let err = parse_argv(&["--help"]).unwrap_err();
        assert!(matches!(err.kind(), clap::error::ErrorKind::DisplayHelp));
    }

    #[test]
    fn version_request_kind_is_display_version() {
        let err = parse_argv(&["--version"]).unwrap_err();
        assert!(matches!(err.kind(), clap::error::ErrorKind::DisplayVersion));
    }
}
