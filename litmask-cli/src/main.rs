//! `litmask` CLI — companion tool for `bind` and `inspect`.
//!
//! Each subcommand lives in a module split into a pure planner
//! ([`inspect::plan`] / [`bind::plan_bind`]) and a thin imperative
//! shell (`run`). `main` is responsible only for argument parsing
//! (via `clap`) and mapping the shell's `Result<Outcome, ShellError>`
//! to an `ExitCode`.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod bind;
mod config;
mod inspect;

/// `EX_USAGE` (64): argument-parsing or operator-input failure.
const EX_USAGE: u8 = 64;
/// `EX_UNAVAILABLE` (69): upstream service (machine-uid) refused.
const EX_UNAVAILABLE: u8 = 69;
/// `EX_SOFTWARE` (70): unexpected internal failure (atomic commit
/// I/O, etc.).
const EX_SOFTWARE: u8 = 70;

/// `litmask` companion tool for inspecting and rebinding
/// litmask-built binaries.
#[derive(Parser, Debug)]
#[command(name = "litmask", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan a binary for the locator recorded in `litmask.config`.
    ///
    /// Exit codes:
    /// - 0 on a single match (prints `verified`)
    /// - 65 on multiple matches (prints `ambiguous:<count>`)
    /// - 66 on no match (prints `not_found`)
    /// - 64 on argument-parse / config-malformed failures
    Inspect {
        /// Path to the binary to scan.
        binary: PathBuf,
        /// Path to `litmask.config`.
        #[arg(long)]
        config: PathBuf,
    },
    /// Rebind a binary's embedded `mask_key` wrapper to a new
    /// hardware-derived `unlock_key`, atomically updating both the
    /// binary and `litmask.config`.
    ///
    /// Works with any provider: binaries using `HardwareIdProvider`
    /// decrypt automatically after bind; binaries using
    /// `EnvVarProvider` decrypt when given the config's updated
    /// `unlock_key` via the environment variable.
    ///
    /// Exit codes:
    /// - 0 on success
    /// - 65 on locator-ambiguous, AEAD decryption failure, or
    ///   unsupported format/cipher
    /// - 66 on no locator match (prints `not_found`)
    /// - 69 on hardware-id lookup failure
    Bind {
        /// Path to the binary to rebind.
        binary: PathBuf,
        /// Path to `litmask.config`.
        #[arg(long)]
        config: PathBuf,
        /// Optional base64url-encoded salt. Mixes into the
        /// hardware-id BLAKE3 derivation so two products on the
        /// same host with different salts get distinct keys.
        #[arg(long)]
        salt: Option<String>,
    },
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
                _ => ExitCode::from(EX_USAGE),
            };
        }
    };

    match cli.command {
        Command::Inspect { binary, config } => dispatch_inspect(&binary, &config),
        Command::Bind {
            binary,
            config,
            salt,
        } => dispatch_bind(&binary, &config, salt.as_deref()),
    }
}

fn dispatch_inspect(binary: &std::path::Path, config: &std::path::Path) -> ExitCode {
    match inspect::run(binary, config) {
        Ok(outcome) => ExitCode::from(outcome.exit_code()),
        Err(e) => {
            eprintln!("litmask: {}", e.message());
            ExitCode::from(EX_USAGE)
        }
    }
}

fn dispatch_bind(
    binary: &std::path::Path,
    config: &std::path::Path,
    salt: Option<&str>,
) -> ExitCode {
    match bind::run(binary, config, salt) {
        Ok(outcome) => ExitCode::from(outcome.exit_code()),
        Err(e @ (bind::ShellError::ConfigUnreadable | bind::ShellError::BinaryUnreadable)) => {
            eprintln!("litmask: {}", e.message());
            ExitCode::from(EX_USAGE)
        }
        Err(bind::ShellError::HardwareIdUnavailable) => {
            // §2.9.1.3: hardware-id failure surfaces on stdout
            // with the documented tag and exits EX_UNAVAILABLE.
            println!("hardware_id_unavailable");
            ExitCode::from(EX_UNAVAILABLE)
        }
        Err(e @ bind::ShellError::CommitFailed(_)) => {
            eprintln!("litmask: {}", e.message());
            ExitCode::from(EX_SOFTWARE)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_argv(argv: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("litmask").chain(argv.iter().copied()))
    }

    #[test]
    fn parses_inspect_with_binary_and_config() {
        let cli = parse_argv(&["inspect", "/path/to/bin", "--config", "/path/to/cfg"]).unwrap();
        match cli.command {
            Command::Inspect { binary, config } => {
                assert_eq!(binary, PathBuf::from("/path/to/bin"));
                assert_eq!(config, PathBuf::from("/path/to/cfg"));
            }
            Command::Bind { .. } => panic!("expected Inspect"),
        }
    }

    #[test]
    fn parses_bind_without_salt() {
        let cli = parse_argv(&["bind", "/bin", "--config", "/cfg"]).unwrap();
        match cli.command {
            Command::Bind { salt, .. } => assert_eq!(salt, None),
            Command::Inspect { .. } => panic!("expected Bind"),
        }
    }

    #[test]
    fn parses_bind_with_salt() {
        let cli = parse_argv(&["bind", "/bin", "--config", "/cfg", "--salt", "AAAA"]).unwrap();
        match cli.command {
            Command::Bind { salt, .. } => assert_eq!(salt.as_deref(), Some("AAAA")),
            Command::Inspect { .. } => panic!("expected Bind"),
        }
    }

    #[test]
    fn parses_gnu_typical_flag_before_positional() {
        // Pin GNU-style flag tolerance: `--config <val>` may appear
        // before or after the positional `binary`. Required because
        // every other Rust CLI tool accepts both orderings, and
        // operators copy-paste argv across them.
        let cli = parse_argv(&["inspect", "--config", "/cfg", "/bin"]).unwrap();
        match cli.command {
            Command::Inspect { binary, config } => {
                assert_eq!(binary, PathBuf::from("/bin"));
                assert_eq!(config, PathBuf::from("/cfg"));
            }
            Command::Bind { .. } => panic!("expected Inspect"),
        }
    }

    #[test]
    fn parses_equals_form_for_flag_value() {
        // `--config=value` (single-token form) is the canonical
        // GNU-style flag syntax; tooling that emits this form must
        // round-trip without a separator-token workaround.
        let cli = parse_argv(&["inspect", "/bin", "--config=/cfg"]).unwrap();
        match cli.command {
            Command::Inspect { config, .. } => assert_eq!(config, PathBuf::from("/cfg")),
            Command::Bind { .. } => panic!("expected Inspect"),
        }
    }

    #[test]
    fn rejects_missing_subcommand() {
        assert!(parse_argv(&[]).is_err());
    }

    #[test]
    fn rejects_unknown_subcommand() {
        assert!(parse_argv(&["nope", "/bin", "--config", "/cfg"]).is_err());
    }

    #[test]
    fn rejects_missing_config_flag() {
        // Positional `binary` alone is not enough — `--config` is
        // a required argument; clap surfaces the missing-required
        // diagnostic.
        assert!(parse_argv(&["inspect", "/bin"]).is_err());
    }

    #[test]
    fn rejects_bind_salt_without_value() {
        assert!(parse_argv(&["bind", "/bin", "--config", "/cfg", "--salt"]).is_err());
    }

    #[test]
    fn rejects_unknown_flag() {
        assert!(parse_argv(&["bind", "/bin", "--config", "/cfg", "--foo", "bar"]).is_err());
    }

    #[test]
    fn rejects_inspect_trailing_positional() {
        // Reject trailing junk so a typo doesn't silently slip
        // through. clap's positional check catches it.
        assert!(parse_argv(&["inspect", "/bin", "--config", "/cfg", "extra"]).is_err());
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
