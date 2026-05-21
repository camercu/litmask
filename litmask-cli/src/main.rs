//! `litmask-cli` — companion tool for `bind` and `inspect`.
//!
//! Each subcommand lives in a module split into a pure planner
//! ([`inspect::plan`] / [`bind::plan_bind`] + [`bind::plan_posix_commit`])
//! and a thin imperative shell (`run`). `main` is responsible only
//! for argument parsing and mapping the shell's `Result<Outcome,
//! ShellError>` to an `ExitCode`.

use std::path::PathBuf;
use std::process::ExitCode;

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

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match parse_args(&args) {
        Ok(Command::Inspect { binary, config }) => dispatch_inspect(&binary, &config),
        Ok(Command::Bind {
            binary,
            config,
            salt,
        }) => dispatch_bind(&binary, &config, salt.as_deref()),
        Err(usage) => {
            eprintln!("{usage}");
            ExitCode::from(EX_USAGE)
        }
    }
}

fn dispatch_inspect(binary: &std::path::Path, config: &std::path::Path) -> ExitCode {
    match inspect::run(binary, config) {
        Ok(outcome) => ExitCode::from(outcome.exit_code()),
        Err(e) => {
            eprintln!("litmask-cli: {}", e.message());
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
            eprintln!("litmask-cli: {}", e.message());
            ExitCode::from(EX_USAGE)
        }
        Err(bind::ShellError::HardwareIdUnavailable) => {
            // §2.9.1.3: hardware-id failure surfaces on stdout
            // with the documented tag and exits EX_UNAVAILABLE.
            println!("hardware_id_unavailable");
            ExitCode::from(EX_UNAVAILABLE)
        }
        Err(e @ bind::ShellError::CommitFailed(_)) => {
            eprintln!("litmask-cli: {}", e.message());
            ExitCode::from(EX_SOFTWARE)
        }
    }
}

enum Command {
    Inspect {
        binary: PathBuf,
        config: PathBuf,
    },
    Bind {
        binary: PathBuf,
        config: PathBuf,
        salt: Option<String>,
    },
}

/// Hand-rolled argument parser. Avoids the `clap` dep so the CLI's
/// dep tree stays minimal; the surface is small enough that a
/// parser-generator would be disproportionate. Pure: same args in,
/// same `Command` out — unit-tested below.
fn parse_args(args: &[String]) -> Result<Command, &'static str> {
    let usage =
        "usage: litmask-cli <inspect|bind> <binary> --config <litmask.config> [--salt <BASE64URL>]";
    let mut iter = args.iter().skip(1);
    let subcmd = iter.next().ok_or(usage)?;
    let binary = iter.next().ok_or(usage)?;
    let config_flag = iter.next().ok_or(usage)?;
    if config_flag != "--config" {
        return Err(usage);
    }
    let config = iter.next().ok_or(usage)?;

    match subcmd.as_str() {
        "inspect" => {
            if iter.next().is_some() {
                return Err(usage);
            }
            Ok(Command::Inspect {
                binary: PathBuf::from(binary),
                config: PathBuf::from(config),
            })
        }
        "bind" => {
            let salt = match iter.next() {
                None => None,
                Some(flag) if flag == "--salt" => {
                    let value = iter.next().ok_or(usage)?;
                    Some(value.clone())
                }
                Some(_) => return Err(usage),
            };
            if iter.next().is_some() {
                return Err(usage);
            }
            Ok(Command::Bind {
                binary: PathBuf::from(binary),
                config: PathBuf::from(config),
                salt,
            })
        }
        _ => Err(usage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<String> {
        std::iter::once("litmask-cli")
            .chain(parts.iter().copied())
            .map(String::from)
            .collect()
    }

    #[test]
    fn parse_inspect_with_binary_and_config_succeeds() {
        let parsed = parse_args(&args(&[
            "inspect",
            "/path/to/bin",
            "--config",
            "/path/to/cfg",
        ]))
        .expect("inspect parses");
        match parsed {
            Command::Inspect { binary, config } => {
                assert_eq!(binary, PathBuf::from("/path/to/bin"));
                assert_eq!(config, PathBuf::from("/path/to/cfg"));
            }
            Command::Bind { .. } => panic!("expected Inspect"),
        }
    }

    #[test]
    fn parse_bind_without_salt_yields_none() {
        let parsed = parse_args(&args(&["bind", "/bin", "--config", "/cfg"])).expect("bind parses");
        match parsed {
            Command::Bind { salt, .. } => assert_eq!(salt, None),
            Command::Inspect { .. } => panic!("expected Bind"),
        }
    }

    #[test]
    fn parse_bind_with_salt_captures_value() {
        let parsed = parse_args(&args(&[
            "bind", "/bin", "--config", "/cfg", "--salt", "AAAA",
        ]))
        .expect("bind+salt parses");
        match parsed {
            Command::Bind { salt, .. } => assert_eq!(salt.as_deref(), Some("AAAA")),
            Command::Inspect { .. } => panic!("expected Bind"),
        }
    }

    #[test]
    fn parse_no_subcommand_errors() {
        assert!(parse_args(&args(&[])).is_err());
    }

    #[test]
    fn parse_unknown_subcommand_errors() {
        assert!(parse_args(&args(&["nope", "/bin", "--config", "/cfg"])).is_err());
    }

    #[test]
    fn parse_misspelled_config_flag_errors() {
        // The flag must be `--config` literally; a misspelled flag
        // should not silently consume the next arg. The misspelled
        // variant below is intentional fixture data — the typos
        // linter would otherwise flag it.
        let misspelled = ["--c", "ofig"].concat(); // typos: ignore
        assert!(parse_args(&args(&["inspect", "/bin", &misspelled, "/cfg"])).is_err());
    }

    #[test]
    fn parse_inspect_trailing_args_rejected() {
        // Reject trailing junk so a typo doesn't get accepted.
        assert!(parse_args(&args(&["inspect", "/bin", "--config", "/cfg", "extra"])).is_err());
    }

    #[test]
    fn parse_bind_unknown_trailing_flag_rejected() {
        assert!(parse_args(&args(&["bind", "/bin", "--config", "/cfg", "--foo", "bar"])).is_err(),);
    }

    #[test]
    fn parse_bind_salt_without_value_errors() {
        assert!(parse_args(&args(&["bind", "/bin", "--config", "/cfg", "--salt"])).is_err());
    }
}
