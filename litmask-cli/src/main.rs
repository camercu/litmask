//! `litmask-cli` — companion tool for `bind` and `inspect` operations.
//!
//! Task 24 implements `inspect`; Task 25 implements `bind` (POSIX
//! atomic commit). Windows atomic commit lands in Task 26.

use std::path::PathBuf;
use std::process::ExitCode;

mod bind;
mod inspect;

/// Exit codes follow sysexits.h (§1.9.7):
/// - `EX_USAGE` (64): argument parsing failure
/// - `EX_DATAERR` (65): ambiguous locator match
/// - `EX_NOINPUT` (66): no locator match
/// - `EX_SOFTWARE` (70): unexpected internal failure
const EX_USAGE: u8 = 64;
const EX_SOFTWARE: u8 = 70;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match parse_args(&args) {
        Ok(Command::Inspect { binary, config }) => run_inspect(&binary, &config),
        Ok(Command::Bind {
            binary,
            config,
            salt,
        }) => run_bind(&binary, &config, salt.as_deref()),
        Err(usage) => {
            eprintln!("{usage}");
            ExitCode::from(EX_USAGE)
        }
    }
}

fn run_inspect(binary: &std::path::Path, config: &std::path::Path) -> ExitCode {
    match inspect::run(binary, config) {
        Ok(code) => ExitCode::from(code),
        Err(e @ (inspect::Error::ConfigUnreadable | inspect::Error::ConfigMalformed)) => {
            eprintln!("litmask-cli: {}", e.message());
            ExitCode::from(EX_USAGE)
        }
        Err(e @ (inspect::Error::BinaryUnreadable | inspect::Error::Internal)) => {
            eprintln!("litmask-cli: {}", e.message());
            ExitCode::from(EX_SOFTWARE)
        }
    }
}

fn run_bind(binary: &std::path::Path, config: &std::path::Path, salt: Option<&str>) -> ExitCode {
    match bind::run(binary, config, salt) {
        Ok(code) => ExitCode::from(code),
        Err(
            e @ (bind::Error::ConfigUnreadable
            | bind::Error::BinaryUnreadable
            | bind::Error::SaltInvalid),
        ) => {
            eprintln!("litmask-cli: {}", e.message());
            ExitCode::from(EX_USAGE)
        }
        Err(e @ (bind::Error::UnsupportedFormat | bind::Error::UnsupportedCipher)) => {
            // Per §2.9.1.6 + §1.9.7: a wrapper that the CLI cannot
            // dispatch on maps to EX_DATAERR — the wrapper itself
            // is the wrong shape, distinct from a CLI internal
            // error.
            println!("{}", e.message());
            ExitCode::from(65)
        }
        Err(e @ bind::Error::Internal) => {
            eprintln!("litmask-cli: {}", e.message());
            ExitCode::from(EX_SOFTWARE)
        }
        // DecryptionFailed / HardwareIdUnavailable can ALSO
        // surface as Err in the rare case the bind handler hits
        // them outside the routed branches; route them through
        // EX_DATAERR / EX_UNAVAILABLE per §2.9.1.3 so the operator
        // sees the same exit code as the in-band path.
        Err(e @ bind::Error::DecryptionFailed) => {
            eprintln!("litmask-cli: {}", e.message());
            ExitCode::from(65)
        }
        Err(e @ bind::Error::HardwareIdUnavailable) => {
            eprintln!("litmask-cli: {}", e.message());
            ExitCode::from(69)
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
/// dep tree stays minimal; the surface (`inspect <binary> --config
/// <path>` / `bind <binary> --config <path> [--salt <BASE64URL>]`)
/// is small enough that a parser-generator would be
/// disproportionate.
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
