//! `litmask-cli` — companion tool for `bind` and `inspect` operations.
//!
//! Task 24 implements `inspect`; `bind` lands in Task 25/26.

use std::path::PathBuf;
use std::process::ExitCode;

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
        Ok(Command::Inspect { binary, config }) => match inspect::run(&binary, &config) {
            Ok(code) => ExitCode::from(code),
            Err(e @ (inspect::Error::ConfigUnreadable | inspect::Error::ConfigMalformed)) => {
                eprintln!("litmask-cli: {}", e.message());
                ExitCode::from(EX_USAGE)
            }
            Err(e @ (inspect::Error::BinaryUnreadable | inspect::Error::Internal)) => {
                eprintln!("litmask-cli: {}", e.message());
                ExitCode::from(EX_SOFTWARE)
            }
        },
        Err(usage) => {
            eprintln!("{usage}");
            ExitCode::from(EX_USAGE)
        }
    }
}

enum Command {
    Inspect { binary: PathBuf, config: PathBuf },
}

/// Hand-rolled argument parser. Avoids the `clap` dep so the CLI's
/// dep tree stays minimal; the surface (`inspect <binary> --config
/// <path>`) is small enough that a parser-generator would be
/// disproportionate.
fn parse_args(args: &[String]) -> Result<Command, &'static str> {
    let usage = "usage: litmask-cli inspect <binary> --config <litmask.config>";
    let mut iter = args.iter().skip(1);
    let subcmd = iter.next().ok_or(usage)?;
    if subcmd != "inspect" {
        return Err(usage);
    }
    let binary = iter.next().ok_or(usage)?;
    let config_flag = iter.next().ok_or(usage)?;
    if config_flag != "--config" {
        return Err(usage);
    }
    let config = iter.next().ok_or(usage)?;
    if iter.next().is_some() {
        // Reject trailing junk so a misspelled flag does not
        // silently accept an extra arg.
        return Err(usage);
    }
    Ok(Command::Inspect {
        binary: PathBuf::from(binary),
        config: PathBuf::from(config),
    })
}
