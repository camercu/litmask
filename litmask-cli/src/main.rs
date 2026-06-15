//! `litmask` CLI — companion tool for build-sealed binaries.
//!
//! `main` is responsible only for argument parsing (via `clap`) and
//! mapping each subcommand's result to a sysexits-aligned `ExitCode`.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod exit;

use litmask_internal::{base64url, encode_machine_id_token};

/// Readable diagnostic for a failed machine-id lookup. Kept as a named
/// constant so the message text is pinned by a unit test.
const MACHINE_ID_UNAVAILABLE_MSG: &str = "could not read the machine ID (machine-uid failed)";

/// Human guidance printed to **stderr** alongside the machine-id token.
/// It explains what the stdout token is for. It rides stderr — not
/// stdout — so a `litmask show-machine-id | …` capture keeps only the
/// token; the in-band check group (§2.9.3) is what protects the token
/// itself against copy corruption.
const MACHINE_ID_GUIDANCE_MSG: &str =
    "send the token above to whoever builds your binary (it is checksummed against typos)";

/// Bytes of fresh randomness `keygen` emits, before base64url encoding.
/// Matches the 32-byte `unlock_key` / seed width the external tier and
/// the build seed derivation consume.
const KEYGEN_BYTES: usize = 32;

/// `litmask` companion tool.
#[derive(Parser, Debug)]
#[command(name = "litmask", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print 32 bytes of fresh randomness, base64url-encoded, to stdout.
    ///
    /// A pure, pipeable generator: nothing is written to stderr and the
    /// binary is never touched. The same 32-byte value populates either
    /// build-time environment variable, depending on what you want:
    ///
    /// `LITMASK_UNLOCK_KEY` seals the external tier — re-supply it at
    /// runtime to unlock, keeping the key out of the binary.
    ///
    /// `LITMASK_RNG_SEED` pins the build seed for reproducible,
    /// per-customer builds — the same seed produces byte-identical output.
    ///
    /// The role is usage, not format (see `docs/DEPLOYMENT.md`).
    ///
    /// Exit codes:
    /// - 0 on success (prints the key to stdout, newline-terminated)
    Keygen,
    /// Print this host's machine ID as a self-checking token — the bytes
    /// a machine-tier build feeds into its key derivation, plus an
    /// in-band check group.
    ///
    /// The enrollment primitive for machine-tier deployments: a target
    /// host runs `show-machine-id` and reports the token, letting the
    /// vendor seal a build against it off-box (see `docs/DEPLOYMENT.md`).
    /// The token's check group lets the build reject a mistyped id before
    /// sealing instead of after deployment.
    ///
    /// Exit codes:
    /// - 0 on success (token to stdout, guidance to stderr)
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
        Command::Keygen => dispatch_keygen(),
        Command::ShowMachineId => dispatch_show_machine_id(),
    }
}

/// Encode freshly generated key bytes for stdout. Pure so the encoding
/// contract (url-safe base64url, no padding) is unit-testable without
/// consuming OS randomness.
fn encode_key(bytes: &[u8]) -> String {
    base64url::encode(bytes)
}

fn dispatch_keygen() -> ExitCode {
    let mut bytes = [0u8; KEYGEN_BYTES];
    if getrandom::fill(&mut bytes).is_err() {
        eprintln!("litmask: OS randomness unavailable (getrandom failed)");
        return ExitCode::from(exit::UNAVAILABLE);
    }
    // Pipeable: the key is the only thing on stdout, newline-terminated.
    println!("{}", encode_key(&bytes));
    ExitCode::from(exit::OK)
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

/// Map a machine-id lookup to its presentation. On success the raw id
/// is wrapped in its self-checking token (§2.9.3) and goes to stdout for
/// capture, while human guidance goes to stderr so a piped capture keeps
/// only the token. A lookup failure is an error and goes to stderr (exit
/// 69), keeping stdout clean for callers piping the token.
fn report_machine_id<E>(lookup: Result<String, E>) -> MachineIdReport {
    match lookup {
        Ok(id) => MachineIdReport {
            stdout: Some(encode_machine_id_token(&id)),
            stderr: Some(MACHINE_ID_GUIDANCE_MSG.to_string()),
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
    fn report_machine_id_success_emits_token_to_stdout_and_guidance_to_stderr() {
        let r = report_machine_id(Ok::<_, std::io::Error>("ABC-123".to_string()));
        let token = r.stdout.expect("success emits a token on stdout");
        // The stdout token is the self-checking form, not the bare id.
        assert_eq!(
            litmask_internal::decode_machine_id_token(&token),
            Ok("ABC-123")
        );
        assert_eq!(r.stderr.as_deref(), Some(MACHINE_ID_GUIDANCE_MSG));
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
    fn encode_key_is_unpadded_base64url_round_tripping_32_bytes() {
        let bytes = [0xABu8; KEYGEN_BYTES];
        let s = encode_key(&bytes);
        // 32 bytes → 43 base64url chars, no padding.
        assert_eq!(s.len(), 43);
        assert!(!s.contains('='), "keygen output must be unpadded: {s}");
        assert_eq!(
            base64url::decode(&s).expect("keygen output decodes"),
            bytes.to_vec()
        );
    }

    #[test]
    fn parses_keygen() {
        let cli = parse_argv(&["keygen"]).unwrap();
        assert!(matches!(cli.command, Command::Keygen));
    }

    #[test]
    fn rejects_keygen_trailing_positional() {
        assert!(parse_argv(&["keygen", "extra"]).is_err());
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
