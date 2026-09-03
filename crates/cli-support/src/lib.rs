//! Shared glue for the binaries in this workspace: turn a usage-rs parse
//! result into either the parsed command or the help, version, or failure
//! text a user expects, with clap's exit codes.

#![forbid(unsafe_code)]

use std::ffi::{OsStr, OsString};

pub mod version;

/// Borrow `argv` as the slice of `OsStr` that usage-rs parses.
pub fn argv(args: &[OsString]) -> Vec<&OsStr> {
    args.iter().map(OsString::as_os_str).collect()
}

/// Unwrap a parse result, or print help, version, or a usage failure and exit.
///
/// `argv` is the full command line including the program name at index 0.
/// Exit codes follow clap: 0 for help and version, 2 for a usage error.
pub fn unwrap_or_exit<T>(
    spec: &usage_rs::spec::Spec<'_>,
    argv: &[&OsStr],
    result: Result<T, usage_rs::Error<'_, '_>>,
) -> T {
    match result {
        Ok(cli) => cli,
        Err(err) => exit_with_usage_error(spec, argv.get(1..).unwrap_or_default(), err),
    }
}

fn exit_with_usage_error(
    spec: &usage_rs::spec::Spec<'_>,
    args: &[&OsStr],
    err: usage_rs::Error<'_, '_>,
) -> ! {
    match err {
        usage_rs::Error::Help { cmd, long } => {
            if let Some(page) = usage_rs::help::render(spec, cmd, long) {
                print!("{page}");
            }
            std::process::exit(0)
        }
        usage_rs::Error::HelpAll { cmd } => {
            if let Some(page) = usage_rs::help::render_all(spec, cmd) {
                print!("{page}");
            }
            std::process::exit(0)
        }
        usage_rs::Error::MissingArgsHelp { cmd } => {
            if let Some(page) = usage_rs::help::render(spec, cmd, false) {
                eprint!("{page}");
            }
            std::process::exit(2)
        }
        usage_rs::Error::Version { long } => {
            let version = if long {
                spec.long_version.or(spec.version)
            } else {
                spec.version
            }
            .unwrap_or_default();
            println!("{} {version}", spec.name);
            std::process::exit(0)
        }
        err => {
            eprint!("{}", usage_rs::render_failure(spec, args, &err));
            std::process::exit(2)
        }
    }
}
