#![forbid(unsafe_code)]

mod attest;
mod index;
mod rekor;
mod sign;
mod vendor;

use std::ffi::OsString;

use eyre::Result;
use omapac_cli_support::version::{BinInfo, Version};
use usage_rs::RunWith;

const BIN: BinInfo = BinInfo {
    name: "omapac-repo",
    version: env!("CARGO_PKG_VERSION"),
};

/// Server-side tooling for a repository that serves omapac clients
///
/// Everything a repository needs to publish what omapac verifies: the
/// signed index, build provenance, and (in later releases) the signer
/// gate, the vendor pipeline, the AUR sync gate, verdicts, advisories,
/// and snapshots. See PLAN.md in the omapac repository.
#[derive(usage_rs::Cli)]
#[usage(
    bin = "omapac-repo",
    version,
    author = "Jeff Dickey <@jdx>",
    arg_required_else_help
)]
struct Cli {
    #[usage(subcommand)]
    command: Option<Commands>,
}

#[derive(usage_rs::Subcommands)]
enum Commands {
    Attest(attest::Attest),
    Index(index::IndexCmd),
    Sign(sign::Sign),
    Vendor(vendor::Vendor),
    Version(Version),
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let args: Vec<OsString> = std::env::args_os().collect();
    let argv = omapac_cli_support::argv(&args);
    let cli = omapac_cli_support::unwrap_or_exit(Cli::spec(), &argv, Cli::parse_from_argv(&argv));
    match cli.command {
        Some(Commands::Attest(cmd)) => cmd.run_with(()),
        Some(Commands::Index(cmd)) => cmd.run_with(()),
        Some(Commands::Sign(cmd)) => cmd.run_with(()),
        Some(Commands::Vendor(cmd)) => cmd.run_with(()),
        Some(Commands::Version(cmd)) => cmd.run_with(BIN),
        None => Ok(()),
    }
}
