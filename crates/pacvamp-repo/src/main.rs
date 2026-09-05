#![forbid(unsafe_code)]

mod advisories;
mod attest;
mod feed;
mod http;
mod index;
mod rekor;
mod repack;
mod sign;
mod snapshot;
mod sync_aur;
mod tool_channel;
mod vendor;
mod verdict;

use std::ffi::OsString;

use eyre::Result;
use pacvamp_cli_support::version::{BinInfo, Version};
use usage_rs::RunWith;

const BIN: BinInfo = BinInfo {
    name: "pacvamp-repo",
    version: env!("CARGO_PKG_VERSION"),
};

/// Server-side tooling for a repository that serves pacvamp clients
///
/// Everything a repository needs to publish what pacvamp verifies: the
/// signed index, build provenance, and (in later releases) the signer
/// gate, the vendor pipeline, the AUR sync gate, verdicts, advisories,
/// and snapshots. See PLAN.md in the pacvamp repository.
#[derive(usage_rs::Cli)]
#[usage(
    bin = "pacvamp-repo",
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
    Advisories(advisories::Advisories),
    Attest(attest::Attest),
    Index(index::IndexCmd),
    Repack(repack::Repack),
    Sign(sign::Sign),
    Snapshot(snapshot::Snapshot),
    SyncAur(sync_aur::SyncAur),
    ToolChannel(tool_channel::ToolChannel),
    Vendor(vendor::Vendor),
    Verdict(verdict::VerdictCmd),
    Version(Version),
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let args: Vec<OsString> = std::env::args_os().collect();
    pacvamp_cli_support::dump_usage_spec_if_requested(&args, || Cli::spec().to_kdl());
    let argv = pacvamp_cli_support::argv(&args);
    let cli = pacvamp_cli_support::unwrap_or_exit(Cli::spec(), &argv, Cli::parse_from_argv(&argv));
    match cli.command {
        Some(Commands::Advisories(cmd)) => cmd.run_with(()),
        Some(Commands::Attest(cmd)) => cmd.run_with(()),
        Some(Commands::Index(cmd)) => cmd.run_with(()),
        Some(Commands::Repack(cmd)) => cmd.run_with(()),
        Some(Commands::Sign(cmd)) => cmd.run_with(()),
        Some(Commands::Snapshot(cmd)) => cmd.run_with(()),
        Some(Commands::SyncAur(cmd)) => cmd.run_with(()),
        Some(Commands::ToolChannel(cmd)) => cmd.run_with(()),
        Some(Commands::Vendor(cmd)) => cmd.run_with(()),
        Some(Commands::Verdict(cmd)) => cmd.run_with(()),
        Some(Commands::Version(cmd)) => cmd.run_with(BIN),
        None => Ok(()),
    }
}
