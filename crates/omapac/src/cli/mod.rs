use std::ffi::OsString;

use eyre::Result;
use omapac_cli_support::version::{BinInfo, Version};
use usage_rs::RunWith;

const LONG_ABOUT: &str = "omapac installs, removes, and updates packages from the Arch mirror, \
the Omarchy Package Repository, and the AUR through one command, with trust tiers, \
commit-bound AUR builds, and policy that is stricter when nobody is watching. \
https://github.com/jdx/omapac";

const BIN: BinInfo = BinInfo {
    name: "omapac",
    version: env!("CARGO_PKG_VERSION"),
};

/// The system package manager for Omarchy
#[derive(usage_rs::Cli)]
#[usage(
    bin = "omapac",
    version,
    long_about = LONG_ABOUT,
    author = "Jeff Dickey <@jdx>",
    arg_required_else_help
)]
pub struct Cli {
    #[usage(subcommand)]
    command: Option<Commands>,
}

#[derive(usage_rs::Subcommands)]
#[usage(run_with)]
enum Commands {
    Version(Version),
}

pub fn run(args: &[OsString]) -> Result<()> {
    let argv = omapac_cli_support::argv(args);
    let cli = omapac_cli_support::unwrap_or_exit(Cli::spec(), &argv, Cli::parse_from_argv(&argv));
    match cli.command {
        Some(command) => command.run_with(BIN),
        None => Ok(()),
    }
}
