#![forbid(unsafe_code)]

use std::ffi::OsString;

use eyre::Result;
use omapac_cli_support::version::{BinInfo, Version};
use usage_rs::RunWith;

const BIN: BinInfo = BinInfo {
    name: "omapac-repo",
    version: env!("CARGO_PKG_VERSION"),
};

/// Server-side tooling for a repository that serves omapac clients
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
#[usage(run_with)]
enum Commands {
    Version(Version),
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let args: Vec<OsString> = std::env::args_os().collect();
    let argv = omapac_cli_support::argv(&args);
    let cli = omapac_cli_support::unwrap_or_exit(Cli::spec(), &argv, Cli::parse_from_argv(&argv));
    match cli.command {
        Some(command) => command.run_with(BIN),
        None => Ok(()),
    }
}
