use std::ffi::OsString;
use std::path::PathBuf;

use eyre::Result;
use pacvamp_cli_support::version::{BinInfo, Version};
use usage_rs::RunWith;

use crate::host::{Host, HostPaths};

mod audit;
mod aur_cmd;
mod build_env;
mod cache;
mod channel;
mod converge;
mod declare;
mod doctor;
mod import;
mod info;
mod install;
mod jail_cmd;
mod ledger_cmd;
mod list;
mod pacnew;
mod present;
mod recover;
mod remove;
mod search;
mod tools;
mod transaction;
mod update;
mod verify;

fn check_rank(check: alpm_db::Check) -> u8 {
    match check {
        alpm_db::Check::Never => 0,
        alpm_db::Check::Optional => 1,
        alpm_db::Check::Required => 2,
    }
}

fn trust_rank(trust: alpm_db::Trust) -> u8 {
    match trust {
        alpm_db::Trust::TrustAll => 0,
        alpm_db::Trust::TrustedOnly => 1,
    }
}

const LONG_ABOUT: &str = "pacvamp installs, removes, and updates packages from the Arch mirror, \
the Omarchy Package Repository, and the AUR through one command, with trust tiers, \
commit-bound AUR builds, and policy that is stricter when nobody is watching. \
https://github.com/jdx/pacvamp";

const BIN: BinInfo = BinInfo {
    name: "pacvamp",
    version: env!("CARGO_PKG_VERSION"),
};

/// A trust-focused package manager for pacman-based Linux distributions
#[derive(usage_rs::Cli)]
#[usage(
    bin = "pacvamp",
    version,
    long_about = LONG_ABOUT,
    author = "Jeff Dickey <@jdx>",
    arg_required_else_help
)]
pub struct Cli {
    /// Read this pacman.conf instead of /etc/pacman.conf
    #[usage(long, global, value_hint = usage_rs::ValueHint::FilePath)]
    config: Option<PathBuf>,
    /// Operate on an alternative root, like pacman --sysroot
    #[usage(long, global, value_hint = usage_rs::ValueHint::DirPath)]
    sysroot: Option<PathBuf>,
    #[usage(subcommand)]
    command: Option<Commands>,
}

#[derive(usage_rs::Subcommands)]
#[usage(run_with)]
enum Commands {
    Add(declare::Add),
    Apply(declare::Apply),
    Audit(audit::Audit),
    Aur(aur_cmd::Aur),
    BuildEnv(build_env::BuildEnv),
    Cache(cache::Cache),
    Channel(channel::Channel),
    Doctor(doctor::Doctor),
    Drop(declare::Drop),
    Info(info::Info),
    Import(import::Import),
    Install(install::Install),
    #[usage(name = "__jail", hide)]
    JailExec(jail_cmd::JailExec),
    #[usage(name = "__build", hide)]
    BuildExec(jail_cmd::BuildExec),
    #[usage(name = "__cgroup-watch", hide)]
    CgroupWatch(jail_cmd::CgroupWatch),
    #[usage(name = "__ledger", hide)]
    LedgerMerge(ledger_cmd::LedgerMerge),
    #[usage(name = "__write", hide)]
    WriteExec(channel::WriteExec),
    List(list::List),
    Missing(present::Missing),
    Pacnew(pacnew::Pacnew),
    Plan(declare::Plan),
    Present(present::Present),
    Remove(remove::Remove),
    Recover(recover::Recover),
    Rollback(channel::Rollback),
    Search(search::Search),
    Status(declare::Status),
    Tools(tools::Tools),
    Update(update::Update),
    Verify(verify::Verify),
    Version(Version),
}

/// What every command gets: the binary identity and where the host lives.
pub struct App {
    pub bin: BinInfo,
    pub paths: HostPaths,
}

impl App {
    /// Load the host's package state.
    pub fn host(&self) -> Result<Host> {
        Host::load(self.paths.clone())
    }

    /// The AUR RPC client. `PACVAMP_AUR_RPC_BASE` points it elsewhere, for
    /// mirrors and tests.
    pub fn aur_rpc(&self) -> crate::aur::rpc::Client {
        match std::env::var("PACVAMP_AUR_RPC_BASE") {
            Ok(base) if !base.is_empty() => crate::aur::rpc::Client::with_base(&base),
            _ => crate::aur::rpc::Client::new(),
        }
    }
}

impl AsRef<BinInfo> for App {
    fn as_ref(&self) -> &BinInfo {
        &self.bin
    }
}

pub fn run(args: &[OsString]) -> Result<()> {
    pacvamp_cli_support::dump_usage_spec_if_requested(args, || Cli::spec().to_kdl());
    let argv = pacvamp_cli_support::argv(args);
    let cli = pacvamp_cli_support::unwrap_or_exit(Cli::spec(), &argv, Cli::parse_from_argv(&argv));
    let app = App {
        bin: BIN,
        paths: HostPaths {
            config: cli.config,
            sysroot: cli.sysroot,
        },
    };
    // Keep generated artifacts leased through approval, installation, and the
    // final ledger write, even after the build's options have been dropped.
    let _cache_lease = if matches!(
        cli.command.as_ref(),
        Some(
            Commands::Aur(_)
                | Commands::Install(_)
                | Commands::Update(_)
                | Commands::Add(_)
                | Commands::Apply(_)
                | Commands::Drop(_)
        )
    ) {
        Some(crate::aur::cache::lease(&crate::aur::cache_dir(), false)?)
    } else {
        None
    };
    match cli.command {
        Some(command) => command.run_with(&app),
        None => Ok(()),
    }
}

/// Print a value as pretty JSON.
pub(crate) fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// A unix timestamp as `YYYY-MM-DD HH:MM` UTC, or the raw number if it is
/// out of range.
pub(crate) fn format_time(ts: i64) -> String {
    match jiff::Timestamp::from_second(ts) {
        Ok(t) => t.strftime("%Y-%m-%d %H:%M UTC").to_string(),
        Err(_) => ts.to_string(),
    }
}

/// Bytes as a short human size.
pub(crate) fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_times() {
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1536), "1.5 KiB");
        assert_eq!(format_size(5_283_285), "5.0 MiB");
        assert_eq!(format_time(1756800000), "2025-09-02 08:00 UTC");
    }
}
