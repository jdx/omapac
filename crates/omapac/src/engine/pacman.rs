//! The pacman command-line engine.
//!
//! Planning uses `pacman --print --print-format` so resolution comes from
//! pacman itself and never elevates. Applying runs pacman with inherited
//! stdio so its own prompts and hooks work, elevated per the sudo policy.
//! `OMARCHY_UPDATE_PACMAN=1` is set on system upgrades because Omarchy's
//! libalpm guard hook aborts any `-Su` without it; omapac is the sanctioned
//! updater.

use std::path::{Path, PathBuf};

use super::sudo::{Context, Elevation, Invocation};
use super::{
    ApplyOpts, Change, Engine, Error, FileInstall, Operation, RefreshOpts, Report, ResolvedTx,
    Result, Transaction,
};

/// The environment variable Omarchy's pacman guard hook looks for.
pub const OMARCHY_GUARD_ENV: &str = "OMARCHY_UPDATE_PACMAN";

const PRINT_FORMAT: &str = "%n\t%v\t%r\t%l\t%s";

/// pacman, driven through its command line.
#[derive(Debug, Clone)]
pub struct PacmanCli {
    /// The pacman binary.
    pub pacman: PathBuf,
    /// An alternative `pacman.conf`, passed as `--config`.
    pub config: Option<PathBuf>,
    /// An alternative root, passed as `--sysroot`.
    pub sysroot: Option<PathBuf>,
    /// Whether to set the Omarchy guard variable on system upgrades.
    pub omarchy_guard: bool,
    /// How to obtain root.
    pub elevation: Elevation,
}

impl PacmanCli {
    /// Find pacman, preferring Arch's root-owned system location. Falling
    /// back to PATH keeps development fixtures and nonstandard sysroots usable.
    pub fn detect() -> Result<PacmanCli> {
        #[cfg(all(debug_assertions, feature = "test-pacman"))]
        if let Some(pacman) = std::env::var_os("OMAPAC_TEST_PACMAN") {
            return Ok(PacmanCli::with_binary(pacman));
        }
        let system = PathBuf::from("/usr/bin/pacman");
        let pacman = if system.is_file() {
            system
        } else {
            which::which("pacman").map_err(|_| {
                Error::NotAvailable("pacman is not on PATH; omapac needs pacman".to_string())
            })?
        };
        Ok(PacmanCli::with_binary(pacman))
    }

    /// Use a specific pacman binary.
    pub fn with_binary(pacman: impl Into<PathBuf>) -> PacmanCli {
        PacmanCli {
            pacman: pacman.into(),
            config: None,
            sysroot: None,
            omarchy_guard: true,
            elevation: Elevation::Auto,
        }
    }

    fn base_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(config) = &self.config {
            args.push("--config".to_string());
            args.push(config.to_string_lossy().into_owned());
        }
        if let Some(sysroot) = &self.sysroot {
            args.push("--sysroot".to_string());
            args.push(sysroot.to_string_lossy().into_owned());
        }
        args
    }

    /// The arguments for `tx`, without `--print` and without confirmation
    /// handling. Shared by planning and applying so both see the same
    /// transaction.
    fn transaction_args(&self, tx: &Transaction) -> Vec<String> {
        let mut args = self.base_args();
        match &tx.operation {
            Operation::Install {
                targets,
                needed,
                as_deps,
            } => {
                args.push("-S".to_string());
                if *needed {
                    args.push("--needed".to_string());
                }
                if *as_deps {
                    args.push("--asdeps".to_string());
                }
                push_ignores(&mut args, tx);
                push_overwrites(&mut args, &tx.overwrite);
                args.push("--".to_string());
                args.extend(targets.iter().map(ToString::to_string));
            }
            Operation::Remove {
                targets,
                recursive,
                cascade,
                nosave,
                unneeded,
            } => {
                args.push("-R".to_string());
                if *recursive {
                    args.push("-s".to_string());
                }
                if *cascade {
                    args.push("-c".to_string());
                }
                if *nosave {
                    args.push("-n".to_string());
                }
                if *unneeded {
                    args.push("-u".to_string());
                }
                args.push("--".to_string());
                args.extend(targets.iter().cloned());
            }
            Operation::Upgrade { allow_downgrade } => {
                args.push(if *allow_downgrade { "-Suu" } else { "-Su" }.to_string());
                push_ignores(&mut args, tx);
                push_overwrites(&mut args, &tx.overwrite);
            }
        }
        args
    }

    /// The command that would apply `tx`, before elevation.
    pub fn apply_invocation(&self, tx: &Transaction, opts: ApplyOpts) -> Invocation {
        let mut args = self.transaction_args(tx);
        if opts.no_confirm {
            // Insert after the operation flag so `-- targets` stays last.
            let at = args
                .iter()
                .position(|a| a.starts_with('-') && !a.starts_with("--"));
            args.insert(at.map_or(0, |i| i + 1), "--noconfirm".to_string());
        }
        let mut invocation = Invocation::new(&self.pacman, args);
        if self.omarchy_guard && matches!(tx.operation, Operation::Upgrade { .. }) {
            invocation = invocation.with_env(OMARCHY_GUARD_ENV, "1");
        }
        invocation
    }

    /// The command that would plan `tx`.
    pub fn plan_invocation(&self, tx: &Transaction) -> Invocation {
        let mut args = self.transaction_args(tx);
        let at = args
            .iter()
            .position(|a| a.starts_with('-') && !a.starts_with("--"))
            .map_or(0, |i| i + 1);
        args.insert(at, "--noconfirm".to_string());
        args.insert(at + 1, "--print".to_string());
        args.insert(at + 2, "--print-format".to_string());
        args.insert(at + 3, PRINT_FORMAT.to_string());
        Invocation::new(&self.pacman, args)
    }

    fn refresh_invocation(&self, refresh: RefreshOpts, opts: ApplyOpts) -> Invocation {
        let mut args = self.base_args();
        args.push(if refresh.force { "-Syy" } else { "-Sy" }.to_string());
        if opts.no_confirm {
            args.push("--noconfirm".to_string());
        }
        Invocation::new(&self.pacman, args)
    }

    fn install_files_invocation(&self, install: &FileInstall, opts: ApplyOpts) -> Invocation {
        let mut args = self.base_args();
        args.push("-U".to_string());
        if opts.no_confirm {
            args.push("--noconfirm".to_string());
        }
        if install.as_deps {
            args.push("--asdeps".to_string());
        }
        if install.nodeps {
            // pacman interprets the first occurrence as "ignore versions"
            // and the second as "ignore dependency names too".
            args.push("--nodeps".to_string());
            args.push("--nodeps".to_string());
        }
        push_overwrites(&mut args, &install.overwrite);
        args.push("--".to_string());
        args.extend(
            install
                .files
                .iter()
                .map(|f| f.to_string_lossy().into_owned()),
        );
        Invocation::new(&self.pacman, args)
    }

    /// Change the local database reason for already-installed packages.
    pub fn set_install_reason(
        &self,
        packages: &[String],
        as_deps: bool,
        opts: ApplyOpts,
    ) -> Result<Report> {
        let mut args = self.base_args();
        args.push("-D".to_string());
        if opts.no_confirm {
            args.push("--noconfirm".to_string());
        }
        args.push(if as_deps { "--asdeps" } else { "--asexplicit" }.to_string());
        args.push("--".to_string());
        args.extend(packages.iter().cloned());
        self.perform(Invocation::new(&self.pacman, args), opts)
    }

    /// Run an elevated command with inherited stdio.
    fn perform(&self, invocation: Invocation, opts: ApplyOpts) -> Result<Report> {
        let ctx = Context::detect(self.elevation);
        let invocation = invocation.elevated(&ctx)?;
        let command = invocation.display();
        if opts.dry_run {
            return Ok(Report {
                command,
                performed: false,
            });
        }
        let status = invocation.command().status().map_err(|source| Error::Io {
            command: command.clone(),
            source,
        })?;
        if !status.success() {
            return Err(Error::Command {
                command,
                status: status.code().unwrap_or(-1),
                stderr: String::new(),
            });
        }
        Ok(Report {
            command,
            performed: true,
        })
    }
}

fn push_ignores(args: &mut Vec<String>, tx: &Transaction) {
    if !tx.ignore.is_empty() {
        args.push("--ignore".to_string());
        args.push(tx.ignore.join(","));
    }
    if !tx.ignore_group.is_empty() {
        args.push("--ignoregroup".to_string());
        args.push(tx.ignore_group.join(","));
    }
}

fn push_overwrites(args: &mut Vec<String>, overwrite: &[String]) {
    for glob in overwrite {
        args.push("--overwrite".to_string());
        args.push(glob.clone());
    }
}

/// Parse `--print` output in [`PRINT_FORMAT`].
pub fn parse_print_output(output: &str) -> Result<Vec<Change>> {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            let [name, version, repo, location, size] = fields[..] else {
                return Err(Error::Parse(format!(
                    "expected 5 tab-separated fields, got {}: {line:?}",
                    fields.len()
                )));
            };
            Ok(Change {
                name: name.to_string(),
                version: version.to_string(),
                repo: non_empty(repo),
                location: non_empty(location),
                download_size: size.parse().ok(),
            })
        })
        .collect()
}

fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() || s == "(null)" {
        None
    } else {
        Some(s.to_string())
    }
}

impl Engine for PacmanCli {
    fn name(&self) -> &str {
        "pacman"
    }

    fn refresh(&self, refresh: RefreshOpts, opts: ApplyOpts) -> Result<Report> {
        self.perform(self.refresh_invocation(refresh, opts), opts)
    }

    fn plan(&self, tx: &Transaction) -> Result<ResolvedTx> {
        let invocation = self.plan_invocation(tx);
        let command = invocation.display();
        let output = invocation
            .command()
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|source| Error::Io {
                command: command.clone(),
                source,
            })?;
        if !output.status.success() {
            return Err(Error::Command {
                command,
                status: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        let changes = parse_print_output(&String::from_utf8_lossy(&output.stdout))?;
        Ok(ResolvedTx {
            transaction: tx.clone(),
            changes,
        })
    }

    fn apply(&self, tx: &ResolvedTx, opts: ApplyOpts) -> Result<Report> {
        self.perform(self.apply_invocation(&tx.transaction, opts), opts)
    }

    fn install_files(&self, install: &FileInstall, opts: ApplyOpts) -> Result<Report> {
        self.perform(self.install_files_invocation(install, opts), opts)
    }
}

/// Where a package file would land for `tx`'s targets under `cache_dir`,
/// used by callers that want to verify a download before pacman does.
pub fn cached_package_path(cache_dir: &Path, filename: &str) -> PathBuf {
    cache_dir.join(filename)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Target;

    fn engine() -> PacmanCli {
        PacmanCli::with_binary("/usr/bin/pacman")
    }

    #[test]
    fn install_argv() {
        let tx = Transaction::install(vec![
            Target::named("helix"),
            "extra/zathura".parse().unwrap(),
        ])
        .ignoring(["gcc14".to_string(), "gcc14-libs".to_string()])
        .overwriting(["/usr/share/omarchy/*".to_string()]);
        assert_eq!(
            engine().plan_invocation(&tx).display(),
            "/usr/bin/pacman -S --noconfirm --print --print-format '%n\t%v\t%r\t%l\t%s' --needed --ignore gcc14,gcc14-libs --overwrite '/usr/share/omarchy/*' -- helix extra/zathura"
        );
        let apply = engine().apply_invocation(
            &tx,
            ApplyOpts {
                dry_run: false,
                no_confirm: true,
            },
        );
        assert_eq!(
            apply.display(),
            "/usr/bin/pacman -S --noconfirm --needed --ignore gcc14,gcc14-libs --overwrite '/usr/share/omarchy/*' -- helix extra/zathura"
        );
        assert!(apply.env.is_empty(), "installs do not need the guard");
    }

    #[test]
    fn remove_argv() {
        let mut tx = Transaction::remove(vec!["yay".to_string()]);
        assert_eq!(
            engine()
                .apply_invocation(&tx, ApplyOpts::default())
                .display(),
            "/usr/bin/pacman -R -s -- yay"
        );
        if let Operation::Remove {
            recursive,
            cascade,
            nosave,
            unneeded,
            ..
        } = &mut tx.operation
        {
            *recursive = false;
            *cascade = true;
            *nosave = true;
            *unneeded = true;
        }
        assert_eq!(
            engine().plan_invocation(&tx).display(),
            "/usr/bin/pacman -R --noconfirm --print --print-format '%n\t%v\t%r\t%l\t%s' -c -n -u -- yay"
        );
    }

    #[test]
    fn upgrade_sets_the_omarchy_guard_and_honours_downgrade() {
        let tx = Transaction::upgrade().ignoring(["linux".to_string()]);
        let apply = engine().apply_invocation(&tx, ApplyOpts::default());
        assert_eq!(
            apply.display(),
            "OMARCHY_UPDATE_PACMAN=1 /usr/bin/pacman -Su --ignore linux"
        );
        let mut no_guard = engine();
        no_guard.omarchy_guard = false;
        assert_eq!(
            no_guard
                .apply_invocation(&tx, ApplyOpts::default())
                .display(),
            "/usr/bin/pacman -Su --ignore linux"
        );
        let down = Transaction::new(Operation::Upgrade {
            allow_downgrade: true,
        });
        assert_eq!(
            engine().plan_invocation(&down).display(),
            "/usr/bin/pacman -Suu --noconfirm --print --print-format '%n\t%v\t%r\t%l\t%s'"
        );
    }

    #[test]
    fn refresh_and_file_install_argv() {
        let mut engine = engine();
        engine.config = Some(PathBuf::from("/tmp/pacman.conf"));
        engine.sysroot = Some(PathBuf::from("/mnt"));
        assert_eq!(
            engine
                .refresh_invocation(
                    RefreshOpts { force: true },
                    ApplyOpts {
                        dry_run: false,
                        no_confirm: true,
                    },
                )
                .display(),
            "/usr/bin/pacman --config /tmp/pacman.conf --sysroot /mnt -Syy --noconfirm"
        );
        let install = FileInstall {
            files: vec![PathBuf::from(
                "/home/u/.cache/omapac/aur/foo/foo-1.0-1-x86_64.pkg.tar.zst",
            )],
            as_deps: true,
            nodeps: true,
            overwrite: vec![],
        };
        assert_eq!(
            engine
                .install_files_invocation(
                    &install,
                    ApplyOpts {
                        dry_run: true,
                        no_confirm: true
                    }
                )
                .display(),
            "/usr/bin/pacman --config /tmp/pacman.conf --sysroot /mnt -U --noconfirm --asdeps --nodeps --nodeps -- /home/u/.cache/omapac/aur/foo/foo-1.0-1-x86_64.pkg.tar.zst"
        );
    }

    #[test]
    fn parses_print_output() {
        let output = "helix\t26.03-1\textra\thttps://m/extra/os/x86_64/helix-26.03-1-x86_64.pkg.tar.zst\t12345678\n\
                      yay\t13.0.1-1\tlocal\tyay-13.0.1-1\t(null)\n\n";
        let changes = parse_print_output(output).unwrap();
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].name, "helix");
        assert_eq!(changes[0].repo.as_deref(), Some("extra"));
        assert_eq!(changes[0].download_size, Some(12345678));
        assert_eq!(changes[1].repo.as_deref(), Some("local"));
        assert_eq!(changes[1].download_size, None);
        assert!(parse_print_output("just one field").is_err());
    }

    #[test]
    fn dry_run_reports_without_running() {
        let mut engine = PacmanCli::with_binary("/nonexistent/pacman");
        engine.elevation = Elevation::Never;
        let report = engine
            .apply(
                &ResolvedTx {
                    transaction: Transaction::install(vec![Target::named("helix")]),
                    changes: vec![],
                },
                ApplyOpts {
                    dry_run: true,
                    no_confirm: false,
                },
            )
            .unwrap();
        assert!(!report.performed);
        assert_eq!(report.command, "/nonexistent/pacman -S --needed -- helix");
        let err = engine
            .plan(&Transaction::install(vec![Target::named("helix")]))
            .unwrap_err();
        assert!(matches!(err, Error::Io { .. }), "{err}");
    }

    #[test]
    fn cache_path() {
        assert_eq!(
            cached_package_path(Path::new("/var/cache/pacman/pkg"), "a-1-1.pkg.tar.zst"),
            PathBuf::from("/var/cache/pacman/pkg/a-1-1.pkg.tar.zst")
        );
    }
}
