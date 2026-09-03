use std::fmt::Write as _;
use std::time::{Duration, SystemTime};

use alpm_db::{Check, Trust};
use eyre::Result;
use serde::Serialize;
use usage_rs::RunWith;

use super::{App, print_json};
use crate::host::Host;

/// Check that this machine is set up for omapac
///
/// Reports the pacman binary, the configuration and its repositories with
/// their signature levels against the floor omapac expects, sync database
/// freshness, the local database, and how omapac would obtain root.
#[derive(Debug, usage_rs::Args)]
pub struct Doctor {
    /// Print as JSON
    #[usage(short = 'J', long)]
    json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub status: Status,
    pub check: String,
    pub detail: String,
}

impl RunWith<&App> for Doctor {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let findings = diagnose(app);
        if self.json {
            print_json(&findings)?;
        } else {
            print!("{}", render(&findings));
        }
        if findings.iter().any(|f| f.status == Status::Fail) {
            std::process::exit(1);
        }
        Ok(())
    }
}

/// How old a sync database may be before it is worth mentioning.
const STALE_AFTER: Duration = Duration::from_secs(7 * 24 * 60 * 60);

pub fn diagnose(app: &App) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut add = |status: Status, check: &str, detail: String| {
        findings.push(Finding {
            status,
            check: check.to_string(),
            detail,
        })
    };

    match crate::engine::pacman::PacmanCli::detect() {
        Ok(engine) => add(Status::Ok, "pacman", format!("{}", engine.pacman.display())),
        Err(err) => add(Status::Fail, "pacman", err.to_string()),
    }

    let host = match app.host() {
        Ok(host) => host,
        Err(err) => {
            add(Status::Fail, "config", format!("{err:#}"));
            return findings;
        }
    };
    diagnose_host(&host, &mut add);

    let ctx = crate::engine::sudo::Context::detect(crate::engine::sudo::Elevation::Auto);
    if ctx.is_root {
        add(Status::Ok, "privileges", "running as root".to_string());
    } else if let Some(sudo) = &ctx.sudo {
        add(
            Status::Ok,
            "privileges",
            format!(
                "will use {}{}",
                sudo.display(),
                if ctx.interactive {
                    ""
                } else {
                    " -n (no terminal, so no password prompt)"
                }
            ),
        );
    } else {
        add(
            Status::Fail,
            "privileges",
            "not root and sudo is not installed".to_string(),
        );
    }
    findings
}

fn diagnose_host(host: &Host, add: &mut impl FnMut(Status, &str, String)) {
    let config_path = host.config_path();
    add(
        Status::Ok,
        "config",
        format!(
            "{} ({} repositories)",
            config_path.display(),
            host.sources.len()
        ),
    );
    for warning in &host.config.warnings {
        add(Status::Warn, "config", warning.to_string());
    }
    if host.config.options.arch().is_none() {
        add(
            Status::Warn,
            "config",
            "no Architecture set; $arch in server URLs cannot expand".to_string(),
        );
    }

    let floor = host.config.options.sig_level;
    for source in &host.sources {
        let level = source.repo.sig_level;
        let check_rank = |check| match check {
            Check::Never => 0,
            Check::Optional => 1,
            Check::Required => 2,
        };
        let trust_rank = |trust| match trust {
            Trust::TrustAll => 0,
            Trust::TrustedOnly => 1,
        };
        let weak = check_rank(level.package()) < check_rank(floor.package())
            || check_rank(level.database()) < check_rank(floor.database())
            || (floor.package() != Check::Never
                && trust_rank(level.package_trust()) < trust_rank(floor.package_trust()))
            || (floor.database() != Check::Never
                && trust_rank(level.database_trust()) < trust_rank(floor.database_trust()));
        let detail = format!(
            "[{}] {} SigLevel = {}{}",
            source.name,
            source.tier,
            level,
            if source.repo.servers.is_empty() {
                ", no servers"
            } else {
                ""
            }
        );
        if level.package() == Check::Never && floor.package() != Check::Never {
            add(
                Status::Fail,
                "signatures",
                format!("{detail}: packages are not signature-checked"),
            );
        } else if weak {
            add(
                Status::Warn,
                "signatures",
                format!("{detail}: weaker than the floor ({floor})"),
            );
        } else {
            add(Status::Ok, "signatures", detail);
        }
        if source.repo.servers.is_empty() {
            add(
                Status::Fail,
                "repositories",
                format!("[{}] has no Server or Include", source.name),
            );
        }
    }

    let now = SystemTime::now();
    for source in &host.sources {
        if source.has_db()
            && let Err(err) = source.db()
        {
            add(
                Status::Fail,
                "sync",
                format!("[{}] database is unreadable: {err:#}", source.name),
            );
            continue;
        }
        match source.db_modified() {
            None => add(
                Status::Warn,
                "sync",
                format!(
                    "[{}] has no sync database yet; run `omapac update` or `pacman -Sy`",
                    source.name
                ),
            ),
            Some(modified) => {
                let age = now.duration_since(modified).unwrap_or_default();
                let days = age.as_secs() / 86_400;
                if age > STALE_AFTER {
                    add(
                        Status::Warn,
                        "sync",
                        format!("[{}] database is {days} days old", source.name),
                    );
                } else {
                    add(
                        Status::Ok,
                        "sync",
                        format!("[{}] database refreshed {days} days ago", source.name),
                    );
                }
            }
        }
    }

    match host.local.version() {
        Ok(Some(version)) => match host.installed() {
            Ok(packages) => add(
                Status::Ok,
                "local",
                format!(
                    "{} (format {version}, {} packages)",
                    host.local.path.display(),
                    packages.len()
                ),
            ),
            Err(err) => add(Status::Fail, "local", format!("{err:#}")),
        },
        Ok(None) => add(
            Status::Fail,
            "local",
            format!("{} has no ALPM_DB_VERSION", host.local.path.display()),
        ),
        Err(err) => add(
            Status::Fail,
            "local",
            format!("{}: {err}", host.local.path.display()),
        ),
    }

    let gpg_dir = host.config.options.gpg_dir();
    let gpg_dir = host
        .paths
        .sysroot
        .as_ref()
        .map(|root| root.join(gpg_dir.strip_prefix("/").unwrap_or(&gpg_dir)))
        .unwrap_or(gpg_dir);
    if gpg_dir.join("pubring.gpg").exists() || gpg_dir.join("pubring.kbx").exists() {
        add(Status::Ok, "keyring", gpg_dir.display().to_string());
    } else {
        add(
            Status::Warn,
            "keyring",
            format!(
                "{} has no pubring.gpg or pubring.kbx; run `pacman-key --init`",
                gpg_dir.display()
            ),
        );
    }
}

pub fn render(findings: &[Finding]) -> String {
    let mut out = String::new();
    for finding in findings {
        let mark = match finding.status {
            Status::Ok => "ok  ",
            Status::Warn => "warn",
            Status::Fail => "FAIL",
        };
        let _ = writeln!(out, "{mark}  {:<12} {}", finding.check, finding.detail);
    }
    let fails = findings.iter().filter(|f| f.status == Status::Fail).count();
    let warns = findings.iter().filter(|f| f.status == Status::Warn).count();
    let _ = writeln!(out, "\n{fails} failing, {warns} warnings");
    out
}
