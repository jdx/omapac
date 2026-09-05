use super::{App, Host, STALE_AFTER, Status};
use crate::manifest::settings::{Advisories, Enforcement};
use crate::resolve::Tier;
use crate::trust;

pub(super) fn diagnose_protections(
    app: &App,
    host: &Host,
    refresh: bool,
    add: &mut impl FnMut(Status, &str, String),
) {
    let manifest = match app.manifest() {
        Ok(manifest) => manifest,
        Err(err) => {
            add(Status::Fail, "policy", format!("{err:#}"));
            return;
        }
    };
    let settings = &manifest.settings;
    add(
        if settings.aur_jail {
            Status::Ok
        } else {
            Status::Warn
        },
        "sandbox-policy",
        format!(
            "AUR jail {}; {} configured build-network grant(s)",
            if settings.aur_jail {
                "enabled"
            } else {
                "DISABLED"
            },
            settings.aur_allow_network_build.len()
        ),
    );
    match settings.aur_limits.effective_kernel_limits() {
        Ok(limits) => add(
            Status::Ok,
            "build-limits",
            format!(
                "wall {}s, CPU {}s/process, virtual memory {} bytes/process, {} processes/user, file {} bytes, sampled disk {} MiB/run (inherited kernel ceilings included)",
                settings.aur_limits.wall_seconds,
                limits.cpu_seconds,
                limits.memory_bytes,
                limits.processes,
                limits.file_bytes,
                settings.aur_limits.disk_mb
            ),
        ),
        Err(err) => add(Status::Fail, "build-limits", format!("{err:#}")),
    }
    if let Some(root) = &settings.aur_cgroup_root {
        match crate::cgroup::validate(root) {
            Ok(()) => add(
                Status::Ok,
                "build-cgroup",
                format!(
                    "{}; aggregate CPU {}%, memory {} MiB, tasks {}; controller writes checked at build startup",
                    root.display(),
                    settings.aur_limits.cpu_percent,
                    settings.aur_limits.memory_mb,
                    settings.aur_limits.processes
                ),
            ),
            Err(err) => add(Status::Fail, "build-cgroup", format!("{err:#}")),
        }
    }
    if settings.aur_chroot {
        match crate::aur::chroot::host(&settings.aur_chroot_root)
            .and_then(|_| which::which("bwrap").map_err(Into::into))
        {
            Ok(_) => add(
                Status::Ok,
                "build-chroot",
                format!(
                    "image {}; bubblewrap present; namespace startup is checked at build time",
                    settings.aur_chroot_root.display()
                ),
            ),
            Err(err) => add(Status::Fail, "build-chroot", format!("{err:#}")),
        }
    }
    match crate::jail::probe() {
        Ok(()) => add(Status::Ok, "sandbox-kernel", "running kernel enforces the Landlock and seccomp helper; filesystem reads/writes confined, internet sockets denied".into()),
        Err(err) => add(if settings.aur_jail { Status::Fail } else { Status::Warn }, "sandbox-kernel", format!("unavailable: {err:#}")),
    }
    add(
        Status::Ok,
        "policy",
        format!(
            "index {:?}, provenance {:?}, advisories {:?}, no-downgrade {}; {} managed policy file(s)",
            settings.trust_index,
            settings.trust_provenance,
            settings.trust_advisories,
            settings.trust_no_downgrade,
            manifest.managed.len()
        ),
    );
    if settings.trust_index == Enforcement::Off
        || settings.trust_provenance == Enforcement::Off
        || !settings.trust_no_downgrade
    {
        add(
            Status::Warn,
            "policy",
            "one or more repository verification protections are disabled".into(),
        );
    }
    if !host
        .sources
        .iter()
        .any(|source| matches!(source.tier, Tier::Opr))
    {
        add(
            if settings.trust_advisories == Advisories::Required {
                Status::Fail
            } else {
                Status::Warn
            },
            "feed-review",
            if settings.trust_advisories == Advisories::Off {
                "AUR advisory and verdict feeds are disabled".into()
            } else {
                "AUR advisory and verdict feeds unavailable: no OPR repository configured; configure an OPR source and trusted keys".into()
            },
        );
    }
    let keyring = match trust::Keyring::load(app.paths.sysroot.as_deref()) {
        Ok(keyring) => keyring,
        Err(_) => return, // The trust-root diagnostic already reports the exact error.
    };
    for source in &host.sources {
        if matches!(source.tier, Tier::Arch) {
            add(
                Status::Ok,
                "publisher",
                format!(
                    "[{}] uses pacman's signature checks; pacvamp provenance is not assumed",
                    source.name
                ),
            );
            continue;
        }
        if keyring.is_empty() {
            add(
                if settings.trust_index == Enforcement::Required
                    || settings.trust_advisories == Advisories::Required
                {
                    Status::Fail
                } else {
                    Status::Warn
                },
                "publisher",
                format!(
                    "[{}] no trusted pacvamp feed can be authenticated without configured keys",
                    source.name
                ),
            );
            continue;
        }
        match app.index_readonly(host, &source.name, !refresh) {
            Ok(index) => {
                report_feed(
                    &source.name,
                    "index",
                    &index.value.generated_at,
                    &index,
                    add,
                );
                let packages = &index.value.packages;
                add(
                    Status::Ok,
                    "publisher",
                    format!(
                        "[{}] signed index sequence {} advertises {} packages: {} with build provenance, {} with vendor manifests, {} with verdicts; these are publisher claims, not package verification results",
                        source.name,
                        index.value.sequence,
                        packages.len(),
                        packages
                            .values()
                            .filter(|p| p.evidence.build_provenance)
                            .count(),
                        packages
                            .values()
                            .filter(|p| p.evidence.vendor_manifest)
                            .count(),
                        packages
                            .values()
                            .filter(|p| p.evidence.verdicts > 0)
                            .count()
                    ),
                );
            }
            Err(err) => add(
                if settings.trust_index == Enforcement::Required {
                    Status::Fail
                } else {
                    Status::Warn
                },
                "feed-index",
                format!(
                    "[{}] unavailable or rejected: {err:#}; {}",
                    source.name,
                    refresh_hint(refresh)
                ),
            ),
        }
        // AUR review currently consumes the first OPR repository's feeds.
        // Do not present unrelated repositories' feeds as active AUR protection.
        if matches!(source.tier, Tier::Opr)
            && host
                .sources
                .iter()
                .find(|s| matches!(s.tier, Tier::Opr))
                .is_some_and(|s| s.name == source.name)
        {
            if settings.trust_advisories == Advisories::Off {
                add(
                    Status::Warn,
                    "feed-policy",
                    "AUR advisory and verdict feeds are disabled".into(),
                );
                continue;
            }
            let result = (|| -> eyre::Result<()> {
                let feed = app
                    .feed_source(host, &source.name)
                    .ok_or_else(|| eyre::eyre!("no feed server"))?;
                let cache = trust::Cache::for_repo(&source.name, app.paths.sysroot.as_deref())?;
                for name in ["advisories.json", "verdicts.json"] {
                    let fetched: eyre::Result<trust::Fetched<serde_json::Value>> =
                        trust::fetch_checked(
                            &feed,
                            name,
                            &keyring,
                            &cache,
                            !refresh,
                            |value: &serde_json::Value| {
                                if name == "advisories.json" {
                                    serde_json::from_value::<trust::Advisories>(value.clone())?;
                                } else {
                                    serde_json::from_value::<trust::Verdicts>(value.clone())?;
                                }
                                Ok(())
                            },
                        );
                    match fetched {
                        Ok(fetched) => report_feed(
                            &source.name,
                            name,
                            fetched.value["issued_at"].as_str().unwrap_or(""),
                            &fetched,
                            add,
                        ),
                        Err(err) => add(
                            if settings.trust_advisories == Advisories::Required {
                                Status::Fail
                            } else {
                                Status::Warn
                            },
                            "feed-review",
                            format!(
                                "[{}] {name} unavailable or rejected: {err:#}; {}",
                                source.name,
                                refresh_hint(refresh)
                            ),
                        ),
                    }
                }
                Ok(())
            })();
            if let Err(err) = result {
                add(
                    if settings.trust_advisories == Advisories::Required {
                        Status::Fail
                    } else {
                        Status::Warn
                    },
                    "feed-review",
                    format!("{err:#}"),
                );
            }
        }
    }
    if settings.channel_snapshot_base.is_none() {
        add(Status::Warn, "snapshot-store", "channel.snapshot_base is not configured; snapshot pinning and rollback are unavailable".into());
    }
    match app.active_release(host, !refresh) {
        Ok(Some(release)) => {
            let passed = release.tests.as_ref().is_some_and(|t| t.result == crate::channel::TestResult::Pass);
            add(if passed && !release.held { Status::Ok } else { Status::Warn }, "snapshot",
                format!("{} on {}: tests {}, promoted {}, held {}, {} tested pkgbases; membership alone does not mean a package was tested",
                    release.id, release.channel, if passed { "passed" } else { "not passed" }, release.was_promoted(), release.held, release.tested_pkgbases.len()));
        }
        Ok(None) => add(Status::Warn, "snapshot", "no authenticated active release available; configure channel infrastructure and trust roots".into()),
        Err(err) => add(Status::Warn, "snapshot", format!("active release unavailable or rejected: {err:#}; {}", refresh_hint(refresh))),
    }
    match app.ledger().and_then(|ledger| {
        if !ledger.pending.is_empty() {
            add(
                Status::Warn,
                "transaction-recovery",
                format!(
                    "{} interrupted transaction(s); inspect with pacvamp recover",
                    ledger.pending.len()
                ),
            );
        }
        let installed = host.installed()?;
        let recorded = installed
            .iter()
            .filter(|p| {
                ledger
                    .packages
                    .get(&p.name)
                    .is_some_and(|e| e.version == p.version && e.verification.is_some())
            })
            .count();
        Ok((recorded, installed.len()))
    }) {
        Ok((recorded, total)) => add(
            if recorded == total {
                Status::Ok
            } else {
                Status::Warn
            },
            "installed-evidence",
            format!(
                "{recorded}/{total} installed versions have recorded repository verification; doctor does not reverify installed files"
            ),
        ),
        Err(err) => add(Status::Fail, "installed-evidence", format!("{err:#}")),
    }
}

fn refresh_hint(refresh: bool) -> &'static str {
    if refresh {
        "check publisher configuration and availability"
    } else {
        "run `pacvamp doctor --refresh` to check the publisher"
    }
}

fn report_feed<T>(
    repo: &str,
    name: &str,
    issued: &str,
    fetched: &trust::Fetched<T>,
    add: &mut impl FnMut(Status, &str, String),
) {
    let now = crate::ledger::now();
    let timestamp = issued
        .parse::<jiff::Timestamp>()
        .ok()
        .map(|t| t.as_second());
    let fresh = timestamp
        .is_some_and(|t| t <= now + 300 && now.saturating_sub(t) <= STALE_AFTER.as_secs() as i64);
    add(
        if fresh && fetched.fallback_error.is_none() {
            Status::Ok
        } else {
            Status::Warn
        },
        "feed-freshness",
        format!(
            "[{repo}] {name}: authenticated by {}; published {issued}; {} (7-day diagnostic threshold); {}{}",
            fetched.key_id,
            if fresh {
                "recent"
            } else {
                "stale or invalid publication time"
            },
            if fetched.fresh {
                "fetched now"
            } else {
                "cached; current publisher availability not verified"
            },
            fetched
                .fallback_error
                .as_ref()
                .map(|e| format!("; refresh failed: {e}"))
                .unwrap_or_default()
        ),
    );
}
