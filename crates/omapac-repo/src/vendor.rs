//! `omapac-repo vendor`: the vendor pipeline. A vendor-built package is
//! generated from the vendor's signed packslip, not from a checksum file
//! fetched over TLS. See `docs/spec/vendor-pipeline.md`.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use eyre::{Context as _, Result, bail};
use packslip::minisign::PublicKey;
use packslip::model::{Level, Statement};
use serde::{Deserialize, Serialize};
use usage_rs::RunWith;

/// `vendor.toml` beside the PKGBUILD.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VendorToml {
    pub upstream: Upstream,
    /// pacman architecture → how to pick the artifact.
    #[serde(default)]
    pub artifacts: BTreeMap<String, Selector>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// The project's package URL, which the packslip must name.
    pub project: String,
    /// The signed release list (`.well-known/packslip/<project>.json`).
    pub releases: String,
    /// The pinned minisign public key: its base64 line, or a file path
    /// relative to the package directory.
    pub pubkey: String,
    /// Skip releases younger than this.
    #[serde(default)]
    pub min_release_age: Option<String>,
    /// The lowest evidence level accepted.
    #[serde(default)]
    pub provenance_floor: Option<Level>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selector {
    pub os: Option<String>,
    pub arch: Option<String>,
    pub libc: Option<String>,
    /// Match the artifact name instead, with `{version}` substituted.
    pub name: Option<String>,
}

/// The release list a vendor advertises.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Releases {
    pub project: String,
    pub releases: Vec<ReleaseRef>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReleaseRef {
    pub version: String,
    pub published_at: String,
    /// URL of the packslip document; its signature is at `<url>.minisig`.
    pub packslip: String,
}

/// `vendor.lock`: what was last generated, for no-downgrade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VendorLock {
    pub version: String,
    pub level: Level,
    pub published_at: String,
    pub key_id: String,
    pub generated_at: String,
}

/// The sidecar the built package ships as `<pkg>.vendor.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorSidecar {
    /// Exact UTF-8 bytes that the upstream signed.
    pub document: String,
    pub signature: String,
    pub level: Level,
    pub key_id: String,
    pub verified_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub version: String,
    pub published_at: String,
    pub level: Level,
    pub key_id: String,
    pub artifacts: BTreeMap<String, Chosen>,
    pub skipped: Vec<String>,
    pub written: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Chosen {
    pub name: String,
    pub sha256: String,
    pub size: u64,
    pub url: Option<String>,
}

/// Generate a vendor-built package from the vendor's packslip
///
/// Reads vendor.toml beside the PKGBUILD, fetches the vendor's signed
/// release list and picks the newest release older than the minimum
/// release age (or --version), fetches and verifies that release's
/// packslip against the pinned key, enforces the evidence floor and
/// no-downgrade against vendor.lock, then rewrites pkgver, pkgrel and the
/// checksum arrays in the PKGBUILD and writes <pkgbase>.vendor.json for
/// the built package to ship. Without --write it reports what it would do.
#[derive(Debug, usage_rs::Args)]
pub struct Vendor {
    /// The package directory holding PKGBUILD and vendor.toml
    #[usage(short = 'p', long, default = ".", value_hint = usage_rs::ValueHint::DirPath)]
    pkgdir: PathBuf,
    /// Use this release instead of the newest eligible one
    #[usage(long)]
    version: Option<String>,
    /// Accept a lower evidence level than vendor.lock records
    #[usage(long)]
    allow_downgrade: bool,
    /// Apply the changes
    #[usage(short = 'w', long)]
    write: bool,
    /// Print the report as JSON
    #[usage(short = 'J', long)]
    json: bool,
}

impl RunWith<()> for Vendor {
    type Output = Result<()>;

    fn run_with(self, _: ()) -> Self::Output {
        let config_path = self.pkgdir.join("vendor.toml");
        let config: VendorToml = toml::from_str(
            &std::fs::read_to_string(&config_path)
                .wrap_err_with(|| format!("reading {}", config_path.display()))?,
        )
        .wrap_err_with(|| format!("parsing {}", config_path.display()))?;
        if config.artifacts.is_empty() {
            bail!(
                "{} must declare at least one [artifacts] selector",
                config_path.display()
            );
        }
        let pubkey = load_pubkey(&self.pkgdir, &config.upstream.pubkey)?;
        let now = now()?;
        let min_age = match &config.upstream.min_release_age {
            Some(age) => parse_age(age)?,
            None => Duration::ZERO,
        };
        let floor = config.upstream.provenance_floor.unwrap_or(Level::L2);

        // The release list, signed with the same key.
        let list_bytes = fetch(&config.upstream.releases)?;
        let list_sig = fetch_text(&format!("{}.minisig", config.upstream.releases))?;
        let sig = packslip::minisign::Sig::parse(&list_sig)?;
        pubkey
            .verify(&list_bytes, &sig)
            .wrap_err("release list signature")?;
        let releases: Releases =
            serde_json::from_slice(&list_bytes).wrap_err("parsing the release list")?;
        if releases.project != config.upstream.project {
            bail!(
                "release list is for {}, vendor.toml says {}",
                releases.project,
                config.upstream.project
            );
        }
        let (chosen, skipped) = choose(&releases, self.version.as_deref(), now, min_age)?;

        // The packslip.
        let document = fetch(&chosen.packslip)?;
        let signature = fetch_text(&format!("{}.minisig", chosen.packslip))?;
        let verified = packslip::verify::verify(&document, &signature, &pubkey, &[])?;
        let statement: Statement = serde_json::from_slice(&document)?;
        if verified.project != config.upstream.project {
            bail!(
                "packslip is for {}, vendor.toml says {}",
                verified.project,
                config.upstream.project
            );
        }
        if verified.version != chosen.version {
            bail!(
                "packslip says version {}, the release list said {}",
                verified.version,
                chosen.version
            );
        }
        if verified.level < floor {
            bail!(
                "release {} has evidence level {}, below the floor {floor}",
                chosen.version,
                verified.level
            );
        }
        let lock_path = self.pkgdir.join("vendor.lock");
        if let Some(previous) = read_lock(&lock_path)? {
            if verified.level < previous.level && !self.allow_downgrade {
                bail!(
                    "release {} has evidence level {}, below the {} recorded for {}; pass --allow-downgrade to accept",
                    chosen.version,
                    verified.level,
                    previous.level,
                    previous.version
                );
            }
            if previous.key_id != verified.key_id && !self.allow_downgrade {
                bail!(
                    "packslip signed by {}, vendor.lock recorded {}",
                    verified.key_id,
                    previous.key_id
                );
            }
        }

        // Artifacts per architecture.
        let mut artifacts = BTreeMap::new();
        for (arch, selector) in &config.artifacts {
            let artifact = select(&statement, selector, &chosen.version)
                .wrap_err_with(|| format!("selecting artifact for {arch}"))?;
            let sha256 = statement
                .digest_of(&artifact.name)
                .unwrap_or_default()
                .to_string();
            artifacts.insert(
                arch.clone(),
                Chosen {
                    name: artifact.name.clone(),
                    sha256,
                    size: artifact.size,
                    url: artifact.url.clone(),
                },
            );
        }

        let report = Report {
            version: chosen.version.clone(),
            published_at: chosen.published_at.clone(),
            level: verified.level,
            key_id: verified.key_id.clone(),
            artifacts,
            skipped,
            written: self.write,
        };
        if self.write {
            let pkgbuild_path = self.pkgdir.join("PKGBUILD");
            let pkgbuild = std::fs::read_to_string(&pkgbuild_path)
                .wrap_err_with(|| format!("reading {}", pkgbuild_path.display()))?;
            let updated = rewrite_pkgbuild(&pkgbuild, &report)?;
            let pkgbase = pkgbase_of(&pkgbuild).unwrap_or_else(|| "package".to_string());
            let sidecar_path = self.pkgdir.join(format!("{pkgbase}.vendor.json"));
            let sidecar = VendorSidecar {
                document: String::from_utf8(document.clone()).wrap_err("packslip is not UTF-8")?,
                signature,
                level: verified.level,
                key_id: verified.key_id.clone(),
                verified_at: now.to_string(),
            };
            let lock = VendorLock {
                version: chosen.version.clone(),
                level: verified.level,
                published_at: chosen.published_at.clone(),
                key_id: verified.key_id.clone(),
                generated_at: now.to_string(),
            };
            // Commit the protective lock first and PKGBUILD last. A crash or
            // later write failure can leave stricter evidence state behind,
            // but never new package contents without their no-downgrade lock.
            write_atomic(&lock_path, toml::to_string_pretty(&lock)?.as_bytes())?;
            write_atomic(&sidecar_path, &serde_json::to_vec_pretty(&sidecar)?)?;
            write_atomic(&pkgbuild_path, updated.as_bytes())?;
        }
        if self.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!(
                "{} {} (published {}, evidence {}, key {})",
                if self.write {
                    "generated"
                } else {
                    "would generate"
                },
                report.version,
                report.published_at,
                report.level,
                report.key_id
            );
            for (arch, chosen) in &report.artifacts {
                println!("  {arch}: {} sha256 {}", chosen.name, chosen.sha256);
            }
            for s in &report.skipped {
                println!("  skipped {s}");
            }
        }
        Ok(())
    }
}

fn now() -> Result<jiff::Timestamp> {
    match std::env::var("OMAPAC_REPO_NOW") {
        Ok(fixed) => jiff::Timestamp::from_str(&fixed).wrap_err("OMAPAC_REPO_NOW"),
        Err(_) => Ok(jiff::Timestamp::now()),
    }
}

/// `24h`, `7d`, `30m`, `0`.
pub fn parse_age(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s == "0" {
        return Ok(Duration::ZERO);
    }
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (number, unit) = s.split_at(split);
    let number: u64 = number.parse().wrap_err_with(|| format!("age {s:?}"))?;
    let seconds = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        "w" => 7 * 86_400,
        _ => bail!("age {s:?}: expected a unit of s, m, h, d or w"),
    };
    Ok(Duration::from_secs(number * seconds))
}

fn load_pubkey(pkgdir: &Path, spec: &str) -> Result<PublicKey> {
    let candidate = pkgdir.join(spec);
    let text = if candidate.is_file() {
        std::fs::read_to_string(&candidate)?
    } else {
        spec.to_string()
    };
    PublicKey::parse(&text).map_err(|e| eyre::eyre!("vendor.toml pubkey: {e}"))
}

fn fetch(url: &str) -> Result<Vec<u8>> {
    let mut response = ureq::get(url)
        .call()
        .wrap_err_with(|| format!("fetching {url}"))?;
    let bytes = response
        .body_mut()
        .with_config()
        .limit(64 * 1024 * 1024)
        .read_to_vec()
        .wrap_err_with(|| format!("reading {url}"))?;
    Ok(bytes)
}

fn fetch_text(url: &str) -> Result<String> {
    String::from_utf8(fetch(url)?).wrap_err_with(|| format!("{url} is not UTF-8"))
}

/// Pick the release: the requested version, or the newest by publish time
/// that is at least `min_age` old. Returns what was skipped and why.
pub fn choose(
    releases: &Releases,
    requested: Option<&str>,
    now: jiff::Timestamp,
    min_age: Duration,
) -> Result<(ReleaseRef, Vec<String>)> {
    if let Some(version) = requested {
        return releases
            .releases
            .iter()
            .find(|r| r.version == version)
            .cloned()
            .map(|r| (r, Vec::new()))
            .ok_or_else(|| eyre::eyre!("release {version} is not in the release list"));
    }
    let mut dated: Vec<(jiff::Timestamp, &ReleaseRef)> = Vec::new();
    for r in &releases.releases {
        let at = jiff::Timestamp::from_str(&r.published_at)
            .wrap_err_with(|| format!("release {}: published_at", r.version))?;
        dated.push((at, r));
    }
    dated.sort_by_key(|(at, _)| std::cmp::Reverse(*at));
    let mut skipped = Vec::new();
    for (at, r) in dated {
        let age = now.since(at).map(|s| s.get_seconds()).unwrap_or(0);
        if age < 0 || Duration::from_secs(age.unsigned_abs()) < min_age {
            skipped.push(format!(
                "{} (published {}, younger than the minimum release age)",
                r.version, r.published_at
            ));
            continue;
        }
        return Ok((r.clone(), skipped));
    }
    bail!("no release is old enough; skipped: {}", skipped.join(", "))
}

fn select<'a>(
    statement: &'a Statement,
    selector: &Selector,
    version: &str,
) -> Result<&'a packslip::model::Artifact> {
    let matches: Vec<_> = statement
        .predicate
        .artifacts
        .iter()
        .filter(|a| {
            if let Some(name) = &selector.name {
                return a.name == name.replace("{version}", version);
            }
            let want = |sel: &Option<String>, have: &Option<String>| match sel {
                Some(s) => have.as_deref() == Some(s.as_str()),
                None => true,
            };
            want(&selector.os, &a.os)
                && want(&selector.arch, &a.arch)
                && want(&selector.libc, &a.libc)
        })
        .collect();
    match matches.as_slice() {
        [artifact] => Ok(*artifact),
        [] => bail!("no artifact in release {version} matches the selector"),
        _ => bail!(
            "{} artifacts in release {version} match the selector; add an exact name or format-specific selector",
            matches.len()
        ),
    }
}

fn read_lock(path: &Path) -> Result<Option<VendorLock>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(toml::from_str(&text).wrap_err("parsing vendor.lock")?)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).wrap_err("reading vendor.lock"),
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    let parent = path
        .parent()
        .ok_or_else(|| eyre::eyre!("{} has no parent", path.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("vendor");
    let (temporary, mut file) = loop {
        let nonce = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".{name}.tmp-{}-{nonce}", std::process::id()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => break (temporary, file),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err).wrap_err_with(|| format!("writing {}", path.display())),
        }
    };
    if let Err(err) = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::rename(&temporary, path))
    {
        let _ = std::fs::remove_file(&temporary);
        return Err(err).wrap_err_with(|| format!("writing {}", path.display()));
    }
    Ok(())
}

fn pkgbase_of(pkgbuild: &str) -> Option<String> {
    let value = |key: &str| {
        assignment_first_value(pkgbuild, key).filter(|name| {
            name.bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && name.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'@' | b'.' | b'_' | b'+' | b'-')
                })
        })
    };
    value("pkgbase").or_else(|| value("pkgname"))
}

fn assignment_first_value(text: &str, key: &str) -> Option<String> {
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let Some(mut value) = line
            .trim()
            .strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
        else {
            continue;
        };
        loop {
            let candidate = value
                .trim_start()
                .strip_prefix('(')
                .unwrap_or(value)
                .trim_start();
            if let Some(quote) = candidate.chars().next().filter(|c| matches!(c, '\'' | '"')) {
                return candidate[quote.len_utf8()..]
                    .split_once(quote)
                    .map(|(word, _)| word.to_string());
            }
            let word: String = candidate
                .chars()
                .take_while(|c| !c.is_whitespace() && !matches!(c, ')' | '#'))
                .collect();
            if !word.is_empty() {
                return Some(word);
            }
            value = lines.next()?;
        }
    }
    None
}

/// Rewrite `pkgver`, `pkgrel`, and the checksum arrays. Arrays are
/// matched per architecture (`sha256sums_x86_64=(...)`) with a plain
/// `sha256sums=(...)` used when only one architecture is configured.
pub fn rewrite_pkgbuild(pkgbuild: &str, report: &Report) -> Result<String> {
    validate_pkgver(&report.version)?;
    for chosen in report.artifacts.values() {
        validate_sha256(&chosen.sha256)?;
    }
    let mut out = String::with_capacity(pkgbuild.len());
    let mut lines = pkgbuild.lines().peekable();
    let mut replaced_sums = Vec::new();
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("pkgver=") {
            let _ = rest;
            out.push_str(&format!("pkgver={}\n", report.version));
            continue;
        }
        if trimmed.starts_with("pkgrel=") {
            out.push_str("pkgrel=1\n");
            continue;
        }
        let sums_for = |name: &str| -> Option<&Chosen> {
            let arch = name.strip_prefix("sha256sums_")?;
            report.artifacts.get(arch)
        };
        let key = trimmed.split('=').next().unwrap_or_default();
        let chosen = if key == "sha256sums" && report.artifacts.len() == 1 {
            report.artifacts.values().next()
        } else {
            sums_for(key)
        };
        if let Some(chosen) = chosen
            && trimmed[key.len()..].starts_with("=(")
        {
            // Skip the rest of a multi-line array.
            let mut closed = shell_array_closed(line);
            while !closed {
                match lines.next() {
                    Some(next) => closed = shell_array_closed(next),
                    None => bail!("unterminated array {key} in PKGBUILD"),
                }
            }
            out.push_str(&format!("{key}=('{}')\n", chosen.sha256));
            replaced_sums.push(key.to_string());
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    let missing: Vec<String> =
        if report.artifacts.len() == 1 && replaced_sums.iter().any(|k| k == "sha256sums") {
            Vec::new()
        } else {
            report
                .artifacts
                .keys()
                .map(|arch| format!("sha256sums_{arch}"))
                .filter(|key| !replaced_sums.contains(key))
                .collect()
        };
    if !missing.is_empty() {
        bail!(
            "PKGBUILD is missing checksum array(s): {}",
            missing.join(", ")
        );
    }
    Ok(out)
}

/// Whether a shell assignment line closes an array outside quotes or a comment.
fn shell_array_closed(text: &str) -> bool {
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    for byte in text.bytes() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if !single => escaped = true,
            b'\'' if !double => single = !single,
            b'"' if !single => double = !double,
            b'#' if !single && !double => break,
            b')' if !single && !double => return true,
            _ => {}
        }
    }
    false
}

fn validate_pkgver(version: &str) -> Result<()> {
    if version.is_empty()
        || version.starts_with('.')
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+'))
    {
        bail!("release version {version:?} is not a safe Arch pkgver");
    }
    Ok(())
}

fn validate_sha256(digest: &str) -> Result<()> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("sha256 {digest:?} must be 64 lowercase hex characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(artifacts: &[(&str, &str)]) -> Report {
        Report {
            version: "2.0.0".into(),
            published_at: "2026-09-01T00:00:00Z".into(),
            level: Level::L2,
            key_id: "k".into(),
            artifacts: artifacts
                .iter()
                .map(|(arch, sha)| {
                    (
                        arch.to_string(),
                        Chosen {
                            name: format!("tool-{arch}.tar.gz"),
                            sha256: sha.to_string(),
                            size: 1,
                            url: None,
                        },
                    )
                })
                .collect(),
            skipped: Vec::new(),
            written: false,
        }
    }

    #[test]
    fn rewrites_version_and_sums() {
        let pkgbuild = "pkgname=tool-bin\npkgver=1.0.0\npkgrel=3\nsource_x86_64=(\"https://x/tool-x86_64.tar.gz\")\nsha256sums_x86_64=('old')\nsha256sums_aarch64=(\n  'old2'\n)\npackage() { :; }\n";
        let aa = "a".repeat(64);
        let bb = "b".repeat(64);
        let out =
            rewrite_pkgbuild(pkgbuild, &report(&[("x86_64", &aa), ("aarch64", &bb)])).unwrap();
        assert_eq!(
            out,
            format!(
                "pkgname=tool-bin\npkgver=2.0.0\npkgrel=1\nsource_x86_64=(\"https://x/tool-x86_64.tar.gz\")\nsha256sums_x86_64=('{aa}')\nsha256sums_aarch64=('{bb}')\npackage() {{ :; }}\n"
            )
        );
        let plain = "pkgver=1\npkgrel=1\nsha256sums=('old')\n";
        let cc = "c".repeat(64);
        let out = rewrite_pkgbuild(plain, &report(&[("x86_64", &cc)])).unwrap();
        assert!(out.contains(&format!("sha256sums=('{cc}')")), "{out}");
        assert!(rewrite_pkgbuild("pkgver=1\n", &report(&[("x86_64", &cc)])).is_err());

        let commented = "pkgver=1\npkgrel=1\nsha256sums=( # generated by update()\n  'old'\n)\npackage() { :; }\n";
        let out = rewrite_pkgbuild(commented, &report(&[("x86_64", &cc)])).unwrap();
        assert_eq!(
            out,
            format!("pkgver=2.0.0\npkgrel=1\nsha256sums=('{cc}')\npackage() {{ :; }}\n")
        );
    }

    #[test]
    fn package_base_reads_scalar_and_array_assignments() {
        assert_eq!(
            pkgbase_of("pkgbase='tools'\npkgname=x\n").as_deref(),
            Some("tools")
        );
        assert_eq!(
            pkgbase_of("pkgname=('tool-bin')\n").as_deref(),
            Some("tool-bin")
        );
        assert_eq!(
            pkgbase_of("pkgname=(\n  \"tool-bin\"\n  tool-docs\n)\n").as_deref(),
            Some("tool-bin")
        );
        assert_eq!(pkgbase_of("pkgname=../../escape\n"), None);
    }

    #[test]
    fn rejects_unsafe_pkgver() {
        let pkgbuild = "pkgver=1\npkgrel=1\nsha256sums=('old')\n";
        let checksum = "c".repeat(64);
        for version in [
            "",
            ".1",
            "1-rc1",
            "1\nprepare() { :; }",
            "$(touch /tmp/pwn)",
            "1;false",
        ] {
            let mut report = report(&[("x86_64", &checksum)]);
            report.version = version.into();
            assert!(rewrite_pkgbuild(pkgbuild, &report).is_err(), "{version:?}");
        }
        let mut report = report(&[("x86_64", &checksum)]);
        report.version = "v2.0_rc1+build.4".into();
        rewrite_pkgbuild(pkgbuild, &report).unwrap();
    }

    #[test]
    fn rejects_unsafe_sha256_before_rewriting_pkgbuild() {
        let report = report(&[("x86_64", "abc'); touch /tmp/pwn; echo '")]);
        assert!(rewrite_pkgbuild("pkgver=1\npkgrel=1\nsha256sums=('old')\n", &report).is_err());
    }

    #[test]
    fn chooses_the_newest_old_enough_release() {
        let releases = Releases {
            project: "pkg:github/x/y".into(),
            releases: vec![
                ReleaseRef {
                    version: "1".into(),
                    published_at: "2026-08-01T00:00:00Z".into(),
                    packslip: "a".into(),
                },
                ReleaseRef {
                    version: "3".into(),
                    published_at: "2026-09-02T23:00:00Z".into(),
                    packslip: "c".into(),
                },
                ReleaseRef {
                    version: "2".into(),
                    published_at: "2026-08-20T00:00:00Z".into(),
                    packslip: "b".into(),
                },
            ],
        };
        let now = jiff::Timestamp::from_str("2026-09-03T00:00:00Z").unwrap();
        let (chosen, skipped) = choose(&releases, None, now, parse_age("24h").unwrap()).unwrap();
        assert_eq!(chosen.version, "2");
        assert_eq!(skipped.len(), 1);
        let (chosen, _) = choose(&releases, None, now, Duration::ZERO).unwrap();
        assert_eq!(chosen.version, "3");
        let (chosen, _) = choose(&releases, Some("1"), now, parse_age("7d").unwrap()).unwrap();
        assert_eq!(chosen.version, "1");
        assert!(choose(&releases, Some("9"), now, Duration::ZERO).is_err());
        assert!(choose(&releases, None, now, parse_age("1w").unwrap() * 10).is_err());
    }

    #[test]
    fn ages() {
        assert_eq!(parse_age("0").unwrap(), Duration::ZERO);
        assert_eq!(parse_age("36h").unwrap(), Duration::from_secs(36 * 3600));
        assert!(parse_age("3x").is_err());
    }
}
