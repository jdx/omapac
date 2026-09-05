//! `pacvamp-repo vendor`: the vendor pipeline. A vendor-built package is
//! generated from the vendor's signed packslip, not from a checksum file
//! fetched over TLS. See `docs/spec/vendor-pipeline.md`.

use packslip::verify::Verified;
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use eyre::{Context as _, Result, bail};
use packslip::minisign::PublicKey;
use packslip::model::{
    Attestor, Evidence, PREDICATE_TYPE, ReleaseRef, Scheme, Statement, repository,
};
use packslip::sigstore::Policy;
use packslip::{Options, Trust};
use serde::{Deserialize, Serialize};
use usage_rs::RunWith;

/// Where GitHub's API lives; tests point this at a local server.
pub(crate) const GITHUB_API_ENV: &str = "PACVAMP_REPO_GITHUB_API";

/// What a release asset must look like to be a packslip: the repository's
/// own `packslip.sigstore.json`, or `packslip.<tool>.sigstore.json` for a
/// tool in a monorepo. The file name is never trusted; the statement's
/// `project` decides.
fn is_bundle_name(name: &str) -> bool {
    name.starts_with("packslip") && name.ends_with(".sigstore.json")
}

/// `vendor.toml` beside the PKGBUILD.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VendorToml {
    pub upstream: Upstream,
    /// pacman architecture → how to pick the artifact.
    #[serde(default)]
    pub artifacts: BTreeMap<String, Selector>,
    /// For `pacvamp-repo repack`: what the repository checked about a
    /// vendor that publishes no packslip.
    #[serde(default)]
    pub attest: Option<Attest>,
    #[serde(default)]
    pub tool: Option<ToolToml>,
}

/// The `[attest]` table: evidence the repository's bump hooks verified,
/// recorded in the repackager-signed packslip.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attest {
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    /// Accept `SKIP` checksums in the PKGBUILD. Off by default.
    #[serde(default)]
    pub allow_skip: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// The project's name (`github.com/owner/repo`, `tool.example.com`),
    /// which the packslip must name.
    pub project: String,
    /// The signed release list (`.well-known/packslip/<path>.json`). A
    /// github.com project needs none: its releases come from GitHub's API.
    #[serde(default)]
    pub releases: Option<String>,
    /// The pinned public key: its base64 line, or a file path relative to
    /// the package directory. For the sigstore-key scheme.
    #[serde(default)]
    pub pubkey: Option<String>,
    /// The exact certificate identity a keyless signer must have.
    #[serde(default)]
    pub identity: Option<String>,
    /// A prefix the certificate identity must start with.
    #[serde(default)]
    pub identity_prefix: Option<String>,
    /// The OIDC issuer a keyless signer must have.
    #[serde(default)]
    pub issuer: Option<String>,
    /// Accept bundles without a transparency log entry. A reviewed,
    /// per-vendor decision; off by default.
    #[serde(default)]
    pub allow_unlogged: bool,
    /// Consider prereleases. Off by default.
    #[serde(default)]
    pub prerelease: bool,
    /// Skip releases younger than this.
    #[serde(default)]
    pub min_release_age: Option<String>,
    /// The lowest evidence level accepted.
    #[serde(default)]
    pub provenance_floor: Option<Level>,
}

pub use pacvamp_policy::Level;

/// What the package pinned: a key, or an identity policy. A github.com or
/// gitlab.com project pins nothing explicitly; the name implies the policy.
enum Pin {
    Key(PublicKey),
    Identity(Policy),
}

impl Pin {
    fn resolve(pkgdir: &Path, upstream: &Upstream) -> Result<Pin> {
        let explicit = Policy {
            issuer: upstream.issuer.clone(),
            identity: upstream.identity.clone(),
            identity_prefix: upstream.identity_prefix.clone(),
        };
        match &upstream.pubkey {
            Some(spec) => {
                if !explicit.is_empty() {
                    bail!("vendor.toml sets both pubkey and a sigstore identity; pick one");
                }
                Ok(Pin::Key(load_pubkey(pkgdir, spec)?))
            }
            None if !explicit.is_empty() => Ok(Pin::Identity(explicit)),
            None => match Policy::for_project(&upstream.project) {
                Some(policy) => Ok(Pin::Identity(policy)),
                None => bail!(
                    "vendor.toml needs a pubkey or an identity, identity_prefix, or issuer for {}; only github.com and gitlab.com projects imply one",
                    upstream.project
                ),
            },
        }
    }

    fn trust(&self) -> Trust<'_> {
        match self {
            Pin::Key(key) => Trust::Key(key),
            Pin::Identity(policy) => Trust::Identity(policy),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selector {
    pub os: Option<String>,
    pub arch: Option<String>,
    pub libc: Option<String>,
    /// The artifact's variant, when the vendor ships several builds for
    /// one platform (`fips`, `baseline`).
    pub variant: Option<String>,
    /// Match the artifact name instead, with `{version}` substituted.
    pub name: Option<String>,
}

/// The releases to choose from, however they were listed.
#[derive(Debug, Clone, Default)]
pub struct Releases {
    pub releases: Vec<ReleaseRef>,
    /// The digest each listed packslip must have, by URL, when the list
    /// was signed; GitHub's listing carries none.
    pub digests: BTreeMap<String, String>,
    /// The signed list's sequence, for no-rollback.
    pub sequence: Option<u64>,
    /// Bundles already fetched while listing, by URL.
    pub bundles: BTreeMap<String, String>,
    pub latest: Option<String>,
}

/// `vendor.lock`: what was last generated, for no-downgrade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VendorLock {
    pub version: String,
    pub level: Level,
    pub published_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<Scheme>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// The certificate identity, or the key id.
    pub key_id: String,
    /// Whether the vendor or the repository (as repackager) made the
    /// claim; absent in locks written before repackager attestation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attested_by: Option<Attestor>,
    /// The last accepted release-list sequence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list_sequence: Option<u64>,
    pub generated_at: String,
}

/// The sidecar the built package ships as `<pkg>.vendor.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorSidecar {
    /// The packslip bundle, byte for byte: the vendor's, or the one the
    /// repository signed as repackager.
    pub bundle: String,
    pub scheme: Scheme,
    pub level: Level,
    pub key_id: String,
    #[serde(default, skip_serializing_if = "Attestor::is_vendor")]
    pub attested_by: Attestor,
    /// What the repackager checked, when it is one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logged_at: Option<String>,
    pub verified_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub version: String,
    pub published_at: String,
    pub level: Level,
    pub scheme: Scheme,
    pub key_id: String,
    pub attested_by: Attestor,
    /// The release list marked this release a security fix.
    pub security: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logged_at: Option<String>,
    pub artifacts: BTreeMap<String, Chosen>,
    pub skipped: Vec<String>,
    pub written: bool,
}

/// The repository's level for a verified document: a vendor packslip is
/// L2, L3 when every artifact links provenance; a repackager packslip is
/// L1 when the repackager checked a signature the vendor made, else L0.
pub(crate) fn level_for(
    attested_by: Attestor,
    evidence: &[Evidence],
    provenance_linked: bool,
) -> Level {
    match attested_by {
        Attestor::Vendor if provenance_linked => Level::L3,
        Attestor::Vendor => Level::L2,
        Attestor::Repackager if evidence.iter().any(|e| is_signature_evidence(&e.kind)) => {
            Level::L1
        }
        Attestor::Repackager => Level::L0,
    }
}

/// Evidence kinds that mean the vendor signed something the repackager
/// verified, as opposed to a checksum fetched over TLS.
pub(crate) fn is_signature_evidence(kind: &str) -> bool {
    matches!(
        kind,
        "apt-release-gpg" | "vendor-signature" | "github-attestation"
    )
}

/// The no-downgrade rules shared by `vendor` and `repack`: the level may
/// not fall, and the signer may not change, unless a human allows it.
/// Moving from a repackager document to the vendor's own is an upgrade
/// and changes the signer by nature.
#[allow(clippy::too_many_arguments)]
pub(crate) fn check_no_downgrade(
    previous: &VendorLock,
    version: &str,
    level: Level,
    attested_by: Attestor,
    key_id: &str,
    scheme: Option<Scheme>,
    issuer: Option<&str>,
    allow_downgrade: bool,
) -> Result<()> {
    if allow_downgrade {
        return Ok(());
    }
    let previous_attestor = previous.attested_by.unwrap_or_default();
    if previous_attestor == Attestor::Vendor && attested_by == Attestor::Repackager {
        bail!(
            "release {version} is repackager-attested, but vendor.lock records the vendor's own packslip for {}; pass --allow-downgrade to accept",
            previous.version
        );
    }
    if level < previous.level {
        bail!(
            "release {version} has evidence level {level}, below the {} recorded for {}; pass --allow-downgrade to accept",
            previous.level,
            previous.version
        );
    }
    let signer_changed = signer_stem(&previous.key_id, previous.issuer.as_deref())
        != signer_stem(key_id, issuer)
        || previous.scheme.is_some_and(|old| Some(old) != scheme)
        || previous.issuer.as_deref() != issuer;
    let upgraded = previous_attestor == Attestor::Repackager && attested_by == Attestor::Vendor;
    if signer_changed && !upgraded {
        bail!(
            "packslip signed by {key_id}, vendor.lock recorded {}",
            previous.key_id
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct Chosen {
    pub name: String,
    pub sha256: String,
    pub size: u64,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolToml {
    /// The tool name mise sees.
    pub name: String,
}

/// A vendor release resolved and verified against the pinned identity.
pub struct Resolved {
    pub chosen: ReleaseRef,
    pub bundle: String,
    pub statement: Statement,
    pub level: Level,
    pub list_sequence: Option<u64>,
    pub verified: Verified,
    pub skipped: Vec<String>,
    /// One artifact per configured key.
    pub artifacts: BTreeMap<String, Chosen>,
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
        let config = load_config(&config_path)?;
        if config.artifacts.is_empty() {
            bail!(
                "{} must declare at least one [artifacts] selector",
                config_path.display()
            );
        }
        let now = now()?;
        let lock_path = self.pkgdir.join("vendor.lock");
        let previous = read_lock(&lock_path)?;
        let resolved = resolve(
            &config,
            &self.pkgdir,
            self.version.as_deref(),
            now,
            previous.as_ref(),
            self.allow_downgrade,
        )?;
        let report = Report {
            version: resolved.chosen.version.clone(),
            published_at: resolved.chosen.published_at.clone(),
            level: resolved.level,
            key_id: resolved.verified.key_id.clone(),
            scheme: resolved.verified.scheme,
            attested_by: resolved.verified.attested_by,
            security: resolved.chosen.security,
            logged_at: resolved.verified.logged_at.clone(),
            artifacts: resolved.artifacts.clone(),
            skipped: resolved.skipped.clone(),
            written: self.write,
        };
        if self.write {
            let pkgbuild_path = self.pkgdir.join("PKGBUILD");
            let pkgbuild = std::fs::read_to_string(&pkgbuild_path)
                .wrap_err_with(|| format!("reading {}", pkgbuild_path.display()))?;
            let updated = rewrite_pkgbuild(&pkgbuild, &report)?;
            let pkgbase = pkgbase_of(&pkgbuild).unwrap_or_else(|| "package".to_string());
            let sidecar_path = self.pkgdir.join(format!("{pkgbase}.vendor.json"));
            let sidecar = sidecar(&resolved, now)?;
            let lock = VendorLock {
                version: resolved.chosen.version.clone(),
                level: resolved.level,
                published_at: resolved.chosen.published_at.clone(),
                key_id: resolved.verified.key_id.clone(),
                scheme: Some(resolved.verified.scheme),
                issuer: resolved.verified.issuer.clone(),
                attested_by: Some(resolved.verified.attested_by),
                list_sequence: resolved.list_sequence,
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
                "{} {} (published {}, evidence {}, {} {})",
                if self.write {
                    "generated"
                } else {
                    "would generate"
                },
                report.version,
                report.published_at,
                report.level,
                match report.scheme {
                    Scheme::SigstoreKey => "key",
                    Scheme::SigstoreOidc => "identity",
                },
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

pub fn load_config(path: &Path) -> Result<VendorToml> {
    toml::from_str(
        &std::fs::read_to_string(path).wrap_err_with(|| format!("reading {}", path.display()))?,
    )
    .wrap_err_with(|| format!("parsing {}", path.display()))
}

/// The sidecar for a resolved release.
pub fn sidecar(resolved: &Resolved, now: jiff::Timestamp) -> Result<VendorSidecar> {
    Ok(VendorSidecar {
        bundle: resolved.bundle.clone(),
        scheme: resolved.verified.scheme,
        attested_by: resolved.verified.attested_by,
        evidence: resolved.statement.predicate.evidence.clone(),
        logged_at: resolved.verified.logged_at.clone(),
        level: resolved.level,
        key_id: resolved.verified.key_id.clone(),
        verified_at: now.to_string(),
    })
}

/// Fetch the release list and the chosen release's packslip, verify both
/// against the pinned key, enforce the floor and no-downgrade, and pick
/// one artifact per configured selector.
pub fn resolve(
    config: &VendorToml,
    dir: &Path,
    requested: Option<&str>,
    now: jiff::Timestamp,
    previous: Option<&VendorLock>,
    allow_downgrade: bool,
) -> Result<Resolved> {
    let pin = Pin::resolve(dir, &config.upstream)?;
    let min_age = match &config.upstream.min_release_age {
        Some(age) => parse_age(age)?,
        None => Duration::ZERO,
    };
    let floor = config.upstream.provenance_floor.unwrap_or(Level::L2);
    let trusted_root = packslip::sigstore::trusted_root(None)?;
    let options = Options {
        require_log: !config.upstream.allow_unlogged,
        trusted_root: &trusted_root,
    };

    // The releases: the vendor's signed list, or, for a github.com
    // project without one, what GitHub's API lists.
    let releases = match &config.upstream.releases {
        Some(url) => {
            let list = fetch_release_list(url, &pin, options, &config.upstream.project, now)?;
            if let Some(last) = previous.as_ref().and_then(|p| p.list_sequence)
                && list.sequence.is_some_and(|s| s < last)
                && !allow_downgrade
            {
                bail!(
                    "release list sequence {} is below the {last} recorded in vendor.lock; pass --allow-downgrade to accept",
                    list.sequence.unwrap_or_default()
                );
            }
            list
        }
        None => github_releases(&config.upstream.project, config.upstream.prerelease)?,
    };
    let (chosen, skipped) = choose(
        &releases,
        requested,
        now,
        min_age,
        config.upstream.prerelease,
    )?;

    // The packslip: one bundle, pinned by digest when the list was signed.
    let bundle = match releases.bundles.get(&chosen.packslip) {
        Some(text) => text.clone(),
        None => fetch_text(&chosen.packslip)?,
    };
    if let Some(expected) = releases.digests.get(&chosen.packslip) {
        let actual = sha256_hex(bundle.as_bytes());
        if actual != *expected {
            bail!(
                "{} has sha256 {actual}, the release list says {expected}",
                chosen.packslip
            );
        }
    }
    let verified = packslip::verify(&bundle, &pin.trust(), options, &[])
        .wrap_err_with(|| format!("verifying the packslip against {}", pin.trust().describe()))?;
    let statement: Statement =
        serde_json::from_slice(&packslip::sigstore::peek_statement(&bundle)?)?;
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
    // An unsigned listing only located the document; the signed
    // document is the authority on what it is.
    let version = verified.version.clone();
    let published_at = verified.published_at.clone();
    if verified.prerelease && !config.upstream.prerelease {
        bail!(
            "release {version} is a prerelease; set `prerelease = true` in vendor.toml to accept prereleases"
        );
    }
    let level = level_for(
        verified.attested_by,
        &statement.predicate.evidence,
        verified.provenance_linked,
    );
    if level < floor {
        bail!("release {version} has evidence level {level}, below the floor {floor}");
    }
    if let Some(previous) = &previous {
        check_no_downgrade(
            previous,
            &version,
            level,
            verified.attested_by,
            &verified.key_id,
            Some(verified.scheme),
            verified.issuer.as_deref(),
            allow_downgrade,
        )?;
    }

    // Artifacts per architecture.
    let mut artifacts = BTreeMap::new();
    for (arch, selector) in &config.artifacts {
        let artifact = select(&statement, selector, &version)
            .wrap_err_with(|| format!("selecting artifact for {arch}"))?;
        let sha256 = statement
            .digest_of(&artifact.name)
            .ok_or_else(|| eyre::eyre!("artifact {} is missing its sha256 digest", artifact.name))?
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

    // GitHub timestamps are unsigned; enforce age on the verified timestamp too.
    let published = jiff::Timestamp::from_str(&published_at)?;
    if now.duration_since(published).as_secs() < min_age.as_secs() as i64 {
        bail!("release {version} is younger than min_release_age");
    }
    let mut chosen = chosen;
    chosen.published_at = published_at;
    Ok(Resolved {
        chosen,
        bundle,
        verified,
        statement,
        level,
        list_sequence: releases.sequence.or(previous.and_then(|p| p.list_sequence)),
        skipped,
        artifacts,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

/// Fetch a vendor's release list and verify it: the bundle against the
/// pin, then its expiry.
fn fetch_release_list(
    url: &str,
    pin: &Pin,
    options: Options<'_>,
    project: &str,
    now: jiff::Timestamp,
) -> Result<Releases> {
    let bundle = fetch_text(url)?;
    let verified =
        packslip::verify_release_list(&bundle, &pin.trust(), options).wrap_err_with(|| {
            format!(
                "verifying the release list against {}",
                pin.trust().describe()
            )
        })?;
    let list = verified.list;
    if list.predicate.project != project {
        bail!(
            "release list is for {}, vendor.toml says {}",
            list.predicate.project,
            project
        );
    }
    if !list.is_current(now) {
        bail!(
            "release list expired at {}; the vendor has not republished it",
            list.predicate.expires_at
        );
    }
    let digests = list
        .subject
        .iter()
        .map(|s| (s.name.clone(), s.digest.sha256.clone()))
        .collect();
    Ok(Releases {
        releases: list.predicate.releases.clone(),
        digests,
        sequence: Some(list.predicate.sequence),
        bundles: BTreeMap::new(),
        latest: list.predicate.latest.clone(),
    })
}

/// The releases GitHub lists for a `github.com/owner/repo[/tool]` project
/// that carry a packslip for it. Unsigned: it locates documents, and the
/// verified document is the authority on version and publish time. A
/// release may carry several `packslip*.sigstore.json` assets (one per
/// tool of a monorepo); each is read and kept only when its statement
/// names this project. Drafts, and prereleases unless wanted, are skipped
/// before anything is fetched.
fn github_releases(project: &str, prereleases: bool) -> Result<Releases> {
    let Some(("github.com", owner, repo)) = repository(project) else {
        bail!(
            "{project} needs a release list: set `releases` in vendor.toml to its signed list; only a github.com/owner/repo project is listed by its releases endpoint"
        );
    };
    let api = std::env::var(GITHUB_API_ENV).unwrap_or_else(|_| "https://api.github.com".into());
    let url = format!(
        "{}/repos/{owner}/{repo}/releases?per_page=50",
        api.trim_end_matches('/')
    );
    let entries: Vec<serde_json::Value> =
        serde_json::from_slice(&fetch(&url)?).wrap_err("parsing GitHub's release list")?;
    let mut releases = Releases::default();
    for entry in entries {
        let flag = |name: &str| entry[name].as_bool().unwrap_or(false);
        if flag("draft") || (flag("prerelease") && !prereleases) {
            continue;
        }
        let candidates = entry["assets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|a| a["name"].as_str().is_some_and(is_bundle_name))
            .filter_map(|a| a["browser_download_url"].as_str());
        let mut found = None;
        for candidate in candidates {
            let text = fetch_text(candidate)?;
            let Ok(payload) = packslip::sigstore::peek_statement(&text) else {
                continue;
            };
            let Ok(statement) = serde_json::from_slice::<Statement>(&payload) else {
                continue;
            };
            if statement.predicate_type == PREDICATE_TYPE && statement.predicate.project == project
            {
                found = Some((candidate.to_string(), text, statement));
                break;
            }
        }
        let Some((asset, text, _statement)) = found else {
            continue;
        };
        let tag = entry["tag_name"].as_str().unwrap_or_default();
        releases.releases.push(ReleaseRef {
            version: match packslip::tag_version(tag, project) {
                Some(v) => v,
                None => continue,
            },
            tag: Some(tag.to_string()),
            published_at: entry["published_at"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            packslip: asset.clone(),
            ..ReleaseRef::default()
        });
        releases.bundles.insert(asset, text);
    }
    if releases.releases.is_empty() {
        bail!("{project} has no release with a packslip for it");
    }
    Ok(releases)
}

/// The stable part of a signer id: a key id as is, a certificate identity
/// without its `@ref`, so every tag of one workflow is the same signer.
fn signer_stem<'a>(key_id: &'a str, issuer: Option<&str>) -> &'a str {
    if issuer == Some("https://token.actions.githubusercontent.com")
        && key_id.starts_with("https://github.com/")
        && key_id.contains("/.github/workflows/")
    {
        key_id
            .rsplit_once('@')
            .map(|(workflow, _)| workflow)
            .unwrap_or(key_id)
    } else {
        key_id
    }
}

pub fn now() -> Result<jiff::Timestamp> {
    match std::env::var("PACVAMP_REPO_NOW") {
        Ok(fixed) => jiff::Timestamp::from_str(&fixed).wrap_err("PACVAMP_REPO_NOW"),
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

pub fn load_pubkey(dir: &Path, spec: &str) -> Result<PublicKey> {
    let candidate = dir.join(spec);
    let text = if candidate.is_file() {
        std::fs::read_to_string(&candidate)?
    } else {
        spec.to_string()
    };
    PublicKey::parse(&text).map_err(|e| eyre::eyre!("pubkey: {e}"))
}

/// The pinned key's file text, for publishing in an index.
pub fn pubkey_text(dir: &Path, spec: &str) -> Result<String> {
    Ok(load_pubkey(dir, spec)?.to_file())
}

pub fn fetch(url: &str) -> Result<Vec<u8>> {
    fetch_limited(url, 64 * 1024 * 1024)
}

/// Fetch at most `max_size` bytes. The extra byte distinguishes an exact-size
/// response from an oversized one without buffering the rest of the body.
pub fn fetch_limited(url: &str, max_size: u64) -> Result<Vec<u8>> {
    let setup_timeout = Some(std::time::Duration::from_secs(30));
    let config = ureq::Agent::config_builder()
        .user_agent(concat!("pacvamp-repo/", env!("CARGO_PKG_VERSION")))
        .timeout_resolve(setup_timeout)
        .timeout_connect(setup_timeout)
        .timeout_send_request(setup_timeout)
        .timeout_recv_response(setup_timeout)
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let mut response = agent
        .get(url)
        .call()
        .wrap_err_with(|| format!("fetching {url}"))?;
    let bytes = response
        .body_mut()
        .with_config()
        .limit(max_size.saturating_add(1))
        .read_to_vec()
        .wrap_err_with(|| format!("reading {url}"))?;
    if bytes.len() as u64 > max_size {
        bail!("{url}: response exceeds the {max_size}-byte limit");
    }
    Ok(bytes)
}

fn fetch_text(url: &str) -> Result<String> {
    String::from_utf8(fetch(url)?).wrap_err_with(|| format!("{url} is not UTF-8"))
}

/// Pick the highest eligible semver, honoring the signed recommendation for defaults.
pub fn choose(
    releases: &Releases,
    requested: Option<&str>,
    now: jiff::Timestamp,
    min_age: Duration,
    prereleases: bool,
) -> Result<(ReleaseRef, Vec<String>)> {
    let mut ranked = releases
        .releases
        .iter()
        .map(|r| Ok((packslip::model::parse_version(&r.version)?, r)))
        .collect::<Result<Vec<_>>>()?;
    ranked.sort_by(|a, b| b.0.cmp_precedence(&a.0));
    if requested.is_none()
        && let Some(latest) = &releases.latest
        && let Some(i) = ranked.iter().position(|(_, r)| &r.version == latest)
    {
        let recommended = ranked.remove(i);
        ranked.insert(0, recommended);
    }
    let mut skipped = Vec::new();
    for (version, release) in ranked {
        if let Some(want) = requested {
            let want = want.strip_prefix('v').unwrap_or(want);
            if release.version != want
                && release.tag.as_deref() != requested
                && !release
                    .version
                    .strip_prefix(want)
                    .is_some_and(|rest| rest.starts_with('.'))
            {
                continue;
            }
        }
        let at = jiff::Timestamp::from_str(&release.published_at)?;
        let age = now.duration_since(at);
        let reason = if release.is_yanked() {
            Some("yanked")
        } else if !prereleases && !version.pre.is_empty() {
            Some("prerelease")
        } else if age.is_negative() || age.as_secs() < min_age.as_secs() as i64 {
            Some("younger than the minimum release age")
        } else {
            None
        };
        if let Some(reason) = reason {
            skipped.push(format!("{} ({reason})", release.version));
            continue;
        }
        return Ok((release.clone(), skipped));
    }
    bail!(
        "no eligible release for {}: {}",
        requested.unwrap_or("latest"),
        skipped.join(", ")
    )
}

fn select<'a>(
    statement: &'a Statement,
    selector: &Selector,
    version: &str,
) -> Result<&'a packslip::Artifact> {
    if let Some(name) = &selector.name {
        let name = name.replace("{version}", version);
        return statement
            .predicate
            .artifacts
            .iter()
            .find(|a| a.name == name)
            .ok_or_else(|| eyre::eyre!("no artifact in release {version} matches {name}"));
    }
    let host = packslip::Host {
        os: selector.os.as_deref().unwrap_or("linux"),
        arch: selector
            .arch
            .as_deref()
            .ok_or_else(|| eyre::eyre!("artifact selector needs arch or name"))?,
        libc: selector
            .libc
            .as_deref()
            .or_else(|| (selector.os.as_deref().unwrap_or("linux") == "linux").then_some("gnu")),
    };
    Ok(packslip::select_artifact(
        &statement.predicate.artifacts,
        &host,
        selector.variant.as_deref(),
        &[
            "tar.zst", "tar.xz", "tar.gz", "tar.bz2", "tar", "zip", "raw", "gz", "xz", "zst",
            "bz2", "deb", "rpm", "appimage",
        ],
    )?)
}

pub fn read_lock(path: &Path) -> Result<Option<VendorLock>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(toml::from_str(&text).wrap_err("parsing vendor.lock")?)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).wrap_err("reading vendor.lock"),
    }
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
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

pub(crate) fn pkgbase_of(pkgbuild: &str) -> Option<String> {
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
        if trimmed.starts_with("pkgver=") {
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
            scheme: Scheme::SigstoreKey,
            attested_by: Attestor::Vendor,
            security: false,
            logged_at: None,
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
            releases: vec![
                ReleaseRef {
                    version: "1.0.0".into(),
                    published_at: "2026-08-01T00:00:00Z".into(),
                    packslip: "a".into(),
                    ..ReleaseRef::default()
                },
                ReleaseRef {
                    version: "3.0.0".into(),
                    published_at: "2026-09-02T23:00:00Z".into(),
                    packslip: "c".into(),
                    ..ReleaseRef::default()
                },
                ReleaseRef {
                    version: "2.0.0".into(),
                    published_at: "2026-08-20T00:00:00Z".into(),
                    packslip: "b".into(),
                    ..ReleaseRef::default()
                },
            ],
            ..Releases::default()
        };
        let now = jiff::Timestamp::from_str("2026-09-03T00:00:00Z").unwrap();
        let (chosen, skipped) =
            choose(&releases, None, now, parse_age("24h").unwrap(), false).unwrap();
        assert_eq!(chosen.version, "2.0.0");
        assert_eq!(skipped.len(), 1);
        let (chosen, _) = choose(&releases, None, now, Duration::ZERO, false).unwrap();
        assert_eq!(chosen.version, "3.0.0");
        let (chosen, _) =
            choose(&releases, Some("1"), now, parse_age("7d").unwrap(), false).unwrap();
        assert_eq!(chosen.version, "1.0.0");
        assert!(choose(&releases, Some("9"), now, Duration::ZERO, false).is_err());
        assert!(choose(&releases, None, now, parse_age("1w").unwrap() * 10, false).is_err());
    }

    #[test]
    fn ages() {
        assert_eq!(parse_age("0").unwrap(), Duration::ZERO);
        assert_eq!(parse_age("36h").unwrap(), Duration::from_secs(36 * 3600));
        assert!(parse_age("3x").is_err());
    }

    #[test]
    fn prefix_selection_filters_yanked_prerelease_and_young_versions() {
        let now = jiff::Timestamp::from_str("2026-09-03T00:00:00Z").unwrap();
        let mut releases = Releases::default();
        for version in ["20.4.0", "20.3.0-rc.1", "20.2.0", "20.1.0", "19.9.0"] {
            releases.releases.push(ReleaseRef {
                version: version.into(),
                published_at: "2026-08-01T00:00:00Z".into(),
                ..ReleaseRef::default()
            });
        }
        releases.releases[0].status = Some(packslip::model::ReleaseStatus::Yanked);
        releases.releases[2].published_at = now.to_string();
        let (chosen, skipped) =
            choose(&releases, Some("20"), now, parse_age("24h").unwrap(), false).unwrap();
        assert_eq!(chosen.version, "20.1.0");
        assert_eq!(skipped.len(), 3);
        assert!(choose(&releases, Some("20.4.0"), now, Duration::ZERO, true).is_err());
        releases.latest = Some("19.9.0".into());
        assert_eq!(
            choose(&releases, None, now, Duration::ZERO, false)
                .unwrap()
                .0
                .version,
            "19.9.0"
        );
        // A signed recommendation never bypasses eligibility.
        releases.latest = Some("20.4.0".into());
        assert_eq!(
            choose(&releases, None, now, parse_age("24h").unwrap(), false)
                .unwrap()
                .0
                .version,
            "20.1.0"
        );
    }

    #[test]
    fn no_downgrade_preserves_email_domain_and_oidc_issuer() {
        let previous = VendorLock {
            version: "1.0.0".into(),
            level: Level::L2,
            published_at: String::new(),
            scheme: Some(Scheme::SigstoreOidc),
            issuer: Some("https://issuer.example".into()),
            key_id: "user@example.com".into(),
            attested_by: Some(Attestor::Vendor),
            list_sequence: None,
            generated_at: String::new(),
        };
        let check = |key, issuer| {
            check_no_downgrade(
                &previous,
                "1.1.0",
                Level::L2,
                Attestor::Vendor,
                key,
                Some(Scheme::SigstoreOidc),
                Some(issuer),
                false,
            )
        };
        assert!(check("user@example.com", "https://issuer.example").is_ok());
        assert!(check("user@other.example", "https://issuer.example").is_err());
        assert!(check("user@example.com", "https://other-issuer.example").is_err());
        let issuer = Some("https://token.actions.githubusercontent.com");
        assert_eq!(
            signer_stem(
                "https://github.com/a/b/.github/workflows/release.yml@refs/tags/v1",
                issuer
            ),
            signer_stem(
                "https://github.com/a/b/.github/workflows/release.yml@refs/tags/v2",
                issuer
            ),
        );
    }

    #[test]
    fn non_github_projects_require_a_signed_list() {
        let err = github_releases("gitlab.com/example/tool", false).unwrap_err();
        assert!(err.to_string().contains("only a github.com"), "{err}");
    }
}
