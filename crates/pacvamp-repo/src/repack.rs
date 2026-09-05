//! `pacvamp-repo repack`: a repository-signed packslip for a vendor that
//! publishes none. The repository's bump hooks already verify whatever the
//! vendor offers (an apt index signed with the vendor's GPG key, a
//! checksum file over TLS) and write the artifact URLs and digests into
//! the PKGBUILD. This command downloads those artifacts, checks them
//! against the PKGBUILD, and signs a packslip marked `attested_by:
//! repackager` that says what was checked, so clients see one document
//! shape whether or not the vendor took part. See
//! `docs/spec/vendor-pipeline.md`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use eyre::{Context as _, Result, bail};
use packslip::create::{ArtifactInput, Request};
use packslip::minisign::SecretKey;
use packslip::model::{Attestor, Evidence};
use packslip::sigstore::Signer;
use pacvamp::aur::srcinfo::{Source, SrcInfo};
use usage_rs::RunWith;

use crate::vendor::{
    Chosen, Report, VendorLock, VendorSidecar, VendorToml, check_no_downgrade, level_for, now,
    pkgbase_of, read_lock,
};

/// Sign a packslip about a vendor's artifacts on the vendor's behalf
///
/// For a package whose vendor publishes no packslip. Reads the PKGBUILD's
/// sources and checksums (from .SRCINFO, or `makepkg --printsrcinfo`),
/// downloads every remote source, refuses any digest mismatch, and writes
/// <pkgbase>.vendor.json holding a packslip signed with the repository's
/// repackager key, marked attested_by repackager and listing the evidence
/// declared in vendor.toml's [attest] table plus the PKGBUILD checksums
/// themselves. Also writes vendor.lock. The key is a dedicated one: never
/// the build key, whose meaning is "this host built this package file".
#[derive(Debug, usage_rs::Args)]
pub struct Repack {
    /// The package directory holding PKGBUILD and vendor.toml
    #[usage(short = 'p', long, default = ".", value_hint = usage_rs::ValueHint::DirPath)]
    pkgdir: PathBuf,
    /// The repackager secret key (from `packslip keygen`)
    #[usage(short = 'k', long, value_hint = usage_rs::ValueHint::FilePath)]
    key: PathBuf,
    /// Do not record the signature in Rekor
    #[usage(long)]
    no_log: bool,
    /// A .SRCINFO to read instead of <pkgdir>/.SRCINFO or makepkg's output
    #[usage(long, value_hint = usage_rs::ValueHint::FilePath)]
    srcinfo: Option<PathBuf>,
    /// Where downloaded sources go; defaults to <pkgdir>/.repack
    #[usage(long, value_hint = usage_rs::ValueHint::DirPath)]
    cache: Option<PathBuf>,
    /// Accept a lower evidence level or a different signer than
    /// vendor.lock records
    #[usage(long)]
    allow_downgrade: bool,
    /// Print the report as JSON
    #[usage(short = 'J', long)]
    json: bool,
}

/// The checksums a PKGBUILD may carry for one source, by algorithm.
#[derive(Debug, Default, Clone)]
struct Sums {
    sha256: Option<String>,
    sha512: Option<String>,
    b2: Option<String>,
}

impl Sums {
    fn is_empty(&self) -> bool {
        self.sha256.is_none() && self.sha512.is_none() && self.b2.is_none()
    }

    fn any_skip(&self) -> bool {
        [&self.sha256, &self.sha512, &self.b2]
            .into_iter()
            .flatten()
            .any(|s| s == "SKIP")
    }
}

/// One remote source the package builds from.
#[derive(Debug, Clone)]
struct Upstream {
    /// The pacman architecture, or none for a source shared by all.
    arch: Option<String>,
    filename: String,
    url: String,
    sums: Sums,
}

/// pacman architecture names as packslip spells them.
fn packslip_arch(arch: &str) -> &str {
    match arch {
        "armv7h" => "armv7",
        other => other,
    }
}

/// Pair `source[_arch]` entries with their checksum arrays by index, the
/// way makepkg does.
fn upstreams(srcinfo: &SrcInfo, arch: Option<&str>) -> Result<Vec<Upstream>> {
    let key = |base: &str| match arch {
        Some(a) => format!("{base}_{a}"),
        None => base.to_string(),
    };
    let sources = srcinfo.base.all(&key("source"));
    let mut by_algorithm = BTreeMap::new();
    for algorithm in ["sha256sums", "sha512sums", "b2sums"] {
        let sums = srcinfo.base.all(&key(algorithm));
        if !sums.is_empty() {
            if sums.len() != sources.len() {
                bail!(
                    "{} has {} entries but {} has {}",
                    key(algorithm),
                    sums.len(),
                    key("source"),
                    sources.len()
                );
            }
            by_algorithm.insert(algorithm, sums);
        }
    }
    let mut out = Vec::new();
    for (i, text) in sources.iter().enumerate() {
        let source = Source::parse(text);
        if source.is_local() || source.is_vcs() {
            continue;
        }
        let filename = source.filename.clone().unwrap_or_else(|| {
            source
                .url
                .split(['#', '?'])
                .next()
                .unwrap_or(&source.url)
                .rsplit('/')
                .next()
                .unwrap_or(&source.url)
                .to_string()
        });
        if filename.is_empty()
            || matches!(filename.as_str(), "." | "..")
            || filename.contains(['/', '\\'])
        {
            bail!("source {text:?} has no usable file name; give it one with name::url");
        }
        let pick = |algorithm: &str| by_algorithm.get(algorithm).map(|sums| sums[i].to_string());
        out.push(Upstream {
            arch: arch.map(str::to_string),
            filename,
            url: source.url.clone(),
            sums: Sums {
                sha256: pick("sha256sums"),
                sha512: pick("sha512sums"),
                b2: pick("b2sums"),
            },
        });
    }
    Ok(out)
}

fn read_srcinfo(pkgdir: &Path, explicit: Option<&Path>) -> Result<String> {
    if let Some(path) = explicit {
        return std::fs::read_to_string(path)
            .wrap_err_with(|| format!("reading {}", path.display()));
    }
    let beside = pkgdir.join(".SRCINFO");
    if beside.is_file() {
        return std::fs::read_to_string(&beside)
            .wrap_err_with(|| format!("reading {}", beside.display()));
    }
    let output = std::process::Command::new("makepkg")
        .arg("--printsrcinfo")
        .current_dir(pkgdir)
        .output()
        .wrap_err("running makepkg --printsrcinfo; pass --srcinfo instead")?;
    if !output.status.success() {
        bail!(
            "makepkg --printsrcinfo failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    String::from_utf8(output.stdout).wrap_err("makepkg output is not UTF-8")
}

impl RunWith<()> for Repack {
    type Output = Result<()>;

    fn run_with(self, _: ()) -> Self::Output {
        let config_path = self.pkgdir.join("vendor.toml");
        let config: VendorToml = toml::from_str(
            &std::fs::read_to_string(&config_path)
                .wrap_err_with(|| format!("reading {}", config_path.display()))?,
        )
        .wrap_err_with(|| format!("parsing {}", config_path.display()))?;
        let attest = config.attest.clone().unwrap_or_default();
        let key_text = std::fs::read_to_string(&self.key)
            .wrap_err_with(|| format!("reading {}", self.key.display()))?;
        let key = SecretKey::parse(&key_text)?;
        let signer = Signer::Key {
            key,
            log: !self.no_log,
        };
        let now = now()?;

        let srcinfo_text = read_srcinfo(&self.pkgdir, self.srcinfo.as_deref())?;
        let srcinfo = SrcInfo::parse(&srcinfo_text)?;
        let pkgbase = srcinfo.pkgbase().to_string();
        let Some(pkgver) = srcinfo.base.first("pkgver") else {
            bail!(".SRCINFO has no pkgver");
        };
        let mut arches: Vec<&str> = srcinfo
            .base
            .all("arch")
            .into_iter()
            .filter(|a| *a != "any")
            .collect();
        arches.sort_unstable();
        arches.dedup();

        // Every remote source, shared ones first.
        let mut upstreams = upstreams(&srcinfo, None)?;
        for arch in &arches {
            upstreams.extend(upstreams_for(&srcinfo, arch)?);
        }
        if upstreams.is_empty() {
            bail!("the PKGBUILD has no remote sources to attest");
        }
        let mut unverified = false;
        for u in &upstreams {
            if u.sums.is_empty() || u.sums.any_skip() {
                if !attest.allow_skip {
                    bail!(
                        "{} has no checksum (or SKIP) in the PKGBUILD; nothing to attest. Set [attest] allow_skip = true to record it as unverified",
                        u.filename
                    );
                }
                unverified = true;
            }
        }

        // Download, verify against the PKGBUILD, and describe.
        let cache = self
            .cache
            .clone()
            .unwrap_or_else(|| self.pkgdir.join(".repack"));
        std::fs::create_dir_all(&cache)
            .wrap_err_with(|| format!("creating {}", cache.display()))?;
        let mut files: BTreeMap<String, (PathBuf, Upstream)> = BTreeMap::new();
        for u in &upstreams {
            if let Some((_, other)) = files.get(&u.filename)
                && other.url != u.url
            {
                bail!(
                    "two sources share the file name {}: {} and {}",
                    u.filename,
                    other.url,
                    u.url
                );
            }
            let dest = cache.join(&u.filename);
            let fetched = crate::http::fetch_to_file(&u.url, &dest)?;
            for (algorithm, expected, actual) in [
                ("sha256", &u.sums.sha256, &fetched.sha256),
                ("sha512", &u.sums.sha512, &fetched.sha512),
                ("b2", &u.sums.b2, &fetched.blake2b),
            ] {
                if let Some(expected) = expected
                    && expected != "SKIP"
                    && !expected.eq_ignore_ascii_case(actual)
                {
                    let _ = std::fs::remove_file(&dest);
                    bail!(
                        "{}: {algorithm} is {actual}, the PKGBUILD says {expected}",
                        u.filename
                    );
                }
            }
            files.insert(u.filename.clone(), (dest, u.clone()));
        }

        let mut evidence = attest.evidence.clone();
        evidence.push(Evidence {
            kind: "pkgbuild-checksums".into(),
            detail: None,
        });
        if unverified {
            evidence.push(Evidence {
                kind: "none".into(),
                detail: Some("some sources have no checksum in the PKGBUILD".into()),
            });
        }
        let artifacts = files
            .values()
            .map(|(path, u)| ArtifactInput {
                os: Some("linux"),
                arch: u.arch.as_deref().map(packslip_arch),
                url: Some(u.url.clone()),
                ..ArtifactInput::new(path)
            })
            .collect();
        let created = packslip::create::create(&Request {
            published_at: Some(&now.to_string()),
            artifacts,
            attested_by: Attestor::Repackager,
            evidence: evidence.clone(),
            ..Request::new(&config.upstream.project, pkgver, signer.identity())
        })?;
        let identity = created.statement.predicate.identity.clone();
        let level = level_for(Attestor::Repackager, &evidence, false);

        let lock_path = self.pkgdir.join("vendor.lock");
        let previous = read_lock(&lock_path)?;
        if let Some(previous) = &previous {
            check_no_downgrade(
                previous,
                pkgver,
                level,
                Attestor::Repackager,
                &identity.key_id,
                Some(identity.scheme),
                identity.issuer.as_deref(),
                self.allow_downgrade,
            )?;
        }

        let bundle = packslip::sigstore::sign(signer, &created.document)?;
        let trusted_root = packslip::sigstore::trusted_root(None)?;
        let public_key = SecretKey::parse(&std::fs::read_to_string(&self.key)?)?.public_key();
        let verified = packslip::verify(
            &bundle,
            &packslip::Trust::Key(&public_key),
            packslip::Options {
                require_log: !self.no_log,
                trusted_root: &trusted_root,
            },
            &[],
        )?;
        let mut chosen = BTreeMap::new();
        for artifact in &created.statement.predicate.artifacts {
            let arch = files
                .get(&artifact.name)
                .and_then(|(_, u)| u.arch.clone())
                .unwrap_or_else(|| "any".to_string());
            chosen.insert(
                arch,
                Chosen {
                    name: artifact.name.clone(),
                    sha256: created
                        .statement
                        .digest_of(&artifact.name)
                        .ok_or_else(|| {
                            eyre::eyre!("{} is missing its sha256 digest", artifact.name)
                        })?
                        .to_string(),
                    size: artifact.size,
                    url: artifact.url.clone(),
                },
            );
        }
        let report = Report {
            version: pkgver.to_string(),
            published_at: now.to_string(),
            level,
            scheme: identity.scheme,
            key_id: identity.key_id.clone(),
            attested_by: Attestor::Repackager,
            security: false,
            logged_at: verified.logged_at.clone(),
            artifacts: chosen,
            skipped: Vec::new(),
            written: true,
        };
        let pkgbuild = std::fs::read_to_string(self.pkgdir.join("PKGBUILD")).ok();
        let sidecar_base = pkgbuild
            .as_deref()
            .and_then(pkgbase_of)
            .unwrap_or_else(|| pkgbase.clone());
        let sidecar = VendorSidecar {
            bundle,
            scheme: identity.scheme,
            level,
            key_id: identity.key_id.clone(),
            attested_by: Attestor::Repackager,
            evidence,
            logged_at: verified.logged_at.clone(),
            verified_at: now.to_string(),
        };
        let lock = VendorLock {
            version: pkgver.to_string(),
            level,
            published_at: now.to_string(),
            scheme: Some(identity.scheme),
            issuer: identity.issuer.clone(),
            key_id: identity.key_id.clone(),
            attested_by: Some(Attestor::Repackager),
            list_sequence: previous.and_then(|p| p.list_sequence),
            generated_at: now.to_string(),
        };
        crate::vendor::write_atomic(&lock_path, toml::to_string_pretty(&lock)?.as_bytes())?;
        crate::vendor::write_atomic(
            &self.pkgdir.join(format!("{sidecar_base}.vendor.json")),
            &serde_json::to_vec_pretty(&sidecar)?,
        )?;

        if self.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!(
                "attested {pkgbase} {pkgver} as repackager (evidence {level}, key {}{})",
                report.key_id,
                if self.no_log { ", unlogged" } else { "" }
            );
            for (arch, c) in &report.artifacts {
                println!("  {arch}: {} sha256 {}", c.name, c.sha256);
            }
        }
        Ok(())
    }
}

fn upstreams_for(srcinfo: &SrcInfo, arch: &str) -> Result<Vec<Upstream>> {
    upstreams(srcinfo, Some(arch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairs_sources_with_sums_per_arch() {
        let text = "pkgbase = tool-bin\n\tpkgver = 1.0\n\tpkgrel = 1\n\tarch = x86_64\n\tarch = aarch64\n\tsource = tool.sh\n\tsource = git+https://example.com/tool.git\n\tsha256sums = aaaa\n\tsha256sums = SKIP\n\tsource_x86_64 = tool_1.0_amd64.deb::https://dl.example/pool/tool_1.0_amd64.deb\n\tsha256sums_x86_64 = bbbb\n\tsha512sums_x86_64 = cccc\n\tsource_aarch64 = https://dl.example/pool/tool_1.0_arm64.deb\n\tsha256sums_aarch64 = dddd\n\npkgname = tool-bin\n";
        let srcinfo = SrcInfo::parse(text).unwrap();
        assert!(
            upstreams(&srcinfo, None).unwrap().is_empty(),
            "local and vcs skipped"
        );
        let x64 = upstreams(&srcinfo, Some("x86_64")).unwrap();
        assert_eq!(x64.len(), 1);
        assert_eq!(x64[0].filename, "tool_1.0_amd64.deb");
        assert_eq!(x64[0].sums.sha256.as_deref(), Some("bbbb"));
        assert_eq!(x64[0].sums.sha512.as_deref(), Some("cccc"));
        assert_eq!(x64[0].sums.b2, None);
        let arm = upstreams(&srcinfo, Some("aarch64")).unwrap();
        assert_eq!(arm[0].filename, "tool_1.0_arm64.deb");
        assert!(arm[0].sums.sha512.is_none());
        let bad = SrcInfo::parse(
            "pkgbase = x\n\tpkgver = 1\n\tpkgrel = 1\n\tarch = x86_64\n\tsource_x86_64 = https://a/x\n\tsource_x86_64 = https://a/y\n\tsha256sums_x86_64 = aa\n\npkgname = x\n",
        )
        .unwrap();
        assert!(
            upstreams(&bad, Some("x86_64")).is_err(),
            "array lengths differ"
        );
        assert_eq!(packslip_arch("armv7h"), "armv7");
        assert_eq!(packslip_arch("x86_64"), "x86_64");
    }
}
