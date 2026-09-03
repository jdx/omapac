//! `omapac-repo tool-channel`: publish vetted vendor tool releases to a
//! mirror with their evidence and a signed index that mise consumes. See
//! `docs/spec/tool-channel.md`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use eyre::{Context as _, Result, bail};
use omapac::trust::feeds::{VerdictKind, Verdicts};
use omapac::trust::tools::{CHANNELS, INDEX_PATH, ToolArtifact, ToolEntry, ToolIndex, ToolVersion};
use packslip::dsse::{Envelope, IN_TOTO_PAYLOAD_TYPE};
use packslip::minisign::SecretKey;
use usage_rs::RunWith;

/// Vet vendor tool releases and publish them for mise
///
/// A tool.toml pins a vendor identity the way vendor.toml does for a
/// package. publish verifies the release, mirrors the artifacts under
/// tools/<tool>/<version>/ with the vendor's packslip and the channel's
/// own provenance beside them, and appends the version to the signed
/// tool index in the edge channel. promote and hold move versions
/// between channels or pull them.
#[derive(Debug, usage_rs::Args)]
pub struct ToolChannel {
    #[usage(subcommand)]
    command: ToolChannelCommands,
    /// The channel store root (the same store the snapshots use)
    #[usage(short = 's', long, global, value_hint = usage_rs::ValueHint::DirPath)]
    store: Option<PathBuf>,
    /// The channel signing key
    #[usage(short = 'k', long, global, value_hint = usage_rs::ValueHint::FilePath)]
    key: Option<PathBuf>,
    /// Print as JSON
    #[usage(short = 'J', long, global)]
    json: bool,
}

#[derive(Debug, usage_rs::Subcommands)]
enum ToolChannelCommands {
    Hold(Hold),
    Promote(Promote),
    Publish(Publish),
    Status(Status),
    Unhold(Unhold),
}

/// Vet a release and publish it to edge
#[derive(Debug, usage_rs::Args)]
pub struct Publish {
    /// The tool.toml describing the vendor and artifacts
    #[usage(short = 'c', long, value_hint = usage_rs::ValueHint::FilePath)]
    config: PathBuf,
    /// Publish this release instead of the newest eligible one
    #[usage(long)]
    version: Option<String>,
    /// Accept a lower evidence level or another key than last time
    #[usage(long)]
    allow_downgrade: bool,
}

/// Add a version to rc or stable
#[derive(Debug, usage_rs::Args)]
pub struct Promote {
    #[usage(long)]
    tool: String,
    #[usage(long)]
    version: String,
    /// rc or stable
    #[usage(long)]
    channel: String,
}

/// Pull a version from every channel
#[derive(Debug, usage_rs::Args)]
pub struct Hold {
    #[usage(long)]
    tool: String,
    #[usage(long)]
    version: String,
    #[usage(long)]
    reason: String,
}

/// Clear a hold
#[derive(Debug, usage_rs::Args)]
pub struct Unhold {
    #[usage(long)]
    tool: String,
    #[usage(long)]
    version: String,
}

/// List tools and versions
#[derive(Debug, usage_rs::Args)]
pub struct Status {}

impl RunWith<()> for ToolChannel {
    type Output = Result<()>;

    fn run_with(self, _: ()) -> Self::Output {
        let Some(store) = &self.store else {
            bail!("--store is required");
        };
        let index_path = store.join(INDEX_PATH);
        let now = crate::vendor::now()?;
        let mut index: ToolIndex =
            crate::feed::load(&index_path)?.unwrap_or_else(|| ToolIndex::empty(&now.to_string()));
        let key = || -> Result<SecretKey> {
            let Some(path) = &self.key else {
                bail!("--key is required");
            };
            crate::feed::secret_key(path)
        };
        match &self.command {
            ToolChannelCommands::Status(_) => {
                if self.json {
                    println!("{}", serde_json::to_string_pretty(&index)?);
                    return Ok(());
                }
                println!("tool index sequence {}", index.sequence);
                for (name, entry) in &index.tools {
                    println!("{name} ({})", entry.project);
                    for (version, v) in index.versions(name, None, true) {
                        println!(
                            "  {version}  published {}  {}  [{}]{}",
                            v.published_at,
                            v.level,
                            v.channels.join(", "),
                            v.held
                                .as_ref()
                                .map(|r| format!("  HELD: {r}"))
                                .unwrap_or_default()
                        );
                    }
                }
                return Ok(());
            }
            ToolChannelCommands::Publish(publish) => {
                let key = key()?;
                let Some(line) = publish_release(store, &mut index, publish, now, &key)? else {
                    println!("tool channel already up to date");
                    return Ok(());
                };
                println!("{line}");
            }
            ToolChannelCommands::Promote(promote) => {
                if !CHANNELS.contains(&promote.channel.as_str()) || promote.channel == "edge" {
                    bail!("--channel must be rc or stable");
                }
                let version = version_mut(&mut index, &promote.tool, &promote.version)?;
                if let Some(reason) = &version.held {
                    bail!("{} {} is held: {reason}", promote.tool, promote.version);
                }
                if !version.channels.contains(&promote.channel) {
                    version.channels.push(promote.channel.clone());
                }
                println!(
                    "{} {} -> {}",
                    promote.tool, promote.version, promote.channel
                );
            }
            ToolChannelCommands::Hold(hold) => {
                let version = version_mut(&mut index, &hold.tool, &hold.version)?;
                version.held = Some(hold.reason.clone());
                println!("held {} {}: {}", hold.tool, hold.version, hold.reason);
            }
            ToolChannelCommands::Unhold(unhold) => {
                let version = version_mut(&mut index, &unhold.tool, &unhold.version)?;
                version.held = None;
                println!("unheld {} {}", unhold.tool, unhold.version);
            }
        }
        let key = key()?;
        index.sequence += 1;
        index.generated_at = now.to_string();
        std::fs::create_dir_all(index_path.parent().unwrap_or(store))?;
        crate::feed::write_signed(
            &index_path,
            &index,
            &key,
            &format!("tool index sequence {}", index.sequence),
        )?;
        println!(
            "wrote {} (sequence {})",
            index_path.display(),
            index.sequence
        );
        Ok(())
    }
}

fn version_mut<'a>(
    index: &'a mut ToolIndex,
    tool: &str,
    version: &str,
) -> Result<&'a mut ToolVersion> {
    index
        .tools
        .get_mut(tool)
        .and_then(|entry| entry.versions.get_mut(version))
        .ok_or_else(|| eyre::eyre!("{tool} {version} is not in the tool index"))
}

fn publish_release(
    store: &Path,
    index: &mut ToolIndex,
    publish: &Publish,
    now: jiff::Timestamp,
    key: &SecretKey,
) -> Result<Option<String>> {
    let config = crate::vendor::load_config(&publish.config)?;
    let dir = publish
        .config
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let Some(tool) = config.tool.as_ref().map(|t| t.name.clone()) else {
        bail!("{}: no [tool] name", publish.config.display());
    };
    if config.artifacts.is_empty() {
        bail!("{}: no [artifacts] to publish", publish.config.display());
    }
    // No-downgrade against what the index already carries for the tool.
    let previous = index.tools.get(&tool).and_then(|entry| {
        index
            .versions(&tool, None, true)
            .last()
            .map(|(version, v)| crate::vendor::VendorLock {
                version: version.to_string(),
                level: v.level,
                published_at: v.published_at.clone(),
                key_id: v.key_id.clone(),
                generated_at: v.vetted_at.clone(),
            })
            .filter(|_| !entry.versions.is_empty())
    });
    let resolved = crate::vendor::resolve(
        &config,
        &dir,
        publish.version.as_deref(),
        now,
        previous.as_ref(),
        publish.allow_downgrade,
    )?;
    let version = resolved.chosen.version.clone();
    safe_component(&tool)?;
    safe_component(&version)?;
    if index
        .tools
        .get(&tool)
        .is_some_and(|e| e.versions.contains_key(&version))
    {
        if publish.version.is_none() {
            return Ok(None);
        }
        bail!("{tool} {version} is already published; versions are immutable");
    }

    // Verdicts: a block on any artifact digest keeps the version out.
    let verdicts: Option<Verdicts> = crate::feed::load(&store.join("verdicts.json"))?;
    if let Some(verdicts) = &verdicts {
        for chosen in resolved.artifacts.values() {
            if verdicts
                .for_digest(&chosen.sha256)
                .iter()
                .any(|v| v.verdict == VerdictKind::Block)
            {
                bail!(
                    "{tool} {version}: {} has a block verdict; not publishing",
                    chosen.name
                );
            }
        }
    }

    let rel_dir = format!("tools/{tool}/{version}");
    let out_dir = store.join(&rel_dir);
    std::fs::create_dir_all(&out_dir)
        .wrap_err_with(|| format!("creating {}", out_dir.display()))?;
    let sidecar = crate::vendor::sidecar(&resolved, now)?;
    let mut artifacts = BTreeMap::new();
    for (platform, chosen) in &resolved.artifacts {
        safe_component(&chosen.name)?;
        let Some(url) = &chosen.url else {
            bail!(
                "{tool} {version}: {} has no download URL in the packslip",
                chosen.name
            );
        };
        let target = out_dir.join(&chosen.name);
        let complete = if target.exists() {
            let (existing, _) = packslip::digest_file(&target)?;
            existing == chosen.sha256
        } else {
            false
        };
        if !complete {
            let bytes = crate::vendor::fetch_limited(url, chosen.size)?;
            let sha256 = crate::rekor::sha256_hex(&bytes);
            if sha256 != chosen.sha256 {
                bail!(
                    "{}: downloaded sha256 {sha256} is not the packslip's {}",
                    chosen.name,
                    chosen.sha256
                );
            }
            if bytes.len() as u64 != chosen.size {
                bail!(
                    "{}: downloaded size {} is not the packslip's {}",
                    chosen.name,
                    bytes.len(),
                    chosen.size
                );
            }
            crate::feed::write_atomic(&target, &bytes)?;
        }
        let mut sidecars = Vec::new();
        let vendor_path = format!("{}.vendor.json", chosen.name);
        std::fs::write(
            out_dir.join(&vendor_path),
            serde_json::to_vec_pretty(&sidecar)?,
        )?;
        sidecars.push(vendor_path);
        let statement = crate::attest::statement(
            &target,
            &tool,
            &config.upstream.project,
            &version,
            &[crate::attest::ResolvedDependency {
                uri: url.clone(),
                digest: crate::attest::Digest {
                    sha256: chosen.sha256.clone(),
                },
            }],
            key,
            &format!("tool-channel publish {tool} {version}"),
        )?;
        let envelope = Envelope::sign(IN_TOTO_PAYLOAD_TYPE, &serde_json::to_vec(&statement)?, key);
        let provenance_path = format!("{}.provenance.json", chosen.name);
        std::fs::write(
            out_dir.join(&provenance_path),
            serde_json::to_vec_pretty(&envelope)?,
        )?;
        sidecars.push(provenance_path);
        artifacts.insert(
            platform.clone(),
            ToolArtifact {
                name: chosen.name.clone(),
                sha256: chosen.sha256.clone(),
                size: chosen.size,
                path: format!("{rel_dir}/{}", chosen.name),
                sidecars,
            },
        );
    }
    let entry = index
        .tools
        .entry(tool.clone())
        .or_insert_with(|| ToolEntry {
            project: config.upstream.project.clone(),
            vendor_pubkey: String::new(),
            versions: BTreeMap::new(),
        });
    entry.project = config.upstream.project.clone();
    entry.vendor_pubkey = crate::vendor::pubkey_text(&dir, &config.upstream.pubkey)?;
    entry.versions.insert(
        version.clone(),
        ToolVersion {
            published_at: resolved.chosen.published_at.clone(),
            vetted_at: now.to_string(),
            level: resolved.verified.level,
            key_id: resolved.verified.key_id.clone(),
            vendor_pubkey: crate::vendor::pubkey_text(&dir, &config.upstream.pubkey)?,
            channels: vec!["edge".into()],
            held: None,
            artifacts,
        },
    );
    Ok(Some(format!(
        "published {tool} {version} to edge (evidence {}, {} artifact(s){})",
        resolved.verified.level,
        resolved.artifacts.len(),
        if resolved.skipped.is_empty() {
            String::new()
        } else {
            format!("; skipped {}", resolved.skipped.join(", "))
        }
    )))
}

fn safe_component(value: &str) -> Result<()> {
    let path = Path::new(value);
    if path.components().count() != 1
        || !matches!(
            path.components().next(),
            Some(std::path::Component::Normal(_))
        )
    {
        bail!("unsafe path component {value:?}");
    }
    Ok(())
}
