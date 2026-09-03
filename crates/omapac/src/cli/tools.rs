use std::path::PathBuf;

use eyre::{Context as _, Result, bail};
use serde::Serialize;
use usage_rs::RunWith;

use super::{App, print_json};
use crate::trust::tools::{INDEX_PATH, ToolIndex};
use crate::trust::{Cache, FeedSource, Keyring};

/// The vetted tool channel: list and fetch vendor tools for mise
///
/// A tool channel is a signed index of vendor releases the channel
/// operator vetted, mirrored with their evidence. These commands are what
/// the mise tool-channel plugin calls; they verify the index, the
/// vendor's packslip, the mirror's provenance, and the artifact digest.
#[derive(Debug, usage_rs::Args)]
pub struct Tools {
    #[usage(subcommand)]
    command: ToolsCommands,
    /// The channel store URL; default [channel] tools_base
    #[usage(long, global)]
    base: Option<String>,
    /// A minisign public key file to verify the channel with, instead of
    /// the keys under /etc/omapac/keys
    #[usage(long, global, value_hint = usage_rs::ValueHint::FilePath)]
    pubkey: Option<PathBuf>,
    /// Use the cached index only
    #[usage(long, global)]
    offline: bool,
    /// Print as JSON
    #[usage(short = 'J', long, global)]
    json: bool,
}

#[derive(Debug, usage_rs::Subcommands)]
enum ToolsCommands {
    Fetch(Fetch),
    Index(Index),
    List(List),
}

/// Show the verified index
#[derive(Debug, usage_rs::Args)]
pub struct Index {}

/// List vetted versions of a tool, oldest first
#[derive(Debug, usage_rs::Args)]
pub struct List {
    tool: String,
    /// Only versions in this channel: edge, rc, or stable
    #[usage(short = 'c', long)]
    channel: Option<String>,
    /// Include held versions
    #[usage(long)]
    all: bool,
}

/// Download and verify one artifact
#[derive(Debug, usage_rs::Args)]
pub struct Fetch {
    tool: String,
    version: String,
    /// The mise platform, such as linux-x64
    #[usage(short = 'p', long)]
    platform: String,
    /// The directory to write the artifact into
    #[usage(short = 'd', long, value_hint = usage_rs::ValueHint::DirPath)]
    dest: PathBuf,
    /// Fetch a held version anyway
    #[usage(long)]
    force: bool,
}

#[derive(Debug, Serialize)]
pub struct Fetched {
    pub tool: String,
    pub version: String,
    pub platform: String,
    pub path: PathBuf,
    pub name: String,
    pub sha256: String,
    pub size: u64,
    pub level: packslip::model::Level,
    pub channels: Vec<String>,
    pub verified: Verified,
}

#[derive(Debug, Serialize)]
pub struct Verified {
    pub index_key: String,
    pub packslip: bool,
    pub provenance: bool,
}

struct Channel {
    base: String,
    keyring: Keyring,
    cache: Cache,
}

impl Tools {
    fn channel(&self, app: &App) -> Result<Channel> {
        let base = match &self.base {
            Some(base) => base.clone(),
            None => app
                .manifest()?
                .settings
                .channel_tools_base
                .clone()
                .ok_or_else(|| {
                    eyre::eyre!(
                        "no tool channel configured; pass --base or set [channel] tools_base"
                    )
                })?,
        };
        let keyring = match &self.pubkey {
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .wrap_err_with(|| format!("reading {}", path.display()))?;
                let key = packslip::minisign::PublicKey::parse(&text)
                    .map_err(|e| eyre::eyre!("{}: {e}", path.display()))?;
                Keyring {
                    keys: vec![(path.clone(), key)],
                }
            }
            None => Keyring::load(app.paths.sysroot.as_deref())?,
        };
        if keyring.is_empty() {
            bail!("no trust keys to verify the tool channel with; pass --pubkey");
        }
        Ok(Channel {
            base: base.trim_end_matches('/').to_string(),
            keyring,
            cache: Cache::for_repo("tools"),
        })
    }

    /// The verified index, with rollback protection against the last
    /// sequence seen in the cache.
    fn index(&self, channel: &Channel) -> Result<(ToolIndex, String)> {
        let source = FeedSource {
            repo: "tools".into(),
            base: channel.base.clone(),
        };
        let fetched: crate::trust::Fetched<ToolIndex> = crate::trust::fetch(
            &source,
            INDEX_PATH,
            &channel.keyring,
            &channel.cache,
            self.offline,
        )?;
        let marker = channel.cache.dir.join("index.sequence");
        if let Ok(seen) = std::fs::read_to_string(&marker)
            && let Ok(seen) = seen.trim().parse::<u64>()
            && fetched.value.sequence < seen
        {
            bail!(
                "tool index sequence {} is below the {seen} seen before: a stale or rolled-back channel",
                fetched.value.sequence
            );
        }
        std::fs::create_dir_all(&channel.cache.dir)?;
        std::fs::write(&marker, fetched.value.sequence.to_string())?;
        Ok((fetched.value, fetched.key_id))
    }
}

impl RunWith<&App> for Tools {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let channel = self.channel(app)?;
        let (index, index_key) = self.index(&channel)?;
        match &self.command {
            ToolsCommands::Index(_) => {
                if self.json {
                    return print_json(&index);
                }
                println!(
                    "tool channel {} (sequence {}, generated {}, signed by {index_key})",
                    channel.base, index.sequence, index.generated_at
                );
                for (name, entry) in &index.tools {
                    let versions = index.versions(name, None, true);
                    println!(
                        "  {name}: {} version(s) from {}",
                        versions.len(),
                        entry.project
                    );
                }
                Ok(())
            }
            ToolsCommands::List(list) => {
                if !index.tools.contains_key(&list.tool) {
                    bail!("{} is not in the tool channel", list.tool);
                }
                let versions = index.versions(&list.tool, list.channel.as_deref(), list.all);
                if self.json {
                    let rows: Vec<serde_json::Value> = versions
                        .iter()
                        .map(|(v, tv)| {
                            serde_json::json!({
                                "version": v,
                                "published_at": tv.published_at,
                                "level": tv.level,
                                "channels": tv.channels,
                                "held": tv.held,
                                "platforms": tv.artifacts.keys().collect::<Vec<_>>(),
                            })
                        })
                        .collect();
                    return print_json(&rows);
                }
                for (v, tv) in versions {
                    if let Some(reason) = &tv.held {
                        println!("{v}\theld: {reason}");
                    } else {
                        println!("{v}");
                    }
                }
                Ok(())
            }
            ToolsCommands::Fetch(fetch) => {
                let report = fetch_artifact(&channel, &index, &index_key, fetch)?;
                if self.json {
                    return print_json(&report);
                }
                println!(
                    "fetched {} {} for {} to {} (evidence {}, packslip {}, provenance {})",
                    report.tool,
                    report.version,
                    report.platform,
                    report.path.display(),
                    report.level,
                    if report.verified.packslip {
                        "verified"
                    } else {
                        "absent"
                    },
                    if report.verified.provenance {
                        "verified"
                    } else {
                        "absent"
                    },
                );
                Ok(())
            }
        }
    }
}

fn fetch_artifact(
    channel: &Channel,
    index: &ToolIndex,
    index_key: &str,
    fetch: &Fetch,
) -> Result<Fetched> {
    let Some(entry) = index.tools.get(&fetch.tool) else {
        bail!("{} is not in the tool channel", fetch.tool);
    };
    let Some(version) = entry.versions.get(&fetch.version) else {
        bail!(
            "{} {} is not vetted; vetted versions: {}",
            fetch.tool,
            fetch.version,
            index
                .versions(&fetch.tool, None, false)
                .iter()
                .map(|(v, _)| *v)
                .collect::<Vec<_>>()
                .join(", ")
        );
    };
    if let Some(reason) = &version.held
        && !fetch.force
    {
        bail!(
            "{} {} is held by the channel: {reason}; pass --force to fetch it anyway",
            fetch.tool,
            fetch.version
        );
    }
    let Some(artifact) = version.artifacts.get(&fetch.platform) else {
        bail!(
            "{} {} has no artifact for {}; platforms: {}",
            fetch.tool,
            fetch.version,
            fetch.platform,
            version
                .artifacts
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
    };
    std::fs::create_dir_all(&fetch.dest)
        .wrap_err_with(|| format!("creating {}", fetch.dest.display()))?;
    let path = fetch.dest.join(&artifact.name);
    let url = format!("{}/{}", channel.base, artifact.path);
    let bytes = download(&url)?;
    let sha256 = crate::trust::sha256_bytes(&bytes);
    if sha256 != artifact.sha256 {
        bail!(
            "{}: sha256 {sha256} is not the {} the index records",
            artifact.name,
            artifact.sha256
        );
    }
    if bytes.len() as u64 != artifact.size {
        bail!(
            "{}: size {} is not the {} the index records",
            artifact.name,
            bytes.len(),
            artifact.size
        );
    }
    std::fs::write(&path, &bytes).wrap_err_with(|| format!("writing {}", path.display()))?;

    // The vendor's packslip, verified against the pinned vendor key and
    // the file just written.
    let vendor_key = packslip::minisign::PublicKey::parse(&entry.vendor_pubkey)
        .map_err(|e| eyre::eyre!("{}: vendor key in the index: {e}", fetch.tool))?;
    let mut packslip_ok = false;
    let vendor_sidecar = format!("{}.vendor.json", artifact.name);
    if artifact.sidecars.iter().any(|s| s == &vendor_sidecar) {
        let sidecar: serde_json::Value = serde_json::from_slice(&download(&format!(
            "{}/{}",
            channel.base,
            sidecar_path(&artifact.path, ".vendor.json")
        ))?)?;
        let document = sidecar["document"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("{vendor_sidecar}: no document"))?;
        let signature = sidecar["signature"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("{vendor_sidecar}: no signature"))?;
        let verified =
            packslip::verify::verify(document.as_bytes(), signature, &vendor_key, &[&path])
                .map_err(|e| eyre::eyre!("{vendor_sidecar}: {e}"))?;
        if verified.version != fetch.version {
            bail!(
                "{vendor_sidecar}: packslip is for version {}, not {}",
                verified.version,
                fetch.version
            );
        }
        packslip_ok = true;
    }

    // The mirror's provenance, signed by a channel key, naming the digest.
    let mut provenance_ok = false;
    let provenance_sidecar = format!("{}.provenance.json", artifact.name);
    if artifact.sidecars.iter().any(|s| s == &provenance_sidecar) {
        let envelope: packslip::dsse::Envelope = serde_json::from_slice(&download(&format!(
            "{}/{}",
            channel.base,
            sidecar_path(&artifact.path, ".provenance.json")
        ))?)?;
        let keys: Vec<&packslip::minisign::PublicKey> =
            channel.keyring.keys.iter().map(|(_, k)| k).collect();
        let Some((payload, _)) = envelope.verify_any(keys) else {
            bail!("{provenance_sidecar}: not signed by a channel key");
        };
        let statement: serde_json::Value = serde_json::from_slice(&payload)?;
        let named = statement["subject"]
            .as_array()
            .map(|subjects| {
                subjects
                    .iter()
                    .any(|s| s["digest"]["sha256"].as_str() == Some(sha256.as_str()))
            })
            .unwrap_or(false);
        if !named {
            bail!("{provenance_sidecar}: does not name the artifact digest");
        }
        provenance_ok = true;
    }

    Ok(Fetched {
        tool: fetch.tool.clone(),
        version: fetch.version.clone(),
        platform: fetch.platform.clone(),
        path,
        name: artifact.name.clone(),
        sha256,
        size: artifact.size,
        level: version.level,
        channels: version.channels.clone(),
        verified: Verified {
            index_key: index_key.to_string(),
            packslip: packslip_ok,
            provenance: provenance_ok,
        },
    })
}

fn sidecar_path(artifact_path: &str, suffix: &str) -> String {
    format!("{artifact_path}{suffix}")
}

fn download(url: &str) -> Result<Vec<u8>> {
    let mut response = ureq::get(url)
        .call()
        .wrap_err_with(|| format!("fetching {url}"))?;
    response
        .body_mut()
        .with_config()
        .limit(4 * 1024 * 1024 * 1024)
        .read_to_vec()
        .wrap_err_with(|| format!("reading {url}"))
}
