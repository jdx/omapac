use std::path::{Path, PathBuf};

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
    /// the keys under /etc/pacvamp/keys
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
        let base = base.trim_end_matches('/').to_string();
        let cache_key = crate::trust::sha256_bytes(base.as_bytes());
        Ok(Channel {
            base,
            keyring,
            cache: Cache::for_repo(&format!("tools/{cache_key}"), app.paths.sysroot.as_deref())?,
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
        record_sequence(&channel.cache.dir, fetched.value.sequence)?;
        Ok((fetched.value, fetched.key_id))
    }
}

/// Check and advance the rollback marker while excluding other clients.
/// The separate lock remains stable when the marker is atomically replaced.
fn record_sequence(cache: &Path, sequence: u64) -> Result<()> {
    use nix::fcntl::{Flock, FlockArg};
    use std::io::Write as _;

    std::fs::create_dir_all(cache)?;
    let lock_path = cache.join("index.sequence.lock");
    let lock_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    let _lock = Flock::lock(lock_file, FlockArg::LockExclusive)
        .map_err(|(_, err)| err)
        .wrap_err_with(|| format!("locking {}", lock_path.display()))?;

    let marker = cache.join("index.sequence");
    if let Ok(seen) = std::fs::read_to_string(&marker)
        && let Ok(seen) = seen.trim().parse::<u64>()
        && sequence < seen
    {
        bail!(
            "tool index sequence {sequence} is below the {seen} seen before: a stale or rolled-back channel"
        );
    }

    static NEXT_TEMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let temp = cache.join(format!(
        ".index.sequence.tmp-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        write!(file, "{sequence}")?;
        file.sync_all()?;
        std::fs::rename(&temp, &marker)
    })();
    if let Err(err) = result {
        let _ = std::fs::remove_file(&temp);
        return Err(err).wrap_err_with(|| format!("writing {}", marker.display()));
    }
    Ok(())
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
    if Path::new(&artifact.name).components().count() != 1
        || !matches!(
            Path::new(&artifact.name).components().next(),
            Some(std::path::Component::Normal(_))
        )
        || Path::new(&artifact.path).is_absolute()
        || Path::new(&artifact.path)
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        bail!("unsafe artifact path in the signed index");
    }
    std::fs::create_dir_all(&fetch.dest)
        .wrap_err_with(|| format!("creating {}", fetch.dest.display()))?;
    let path = fetch.dest.join(&artifact.name);
    let url = format!("{}/{}", channel.base, artifact.path);
    let bytes = download(&url, artifact.size)?;
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
    let staging = tempfile::tempdir_in(&fetch.dest)?;
    let staged = staging.path().join(&artifact.name);
    std::fs::write(&staged, &bytes)?;
    // A version may override the tool's pinned identity for a key
    // rotation; otherwise the documented tool-level key applies.
    let vendor_pubkey = if version.vendor_pubkey.is_empty() {
        &entry.vendor_pubkey
    } else {
        &version.vendor_pubkey
    };
    if vendor_pubkey.is_empty() {
        bail!("{} has no pinned vendor key", fetch.tool);
    }
    let vendor_key = packslip::minisign::PublicKey::parse(vendor_pubkey)
        .map_err(|e| eyre::eyre!("{}: vendor key in the index: {e}", fetch.tool))?;
    let vendor_sidecar = format!("{}.vendor.json", artifact.name);
    if !artifact.sidecars.iter().any(|s| s == &vendor_sidecar) {
        bail!("{vendor_sidecar}: required sidecar is absent from the index");
    } else {
        let sidecar: serde_json::Value = serde_json::from_slice(&download(
            &format!(
                "{}/{}",
                channel.base,
                sidecar_path(&artifact.path, ".vendor.json")
            ),
            64 * 1024 * 1024,
        )?)?;
        let document = sidecar["document"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("{vendor_sidecar}: no document"))?;
        let signature = sidecar["signature"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("{vendor_sidecar}: no signature"))?;
        let verified =
            packslip::verify::verify(document.as_bytes(), signature, &vendor_key, &[&staged])
                .map_err(|e| eyre::eyre!("{vendor_sidecar}: {e}"))?;
        if verified.version != fetch.version {
            bail!(
                "{vendor_sidecar}: packslip is for version {}, not {}",
                verified.version,
                fetch.version
            );
        }
    }

    // The mirror's provenance, signed by a channel key, naming the digest.
    let provenance_sidecar = format!("{}.provenance.json", artifact.name);
    if !artifact.sidecars.iter().any(|s| s == &provenance_sidecar) {
        bail!("{provenance_sidecar}: required sidecar is absent from the index");
    } else {
        let envelope: packslip::dsse::Envelope = serde_json::from_slice(&download(
            &format!(
                "{}/{}",
                channel.base,
                sidecar_path(&artifact.path, ".provenance.json")
            ),
            64 * 1024 * 1024,
        )?)?;
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
    }

    std::fs::rename(&staged, &path).wrap_err_with(|| format!("writing {}", path.display()))?;

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
            packslip: true,
            provenance: true,
        },
    })
}

fn sidecar_path(artifact_path: &str, suffix: &str) -> String {
    format!("{artifact_path}{suffix}")
}

pub(crate) fn download(url: &str, max_size: u64) -> Result<Vec<u8>> {
    let setup_timeout = Some(std::time::Duration::from_secs(30));
    let config = ureq::Agent::config_builder()
        .user_agent(concat!("pacvamp/", env!("CARGO_PKG_VERSION")))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_sequence_updates_never_rewind() {
        let cache = tempfile::tempdir().unwrap();
        std::thread::scope(|scope| {
            for sequence in 1..=32 {
                let path = cache.path();
                scope.spawn(move || {
                    let _ = record_sequence(path, sequence);
                });
            }
        });
        assert_eq!(
            std::fs::read_to_string(cache.path().join("index.sequence")).unwrap(),
            "32"
        );
    }
}
