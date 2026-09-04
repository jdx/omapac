//! What a repository publishes beyond pacman's databases: the signed index,
//! the advisory feed, and the verdict feed, all detached-signed with a
//! distro key the machine holds. See `docs/spec/repository-feeds.md` and
//! `PLAN.md`, "Server-side features".
//!
//! Feeds are fetched from the repository's server, verified against the
//! keys under `/etc/pacvamp/keys` and `/usr/share/pacvamp/keys`, cached, and
//! checked for rollback against the ledger's last-seen sequence. Reads of
//! the cache never touch the network.

pub mod feeds;
pub mod tools;

use std::{
    io::Write as _,
    os::unix::{ffi::OsStrExt as _, fs::DirBuilderExt as _, fs::MetadataExt as _},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use eyre::{Context as _, Result, bail};
use packslip::minisign::{PublicKey, Sig};
use sha2::{Digest as _, Sha256};

pub use feeds::{Advisories, Advisory, Index, IndexPackage, Verdict, Verdicts};

/// Trust keys the machine holds, in minisign public key format.
#[derive(Debug, Clone, Default)]
pub struct Keyring {
    pub keys: Vec<(PathBuf, PublicKey)>,
}

impl Keyring {
    /// The conventional key directories, under `sysroot` when given.
    pub fn dirs(sysroot: Option<&Path>) -> Vec<PathBuf> {
        ["/etc/pacvamp/keys", "/usr/share/pacvamp/keys"]
            .into_iter()
            .map(|dir| match sysroot {
                Some(root) => root.join(dir.trim_start_matches('/')),
                None => PathBuf::from(dir),
            })
            .collect()
    }

    /// Load every `*.pub` under the key directories.
    pub fn load(sysroot: Option<&Path>) -> Result<Keyring> {
        let mut keys = Vec::new();
        for dir in Keyring::dirs(sysroot) {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            let mut paths: Vec<PathBuf> = entries
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "pub"))
                .collect();
            paths.sort();
            for path in paths {
                let text = std::fs::read_to_string(&path)
                    .wrap_err_with(|| format!("reading {}", path.display()))?;
                let key =
                    PublicKey::parse(&text).map_err(|e| eyre::eyre!("{}: {e}", path.display()))?;
                keys.push((path, key));
            }
        }
        Ok(Keyring { keys })
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Verify `signature` over `bytes` with whichever key it names.
    pub fn verify(&self, bytes: &[u8], signature: &str) -> Result<&PublicKey> {
        let sig = Sig::parse(signature).map_err(|e| eyre::eyre!("feed signature: {e}"))?;
        let Some((path, key)) = self.keys.iter().find(|(_, k)| k.key_id == sig.key_id) else {
            bail!(
                "feed is signed by key {}, which no key under {} holds",
                packslip::minisign::key_id_hex(&sig.key_id),
                Keyring::dirs(None)
                    .iter()
                    .map(|d| d.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" or ")
            );
        };
        key.verify(bytes, &sig)
            .map_err(|e| eyre::eyre!("feed signature by {}: {e}", path.display()))?;
        Ok(key)
    }
}

/// Where the feeds of one repository live: `<server>/<name>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedSource {
    pub repo: String,
    pub base: String,
}

impl FeedSource {
    pub fn url(&self, name: &str) -> String {
        format!("{}/{name}", self.base.trim_end_matches('/'))
    }
}

/// The on-disk cache of fetched feeds.
#[derive(Debug, Clone)]
pub struct Cache {
    pub dir: PathBuf,
}

impl Cache {
    /// `$XDG_CACHE_HOME/pacvamp/trust/<repo>`, scoped to `sysroot` when set.
    pub fn for_repo(repo: &str, sysroot: Option<&Path>) -> Result<Cache> {
        let cache_home = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
            .map(Ok)
            .unwrap_or_else(secure_temporary_cache_home)?;
        let mut dir = cache_home.join("pacvamp/trust");
        if let Some(sysroot) = sysroot {
            let digest = Sha256::digest(sysroot.as_os_str().as_bytes());
            dir.push(format!("sysroot-{}", hex(&digest[..16])));
        }
        Ok(Cache {
            dir: dir.join(repo),
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// The cached bytes and signature, if both exist.
    pub fn read(&self, name: &str) -> Option<(Vec<u8>, String, std::time::SystemTime)> {
        let combined = self.path(&format!("{name}.cache"));
        if let Ok(data) = std::fs::read(&combined)
            && let Ok(cached) = serde_json::from_slice::<CachedFeed>(&data)
        {
            let fetched = std::fs::metadata(&combined)
                .and_then(|m| m.modified())
                .ok()?;
            return Some((cached.bytes, cached.signature, fetched));
        }
        // Read the original two-file format for migration.
        let bytes = std::fs::read(self.path(name)).ok()?;
        let signature = std::fs::read_to_string(self.path(&format!("{name}.minisig"))).ok()?;
        let fetched = std::fs::metadata(self.path(name))
            .and_then(|m| m.modified())
            .ok()?;
        Some((bytes, signature, fetched))
    }

    pub fn write(&self, name: &str, bytes: &[u8], signature: &str) -> Result<()> {
        let path = self.path(&format!("{name}.cache"));
        let dir = path.parent().unwrap_or(&self.dir);
        std::fs::create_dir_all(dir).wrap_err_with(|| format!("creating {}", dir.display()))?;
        let data = serde_json::to_vec(&CachedFeed {
            bytes: bytes.to_vec(),
            signature: signature.to_string(),
        })?;
        static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
        let (temp_path, mut temp) = loop {
            let nonce = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let leaf = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("feed.cache");
            let temp_path = dir.join(format!(".{leaf}.tmp-{}-{nonce}", std::process::id()));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
            {
                Ok(file) => break (temp_path, file),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err.into()),
            }
        };
        if let Err(err) = temp
            .write_all(&data)
            .and_then(|()| temp.sync_all())
            .and_then(|()| std::fs::rename(&temp_path, &path))
        {
            let _ = std::fs::remove_file(&temp_path);
            return Err(err.into());
        }
        Ok(())
    }
}

fn secure_temporary_cache_home() -> Result<PathBuf> {
    let uid = nix::unistd::geteuid().as_raw();
    let dir = std::env::temp_dir().join(format!("pacvamp-{uid}"));
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(&dir)
                .wrap_err_with(|| format!("inspecting {}", dir.display()))?;
            if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
                bail!("temporary cache directory {} is not private", dir.display());
            }
        }
        Err(err) => return Err(err).wrap_err_with(|| format!("creating {}", dir.display())),
    }
    Ok(dir)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CachedFeed {
    bytes: Vec<u8>,
    signature: String,
}

/// A verified feed document with where it came from.
#[derive(Debug, Clone)]
pub struct Fetched<T> {
    pub value: T,
    /// Whether this came from the network on this call.
    pub fresh: bool,
    pub fetched_at: std::time::SystemTime,
    pub key_id: String,
    /// Why a network fetch fell back to this authenticated cache entry.
    pub fallback_error: Option<String>,
}

/// Fetch, verify, and cache one feed. Falls back to the cache when the
/// network fails; fails when neither is available.
pub fn fetch<T: serde::de::DeserializeOwned>(
    source: &FeedSource,
    name: &str,
    keyring: &Keyring,
    cache: &Cache,
    offline: bool,
) -> Result<Fetched<T>> {
    fetch_checked(source, name, keyring, cache, offline, |_| Ok(()))
}

/// Fetch a feed, applying `accept` before a network response is cached.
pub fn fetch_checked<T: serde::de::DeserializeOwned>(
    source: &FeedSource,
    name: &str,
    keyring: &Keyring,
    cache: &Cache,
    offline: bool,
    accept: impl Fn(&T) -> Result<()>,
) -> Result<Fetched<T>> {
    if keyring.is_empty() {
        bail!(
            "no trust keys under {}; the distro package should ship them",
            Keyring::dirs(None)
                .iter()
                .map(|d| d.display().to_string())
                .collect::<Vec<_>>()
                .join(" or ")
        );
    }
    let cached = cache.read(name);
    let mut fallback_error = None;
    if !offline {
        let network = (|| -> Result<(Vec<u8>, String)> {
            let bytes = http_get(&source.url(name))?;
            let signature = http_get(&source.url(&format!("{name}.minisig")))?;
            Ok((bytes, String::from_utf8_lossy(&signature).into_owned()))
        })();
        match network.and_then(|(bytes, signature)| {
            let (value, key_id, sequence, repo) = decode::<T>(name, &bytes, &signature, keyring)?;
            if repo.as_deref().is_some_and(|repo| repo != source.repo) {
                bail!("{name} says it is for a different repository");
            }
            accept(&value)?;
            if let Some((cached_bytes, cached_signature, _)) = &cached
                && let Ok((_, _, Some(cached_sequence), _)) =
                    decode::<serde_json::Value>(name, cached_bytes, cached_signature, keyring)
                && sequence.is_some_and(|sequence| sequence < cached_sequence)
            {
                bail!("{name} sequence is older than the cached copy");
            }
            if let Err(err) = cache.write(name, &bytes, &signature) {
                eprintln!("warning: {name}: verified feed could not be cached: {err:#}");
            }
            Ok(Fetched {
                value,
                fresh: true,
                fetched_at: std::time::SystemTime::now(),
                key_id,
                fallback_error: None,
            })
        }) {
            Ok(fetched) => return Ok(fetched),
            Err(err) if cached.is_some() && !err.to_string().contains("different repository") => {
                let detail = format!("{err:#}");
                eprintln!("warning: {name}: {detail}; using the cached copy");
                fallback_error = Some(detail);
            }
            Err(err) => return Err(err.wrap_err(format!("fetching {name} from {}", source.base))),
        }
    }
    let Some((bytes, signature, fetched_at)) = cached else {
        bail!("{name}: not cached and offline");
    };
    let (value, key_id, _, repo) = decode(name, &bytes, &signature, keyring)?;
    if repo.as_deref().is_some_and(|repo| repo != source.repo) {
        bail!("cached {name} says it is for a different repository");
    }
    accept(&value)?;
    Ok(Fetched {
        value,
        fresh: false,
        fetched_at,
        key_id,
        fallback_error,
    })
}

fn decode<T: serde::de::DeserializeOwned>(
    name: &str,
    bytes: &[u8],
    signature: &str,
    keyring: &Keyring,
) -> Result<(T, String, Option<u64>, Option<String>)> {
    let key = keyring.verify(bytes, signature)?;
    let document: serde_json::Value =
        serde_json::from_slice(bytes).wrap_err_with(|| format!("parsing {name}"))?;
    let sequence = document.get("sequence").and_then(serde_json::Value::as_u64);
    let repo = document
        .get("repo")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let value = serde_json::from_value(document).wrap_err_with(|| format!("parsing {name}"))?;
    Ok((
        value,
        packslip::minisign::key_id_hex(&key.key_id),
        sequence,
        repo,
    ))
}

fn http_get(url: &str) -> Result<Vec<u8>> {
    let agent = ureq::Agent::config_builder()
        .user_agent(concat!("pacvamp/", env!("CARGO_PKG_VERSION")))
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .build();
    let agent = ureq::Agent::new_with_config(agent);
    let mut response = agent
        .get(url)
        .call()
        .map_err(|e| eyre::eyre!("GET {url}: {e}"))?;
    let bytes = response
        .body_mut()
        .read_to_vec()
        .map_err(|e| eyre::eyre!("GET {url}: {e}"))?;
    Ok(bytes)
}

/// The sha256 of a file, lowercase hex.
/// Lowercase hex sha256 of bytes.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let (digest, _) =
        packslip::digest_file(path).wrap_err_with(|| format!("hashing {}", path.display()))?;
    Ok(digest)
}
