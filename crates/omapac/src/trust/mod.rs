//! What a repository publishes beyond pacman's databases: the signed index,
//! the advisory feed, and the verdict feed, all detached-signed with a
//! distro key the machine holds. See `docs/spec/repository-feeds.md` and
//! `PLAN.md`, "Server-side features".
//!
//! Feeds are fetched from the repository's server, verified against the
//! keys under `/etc/omapac/keys` and `/usr/share/omapac/keys`, cached, and
//! checked for rollback against the ledger's last-seen sequence. Reads of
//! the cache never touch the network.

pub mod feeds;

use std::path::{Path, PathBuf};

use eyre::{Context as _, Result, bail};
use packslip::minisign::{PublicKey, Sig};

pub use feeds::{Advisories, Advisory, Index, IndexPackage, Verdict, Verdicts};

/// Trust keys the machine holds, in minisign public key format.
#[derive(Debug, Clone, Default)]
pub struct Keyring {
    pub keys: Vec<(PathBuf, PublicKey)>,
}

impl Keyring {
    /// The conventional key directories, under `sysroot` when given.
    pub fn dirs(sysroot: Option<&Path>) -> Vec<PathBuf> {
        ["/etc/omapac/keys", "/usr/share/omapac/keys"]
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
    /// `$XDG_CACHE_HOME/omapac/trust/<repo>`.
    pub fn for_repo(repo: &str) -> Cache {
        let cache_home = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        Cache {
            dir: cache_home.join("omapac/trust").join(repo),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// The cached bytes and signature, if both exist.
    pub fn read(&self, name: &str) -> Option<(Vec<u8>, String, std::time::SystemTime)> {
        let bytes = std::fs::read(self.path(name)).ok()?;
        let signature = std::fs::read_to_string(self.path(&format!("{name}.minisig"))).ok()?;
        let fetched = std::fs::metadata(self.path(name))
            .and_then(|m| m.modified())
            .ok()?;
        Some((bytes, signature, fetched))
    }

    pub fn write(&self, name: &str, bytes: &[u8], signature: &str) -> Result<()> {
        std::fs::create_dir_all(&self.dir)
            .wrap_err_with(|| format!("creating {}", self.dir.display()))?;
        std::fs::write(self.path(name), bytes)?;
        std::fs::write(self.path(&format!("{name}.minisig")), signature)?;
        Ok(())
    }
}

/// A verified feed document with where it came from.
#[derive(Debug, Clone)]
pub struct Fetched<T> {
    pub value: T,
    /// Whether this came from the network on this call.
    pub fresh: bool,
    pub fetched_at: std::time::SystemTime,
    pub key_id: String,
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
    let network = if offline {
        None
    } else {
        match (
            http_get(&source.url(name)),
            http_get(&source.url(&format!("{name}.minisig"))),
        ) {
            (Ok(bytes), Ok(signature)) => {
                Some((bytes, String::from_utf8_lossy(&signature).into_owned()))
            }
            (Err(err), _) | (_, Err(err)) => {
                if cache.read(name).is_none() {
                    return Err(err.wrap_err(format!("fetching {name} from {}", source.base)));
                }
                eprintln!("warning: {name}: {err:#}; using the cached copy");
                None
            }
        }
    };
    let (bytes, signature, fresh, fetched_at) = match network {
        Some((bytes, signature)) => (bytes, signature, true, std::time::SystemTime::now()),
        None => match cache.read(name) {
            Some((bytes, signature, fetched)) => (bytes, signature, false, fetched),
            None => bail!("{name}: not cached and offline"),
        },
    };
    let key = keyring.verify(&bytes, &signature)?;
    let value: T = serde_json::from_slice(&bytes).wrap_err_with(|| format!("parsing {name}"))?;
    if fresh {
        cache.write(name, &bytes, &signature)?;
    }
    Ok(Fetched {
        value,
        fresh,
        fetched_at,
        key_id: packslip::minisign::key_id_hex(&key.key_id),
    })
}

fn http_get(url: &str) -> Result<Vec<u8>> {
    let agent = ureq::Agent::config_builder()
        .user_agent(concat!("omapac/", env!("CARGO_PKG_VERSION")))
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
pub fn sha256_file(path: &Path) -> Result<String> {
    let (digest, _) =
        packslip::digest_file(path).wrap_err_with(|| format!("hashing {}", path.display()))?;
    Ok(digest)
}
