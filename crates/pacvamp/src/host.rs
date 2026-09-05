//! What this machine has: its `pacman.conf`, its local database, and the
//! sync databases pacman last refreshed. Everything is read directly from
//! disk through `alpm-db`; nothing here runs pacman.

use std::cell::OnceCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use alpm_db::{Config, Dependency, LocalDb, LocalPackage, SyncDb, SyncPackage};
use eyre::{Context as _, Result};

use crate::resolve::Tier;

/// Where a host's files come from.
#[derive(Debug, Clone, Default)]
pub struct HostPaths {
    /// `pacman.conf`, default `/etc/pacman.conf`.
    pub config: Option<PathBuf>,
    /// An alternative root, like `pacman --sysroot`.
    pub sysroot: Option<PathBuf>,
}

impl HostPaths {
    pub(crate) fn rooted(&self, path: &Path) -> PathBuf {
        match &self.sysroot {
            Some(root) => root.join(path.strip_prefix("/").unwrap_or(path)),
            None => path.to_path_buf(),
        }
    }
}

/// One repository as configured, with its sync database when present.
pub struct Source {
    pub name: String,
    pub tier: Tier,
    pub repo: alpm_db::Repo,
    db_path: PathBuf,
    db: OnceCell<Option<SyncDb>>,
}

impl Source {
    /// The authoritative sync database path, including the configured sysroot.
    pub(crate) fn database_path(&self) -> &Path {
        &self.db_path
    }

    /// The sync database, parsed on first use. `None` when pacman has not
    /// downloaded it yet.
    pub fn db(&self) -> Result<Option<&SyncDb>> {
        if let Some(db) = self.db.get() {
            return Ok(db.as_ref());
        }
        if !self.db_path.exists() {
            return Ok(self.db.get_or_init(|| None).as_ref());
        }

        let db = SyncDb::read(&self.db_path, &self.name)
            .wrap_err_with(|| format!("reading {}", self.db_path.display()))?;
        Ok(self.db.get_or_init(|| Some(db)).as_ref())
    }

    /// Whether the sync database file exists.
    pub fn has_db(&self) -> bool {
        self.db_path.exists()
    }

    /// The sync database's modification time, for freshness checks.
    pub fn db_modified(&self) -> Option<std::time::SystemTime> {
        std::fs::metadata(&self.db_path)
            .and_then(|m| m.modified())
            .ok()
    }
}

/// The machine's package state.
pub struct Host {
    pub paths: HostPaths,
    pub config: Config,
    pub local: LocalDb,
    /// Repositories in `pacman.conf` order, which is precedence order.
    pub sources: Vec<Source>,
    installed: OnceCell<Vec<LocalPackage>>,
}

impl Host {
    /// The pacman configuration file actually read, rooted under the
    /// configured sysroot when present.
    pub fn config_path(&self) -> PathBuf {
        let path = self
            .paths
            .config
            .clone()
            .unwrap_or_else(|| PathBuf::from(alpm_db::conf::DEFAULT_PATH));
        self.paths.rooted(&path)
    }

    /// Pacman's database path rooted under the configured sysroot.
    pub fn db_path(&self) -> PathBuf {
        self.paths.rooted(&self.config.options.db_path())
    }

    /// Load the host from `paths`.
    pub fn load(paths: HostPaths) -> Result<Host> {
        let config_path = paths
            .config
            .clone()
            .unwrap_or_else(|| PathBuf::from(alpm_db::conf::DEFAULT_PATH));
        let loader = alpm_db::conf::FsLoader {
            sysroot: paths.sysroot.clone(),
        };
        let config = Config::load_with(&config_path, &loader)
            .wrap_err_with(|| format!("loading {}", config_path.display()))?;
        let db_path = paths.rooted(&config.options.db_path());
        let local = LocalDb::at(&db_path);
        let sources = config
            .repos
            .iter()
            .map(|repo| Source {
                name: repo.name.clone(),
                tier: Tier::of_repo(&repo.name),
                repo: repo.clone(),
                db_path: db_path.join("sync").join(format!("{}.db", repo.name)),
                db: OnceCell::new(),
            })
            .collect();
        Ok(Host {
            paths,
            config,
            local,
            sources,
            installed: OnceCell::new(),
        })
    }

    /// Installed packages, sorted by name, read once.
    pub fn installed(&self) -> Result<&[LocalPackage]> {
        if let Some(packages) = self.installed.get() {
            return Ok(packages);
        }
        let packages = self
            .local
            .packages()
            .wrap_err_with(|| format!("reading {}", self.local.path.display()))?;
        Ok(self.installed.get_or_init(|| packages))
    }

    /// One installed package by exact name.
    pub fn installed_package(&self, name: &str) -> Result<Option<&LocalPackage>> {
        Ok(self.installed()?.iter().find(|p| p.name == name))
    }

    /// Installed packages by name, for repeated lookups.
    pub fn installed_by_name(&self) -> Result<BTreeMap<&str, &LocalPackage>> {
        Ok(self
            .installed()?
            .iter()
            .map(|p| (p.name.as_str(), p))
            .collect())
    }

    /// Whether something installed satisfies `dep`, by name or provision.
    pub fn is_satisfied(&self, dep: &Dependency) -> Result<bool> {
        Ok(self.installed()?.iter().any(|p| p.satisfies(dep)))
    }

    /// The first sync package with this exact name, in repository order.
    pub fn find_sync(&self, name: &str) -> Result<Option<(&Source, &SyncPackage)>> {
        for source in &self.sources {
            if let Some(db) = source.db()?
                && let Some(package) = db.package(name)
            {
                return Ok(Some((source, package)));
            }
        }
        Ok(None)
    }

    /// A sync package pinned to one repository.
    pub fn find_sync_in(&self, repo: &str, name: &str) -> Result<Option<(&Source, &SyncPackage)>> {
        for source in self.sources.iter().filter(|s| s.name == repo) {
            if let Some(db) = source.db()?
                && let Some(package) = db.package(name)
            {
                return Ok(Some((source, package)));
            }
        }
        Ok(None)
    }

    /// Every sync package that satisfies `dep`, in repository order.
    pub fn sync_providers(&self, dep: &Dependency) -> Result<Vec<(&Source, &SyncPackage)>> {
        let mut found = Vec::new();
        for source in &self.sources {
            if let Some(db) = source.db()? {
                found.extend(db.providers(dep).into_iter().map(|p| (source, p)));
            }
        }
        Ok(found)
    }

    /// The tier of an installed package: the tier of the first repository
    /// that carries its name, or `foreign`.
    pub fn tier_of_installed(&self, package: &LocalPackage) -> Result<Tier> {
        Ok(match self.find_sync(&package.name)? {
            Some((source, _)) => source.tier.clone(),
            None => Tier::Foreign,
        })
    }

    /// Installed packages that were pulled in as dependencies and that no
    /// installed package depends on any more (`pacman -Qtd`).
    pub fn orphans(&self) -> Result<Vec<&LocalPackage>> {
        let installed = self.installed()?;
        let required: Vec<&Dependency> = installed.iter().flat_map(|p| &p.depends).collect();
        Ok(installed
            .iter()
            .filter(|p| p.reason == alpm_db::InstallReason::Dependency)
            .filter(|p| !required.iter().any(|dep| p.satisfies(dep)))
            .collect())
    }
}
