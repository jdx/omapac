//! The local package database at `<DBPath>/local`, following libalpm's
//! `be_local.c`.
//!
//! Each installed package is a directory `name-version` holding `desc`
//! (metadata), `files` (the file list and backup entries), and `mtree`.
//! `ALPM_DB_VERSION` at the top records the layout version. This reader
//! trusts `desc` for the name and version rather than the directory name,
//! as libalpm does after its consistency check.

use std::io;
use std::path::{Path, PathBuf};

use crate::dep::Dependency;
use crate::desc::Fields;

/// Why a package was installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallReason {
    /// Asked for by the user.
    Explicit,
    /// Pulled in as a dependency.
    Dependency,
}

/// One installed package's `desc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPackage {
    pub name: String,
    pub version: String,
    pub base: Option<String>,
    pub desc: Option<String>,
    pub url: Option<String>,
    pub arch: Option<String>,
    pub build_date: Option<i64>,
    pub install_date: Option<i64>,
    pub packager: Option<String>,
    /// Installed size in bytes.
    pub size: Option<u64>,
    pub groups: Vec<String>,
    pub licenses: Vec<String>,
    /// How the package was validated at install: `none`, `md5`, `sha256`,
    /// `pgp`, in any combination.
    pub validation: Vec<String>,
    pub replaces: Vec<Dependency>,
    pub depends: Vec<Dependency>,
    pub optdepends: Vec<Dependency>,
    pub conflicts: Vec<Dependency>,
    pub provides: Vec<Dependency>,
    pub makedepends: Vec<Dependency>,
    pub checkdepends: Vec<Dependency>,
    pub reason: InstallReason,
    /// Extended data, `key=value` strings such as `pkgtype=pkg`.
    pub xdata: Vec<String>,
    /// The package's directory, for reading `files` and `mtree`.
    pub dir: PathBuf,
}

/// The `files` entry of an installed package.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalFiles {
    /// Paths relative to the root, directories with a trailing slash.
    pub files: Vec<String>,
    /// `(path, hash)` pairs for files pacman protects with `.pacnew`.
    pub backup: Vec<(String, String)>,
}

impl LocalPackage {
    fn from_fields(fields: &Fields, dir: PathBuf) -> Option<LocalPackage> {
        let deps = |key: &str| -> Vec<Dependency> {
            fields
                .all(key)
                .iter()
                .map(|s| Dependency::parse(s))
                .collect()
        };
        Some(LocalPackage {
            name: fields.first("NAME")?.to_string(),
            version: fields.first("VERSION")?.to_string(),
            base: fields.first("BASE").map(str::to_string),
            desc: fields.first("DESC").map(str::to_string),
            url: fields.first("URL").map(str::to_string),
            arch: fields.first("ARCH").map(str::to_string),
            build_date: fields.number("BUILDDATE"),
            install_date: fields.number("INSTALLDATE"),
            packager: fields.first("PACKAGER").map(str::to_string),
            size: fields.number("SIZE"),
            groups: fields.all("GROUPS").to_vec(),
            licenses: fields.all("LICENSE").to_vec(),
            validation: fields.all("VALIDATION").to_vec(),
            replaces: deps("REPLACES"),
            depends: deps("DEPENDS"),
            optdepends: deps("OPTDEPENDS"),
            conflicts: deps("CONFLICTS"),
            provides: deps("PROVIDES"),
            makedepends: deps("MAKEDEPENDS"),
            checkdepends: deps("CHECKDEPENDS"),
            reason: match fields.first("REASON") {
                Some("1") => InstallReason::Dependency,
                _ => InstallReason::Explicit,
            },
            xdata: fields.all("XDATA").to_vec(),
            dir,
        })
    }

    /// Read the package's `files` entry.
    pub fn files(&self) -> io::Result<LocalFiles> {
        let text = std::fs::read_to_string(self.dir.join("files"))?;
        Ok(parse_files(&text))
    }

    /// Whether the package satisfies `dep`, directly or by provision.
    pub fn satisfies(&self, dep: &Dependency) -> bool {
        dep.satisfied_by(&self.name, &self.version, &self.provides)
    }
}

fn parse_files(text: &str) -> LocalFiles {
    let fields = Fields::parse(text);
    LocalFiles {
        files: fields.all("FILES").to_vec(),
        backup: fields
            .all("BACKUP")
            .iter()
            .filter_map(|line| {
                let (path, hash) = line.split_once('\t')?;
                Some((path.to_string(), hash.to_string()))
            })
            .collect(),
    }
}

/// The local database directory.
#[derive(Debug, Clone)]
pub struct LocalDb {
    pub path: PathBuf,
}

impl LocalDb {
    /// `<db_path>/local`, where `db_path` is pacman's `DBPath`.
    pub fn at(db_path: &Path) -> LocalDb {
        LocalDb {
            path: db_path.join("local"),
        }
    }

    /// The `ALPM_DB_VERSION` marker, `None` when the file is absent.
    pub fn version(&self) -> io::Result<Option<u32>> {
        match std::fs::read_to_string(self.path.join("ALPM_DB_VERSION")) {
            Ok(text) => Ok(text.trim().parse().ok()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// Every installed package, sorted by name.
    pub fn packages(&self) -> io::Result<Vec<LocalPackage>> {
        let mut packages = Vec::new();
        for entry in std::fs::read_dir(&self.path)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let dir = entry.path();
            let desc = match std::fs::read_to_string(dir.join("desc")) {
                Ok(text) => text,
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => return Err(err),
            };
            if let Some(package) = LocalPackage::from_fields(&Fields::parse(&desc), dir) {
                packages.push(package);
            }
        }
        packages.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(packages)
    }

    /// One installed package by name.
    pub fn package(&self, name: &str) -> io::Result<Option<LocalPackage>> {
        Ok(self.packages()?.into_iter().find(|p| p.name == name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACMAN_DESC: &str = include_str!("../fixtures/local/pacman-7.1.0-2/desc");
    const PACMAN_FILES: &str = include_str!("../fixtures/local/pacman-7.1.0-2/files");

    fn fixture_db() -> LocalDb {
        LocalDb {
            path: Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/local"),
        }
    }

    #[test]
    fn reads_the_fixture_database() {
        let db = fixture_db();
        assert_eq!(db.version().unwrap(), Some(9));
        let packages = db.packages().unwrap();
        let names: Vec<&str> = packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["glibc", "pacman", "yay"]);

        let pacman = &packages[1];
        assert_eq!(pacman.version, "7.1.0-2");
        assert_eq!(pacman.reason, InstallReason::Explicit);
        assert_eq!(pacman.base.as_deref(), Some("pacman"));
        assert_eq!(pacman.size, Some(5283285));
        assert_eq!(pacman.install_date, Some(1756800000));
        assert_eq!(pacman.validation, ["pgp"]);
        assert_eq!(pacman.xdata, ["pkgtype=pkg"]);
        assert_eq!(pacman.provides, [Dependency::parse("libalpm.so=16-64")]);
        assert!(pacman.depends.iter().any(|d| d.name == "bash"));
        assert_eq!(
            pacman.optdepends[0].description.as_deref(),
            Some("required to use makepkg")
        );

        let yay = &packages[2];
        assert_eq!(yay.reason, InstallReason::Dependency);
        assert!(yay.provides.is_empty());
    }

    #[test]
    fn files_and_backup() {
        let db = fixture_db();
        let pacman = db.package("pacman").unwrap().unwrap();
        let files = pacman.files().unwrap();
        assert!(files.files.contains(&"usr/bin/pacman".to_string()));
        assert!(files.files.contains(&"etc/".to_string()));
        assert_eq!(
            files.backup,
            [
                (
                    "etc/makepkg.conf".to_string(),
                    "0123456789abcdef0123456789abcdef".to_string()
                ),
                (
                    "etc/pacman.conf".to_string(),
                    "fedcba9876543210fedcba9876543210".to_string()
                ),
            ]
        );
        // The parsers agree with the raw fixture text.
        assert_eq!(Fields::parse(PACMAN_DESC).first("NAME"), Some("pacman"));
        assert_eq!(parse_files(PACMAN_FILES), files);
    }

    #[test]
    fn satisfies_dependencies_directly_and_by_provision() {
        let db = fixture_db();
        let pacman = db.package("pacman").unwrap().unwrap();
        assert!(pacman.satisfies(&Dependency::parse("pacman>=7")));
        assert!(pacman.satisfies(&Dependency::parse("libalpm.so=16-64")));
        assert!(!pacman.satisfies(&Dependency::parse("libalpm.so=15-64")));
        assert!(!pacman.satisfies(&Dependency::parse("pacman<7")));
    }

    #[test]
    fn skips_stray_entries() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("broken-1.0-1")).unwrap();
        std::fs::write(dir.path().join("stray-file"), "x").unwrap();
        std::fs::create_dir(dir.path().join("ok-1.0-1")).unwrap();
        std::fs::write(
            dir.path().join("ok-1.0-1/desc"),
            "%NAME%\nok\n\n%VERSION%\n1.0-1\n\n%REASON%\n1\n",
        )
        .unwrap();
        let db = LocalDb {
            path: dir.path().to_path_buf(),
        };
        assert_eq!(db.version().unwrap(), None);
        let packages = db.packages().unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "ok");
        assert_eq!(packages[0].reason, InstallReason::Dependency);
    }

    #[test]
    fn at_appends_local() {
        assert_eq!(
            LocalDb::at(Path::new("/var/lib/pacman")).path,
            Path::new("/var/lib/pacman/local")
        );
    }
}
