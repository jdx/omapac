//! Sync databases (`<repo>.db` and `<repo>.files`), following libalpm's
//! `be_sync.c`.
//!
//! A sync database is a tar archive, compressed with gzip, zstd, or xz,
//! or not at all; the compression is detected from the first bytes rather
//! than the file name because `repo-add` names them all `.db`. Each package
//! is a directory `name-version` with a `desc` entry, an optional legacy
//! `depends` entry that older databases split out, and in `.files`
//! databases a `files` entry.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::Path;

use crate::dep::Dependency;
use crate::desc::Fields;

/// One package's entry in a sync database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncPackage {
    /// The repository the package came from.
    pub repo: String,
    pub filename: String,
    pub name: String,
    pub base: Option<String>,
    pub version: String,
    pub desc: Option<String>,
    pub groups: Vec<String>,
    /// Compressed (download) size in bytes.
    pub csize: Option<u64>,
    /// Installed size in bytes.
    pub isize: Option<u64>,
    pub md5sum: Option<String>,
    pub sha256sum: Option<String>,
    /// The detached signature, base64.
    pub pgpsig: Option<String>,
    pub url: Option<String>,
    pub licenses: Vec<String>,
    pub arch: Option<String>,
    pub build_date: Option<i64>,
    pub packager: Option<String>,
    pub replaces: Vec<Dependency>,
    pub depends: Vec<Dependency>,
    pub optdepends: Vec<Dependency>,
    pub makedepends: Vec<Dependency>,
    pub checkdepends: Vec<Dependency>,
    pub conflicts: Vec<Dependency>,
    pub provides: Vec<Dependency>,
    /// The file list, present only in `.files` databases.
    pub files: Option<Vec<String>>,
}

impl SyncPackage {
    fn from_fields(repo: &str, fields: &Fields, files: Option<Vec<String>>) -> Option<Self> {
        let deps = |key: &str| -> Vec<Dependency> {
            fields
                .all(key)
                .iter()
                .map(|s| Dependency::parse(s))
                .collect()
        };
        Some(SyncPackage {
            repo: repo.to_string(),
            filename: fields.first("FILENAME")?.to_string(),
            name: fields.first("NAME")?.to_string(),
            base: fields.first("BASE").map(str::to_string),
            version: fields.first("VERSION")?.to_string(),
            desc: fields.first("DESC").map(str::to_string),
            groups: fields.all("GROUPS").to_vec(),
            csize: fields.number("CSIZE"),
            isize: fields.number("ISIZE"),
            md5sum: fields.first("MD5SUM").map(str::to_string),
            sha256sum: fields.first("SHA256SUM").map(str::to_string),
            pgpsig: fields.first("PGPSIG").map(str::to_string),
            url: fields.first("URL").map(str::to_string),
            licenses: fields.all("LICENSE").to_vec(),
            arch: fields.first("ARCH").map(str::to_string),
            build_date: fields.number("BUILDDATE"),
            packager: fields.first("PACKAGER").map(str::to_string),
            replaces: deps("REPLACES"),
            depends: deps("DEPENDS"),
            optdepends: deps("OPTDEPENDS"),
            makedepends: deps("MAKEDEPENDS"),
            checkdepends: deps("CHECKDEPENDS"),
            conflicts: deps("CONFLICTS"),
            provides: deps("PROVIDES"),
            files,
        })
    }

    /// Whether the package satisfies `dep`, directly or by provision.
    pub fn satisfies(&self, dep: &Dependency) -> bool {
        dep.satisfied_by(&self.name, &self.version, &self.provides)
    }
}

/// A parsed sync database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncDb {
    pub repo: String,
    /// Packages in archive order.
    pub packages: Vec<SyncPackage>,
}

/// Why a sync database could not be read.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not read sync database")]
    Io(#[from] io::Error),
    #[error("unsupported compression (magic {magic:02x?})")]
    UnsupportedCompression { magic: Vec<u8> },
    #[error("archive entry {entry} is not valid text")]
    NotText { entry: String },
}

impl SyncDb {
    /// Read `<path>` as the database of repository `repo`.
    pub fn read(path: &Path, repo: &str) -> Result<SyncDb, Error> {
        let bytes = std::fs::read(path)?;
        SyncDb::from_bytes(&bytes, repo)
    }

    /// Parse database bytes, detecting the compression.
    pub fn from_bytes(bytes: &[u8], repo: &str) -> Result<SyncDb, Error> {
        let reader: Box<dyn Read> = match bytes {
            [0x1f, 0x8b, ..] => Box::new(flate2::read::GzDecoder::new(bytes)),
            [0x28, 0xb5, 0x2f, 0xfd, ..] => Box::new(zstd::stream::read::Decoder::new(bytes)?),
            [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, ..] => Box::new(xz2::read::XzDecoder::new(bytes)),
            [b'B', b'Z', b'h', ..] => {
                return Err(Error::UnsupportedCompression {
                    magic: bytes[..3].to_vec(),
                });
            }
            _ => Box::new(bytes),
        };
        SyncDb::from_tar(reader, repo)
    }

    /// Parse an uncompressed tar stream.
    pub fn from_tar(reader: impl Read, repo: &str) -> Result<SyncDb, Error> {
        // Gather each package directory's entries first: `desc`, the legacy
        // `depends`, and `files` may arrive in any order.
        let mut entries: BTreeMap<String, Entry> = BTreeMap::new();
        let mut order = Vec::new();
        let mut archive = tar::Archive::new(reader);
        for item in archive.entries()? {
            let mut item = item?;
            let path = item.path()?.to_path_buf();
            let Some(kind) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(dir) = path.parent().and_then(|p| p.to_str()) else {
                continue;
            };
            if dir.is_empty() || !matches!(kind, "desc" | "depends" | "files") {
                continue;
            }
            let mut text = String::new();
            item.read_to_string(&mut text).map_err(|_| Error::NotText {
                entry: path.display().to_string(),
            })?;
            if !entries.contains_key(dir) {
                order.push(dir.to_string());
            }
            let entry = entries.entry(dir.to_string()).or_default();
            match kind {
                "desc" => entry.desc = Some(Fields::parse(&text)),
                "depends" => entry.depends = Some(Fields::parse(&text)),
                _ => entry.files = Some(Fields::parse(&text).all("FILES").to_vec()),
            }
        }
        let mut packages = Vec::with_capacity(order.len());
        for dir in order {
            let entry = entries.remove(&dir).unwrap_or_default();
            let Some(mut fields) = entry.desc else {
                continue;
            };
            if let Some(depends) = entry.depends {
                fields.extend(depends);
            }
            if let Some(package) = SyncPackage::from_fields(repo, &fields, entry.files) {
                packages.push(package);
            }
        }
        Ok(SyncDb {
            repo: repo.to_string(),
            packages,
        })
    }

    /// One package by exact name.
    pub fn package(&self, name: &str) -> Option<&SyncPackage> {
        self.packages.iter().find(|p| p.name == name)
    }

    /// Every package that satisfies `dep`, directly or by provision, in
    /// archive order.
    pub fn providers(&self, dep: &Dependency) -> Vec<&SyncPackage> {
        self.packages.iter().filter(|p| p.satisfies(dep)).collect()
    }
}

#[derive(Default)]
struct Entry {
    desc: Option<Fields>,
    depends: Option<Fields>,
    files: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const CORE_DB: &[u8] = include_bytes!("../fixtures/sync/core.db");
    const OMARCHY_DB: &[u8] = include_bytes!("../fixtures/sync/omarchy.db");

    #[test]
    fn reads_arch_core_gzip() {
        let db = SyncDb::from_bytes(CORE_DB, "core").unwrap();
        assert!(db.packages.len() > 200, "{}", db.packages.len());
        let pacman = db.package("pacman").expect("core has pacman");
        assert_eq!(pacman.repo, "core");
        assert!(pacman.filename.ends_with(".pkg.tar.zst"));
        assert_eq!(pacman.arch.as_deref(), Some("x86_64"));
        assert!(pacman.sha256sum.as_ref().is_some_and(|s| s.len() == 64));
        assert!(pacman.pgpsig.is_some());
        assert!(pacman.csize.is_some() && pacman.isize.is_some());
        assert!(pacman.build_date.is_some());
        assert!(pacman.depends.iter().any(|d| d.name == "bash"));
        assert!(pacman.provides.iter().any(|d| d.name == "libalpm.so"));
        assert_eq!(pacman.files, None);
        for package in &db.packages {
            assert!(!package.name.is_empty() && !package.version.is_empty());
            assert!(package.sha256sum.is_some(), "{}", package.name);
        }
    }

    #[test]
    fn reads_omarchy_zstd() {
        let db = SyncDb::from_bytes(OMARCHY_DB, "omarchy").unwrap();
        assert!(db.packages.len() > 100, "{}", db.packages.len());
        let omarchy = db.package("omarchy").expect("OPR has omarchy");
        assert_eq!(omarchy.repo, "omarchy");
        assert!(omarchy.depends.iter().any(|d| d.name == "omarchy-keyring"));
        assert!(db.package("mise-bin").is_some());
    }

    #[test]
    fn providers_by_name_and_provision() {
        let db = SyncDb::from_bytes(CORE_DB, "core").unwrap();
        let by_soname = db.providers(&Dependency::parse("libalpm.so"));
        assert!(by_soname.iter().any(|p| p.name == "pacman"));
        let by_name = db.providers(&Dependency::parse("pacman>=7"));
        assert_eq!(by_name.len(), 1);
        assert!(db.providers(&Dependency::parse("pacman<1")).is_empty());
    }

    fn tar_with(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, contents) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, path, contents.as_bytes())
                .unwrap();
        }
        builder.into_inner().unwrap()
    }

    #[test]
    fn legacy_split_depends_and_files_databases() {
        let tar = tar_with(&[
            (
                "foo-1.0-1/desc",
                "%FILENAME%\nfoo-1.0-1-any.pkg.tar.zst\n\n%NAME%\nfoo\n\n%VERSION%\n1.0-1\n",
            ),
            (
                "foo-1.0-1/depends",
                "%DEPENDS%\nbar>=2\n\n%PROVIDES%\nbaz\n",
            ),
            ("foo-1.0-1/files", "%FILES%\nusr/\nusr/bin/\nusr/bin/foo\n"),
            ("nodesc-1-1/files", "%FILES%\nx\n"),
        ]);
        let db = SyncDb::from_tar(tar.as_slice(), "test").unwrap();
        assert_eq!(db.packages.len(), 1);
        let foo = &db.packages[0];
        assert_eq!(foo.depends, [Dependency::parse("bar>=2")]);
        assert_eq!(foo.provides, [Dependency::parse("baz")]);
        assert_eq!(
            foo.files.as_deref(),
            Some(
                &[
                    "usr/".to_string(),
                    "usr/bin/".to_string(),
                    "usr/bin/foo".to_string()
                ][..]
            )
        );
    }

    #[test]
    fn compression_detection() {
        let tar = tar_with(&[(
            "a-1-1/desc",
            "%FILENAME%\na.pkg\n\n%NAME%\na\n\n%VERSION%\n1-1\n",
        )]);
        let plain = SyncDb::from_bytes(&tar, "r").unwrap();
        assert_eq!(plain.packages[0].name, "a");

        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        io::Write::write_all(&mut gz, &tar).unwrap();
        let gz = gz.finish().unwrap();
        assert_eq!(SyncDb::from_bytes(&gz, "r").unwrap(), plain);

        let zst = zstd::stream::encode_all(tar.as_slice(), 1).unwrap();
        assert_eq!(SyncDb::from_bytes(&zst, "r").unwrap(), plain);

        let mut xz = xz2::write::XzEncoder::new(Vec::new(), 1);
        io::Write::write_all(&mut xz, &tar).unwrap();
        let xz = xz.finish().unwrap();
        assert_eq!(SyncDb::from_bytes(&xz, "r").unwrap(), plain);

        let err = SyncDb::from_bytes(b"BZh91AY&SY", "r").unwrap_err();
        assert!(matches!(err, Error::UnsupportedCompression { .. }));
    }
}
