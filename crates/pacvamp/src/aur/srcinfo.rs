//! `.SRCINFO`: the machine-readable summary makepkg writes for a PKGBUILD.
//!
//! A `pkgbase = name` section holds the shared fields, then one
//! `pkgname = name` section per package overrides or extends them. Keys
//! are `\tkey = value`, repeated for lists, and may carry an architecture
//! suffix (`source_x86_64`). This parser needs no bash and never executes
//! anything. The `plan` command uses this static metadata.

use std::collections::BTreeSet;

use alpm_db::Dependency;

/// One `pkgbase` or `pkgname` section: ordered key/value pairs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub fields: Vec<(String, String)>,
}

impl Section {
    /// Every value of `key`, in order.
    pub fn all(&self, key: &str) -> Vec<&str> {
        self.fields
            .iter()
            .filter(|(k, value)| k == key && !value.is_empty())
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// The first value of `key`.
    pub fn first(&self, key: &str) -> Option<&str> {
        self.all(key).first().copied()
    }

    /// Values of `key` plus `key_<arch>` for the given architecture.
    pub fn all_for_arch(&self, key: &str, arch: &str) -> Vec<&str> {
        let suffixed = format!("{key}_{arch}");
        self.fields
            .iter()
            .filter(|(k, value)| (k == key || *k == suffixed) && !value.is_empty())
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

/// A parsed `.SRCINFO`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrcInfo {
    pub base: Section,
    pub packages: Vec<Section>,
}

/// Why a `.SRCINFO` could not be parsed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(".SRCINFO line {line}: expected `key = value`, got {text:?}")]
    Malformed { line: usize, text: String },
    #[error(".SRCINFO has no pkgbase section")]
    NoBase,
    #[error(".SRCINFO line {line}: field before any section")]
    FieldBeforeSection { line: usize },
}

impl SrcInfo {
    pub fn parse(text: &str) -> Result<SrcInfo, Error> {
        let mut base: Option<Section> = None;
        let mut packages = Vec::new();
        let mut current: Option<Section> = None;
        for (index, raw) in text.lines().enumerate() {
            let line = index + 1;
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let Some((key, value)) = trimmed.split_once('=') else {
                return Err(Error::Malformed {
                    line,
                    text: trimmed.to_string(),
                });
            };
            let key = key.trim();
            let value = value.trim();
            match key {
                "pkgbase" | "pkgname" => {
                    if let Some(section) = current.take() {
                        if section.fields.is_empty() && base.is_none() && key == "pkgname" {
                            // Not reachable: pkgbase always comes first.
                        }
                        push_section(&mut base, &mut packages, section);
                    }
                    current = Some(Section {
                        name: value.to_string(),
                        fields: Vec::new(),
                    });
                    if key == "pkgbase" {
                        // Marker so the section is filed as the base.
                        current
                            .as_mut()
                            .unwrap()
                            .fields
                            .push(("__base".into(), String::new()));
                    }
                }
                _ => match current.as_mut() {
                    Some(section) => section.fields.push((key.to_string(), value.to_string())),
                    None => return Err(Error::FieldBeforeSection { line }),
                },
            }
        }
        if let Some(section) = current.take() {
            push_section(&mut base, &mut packages, section);
        }
        let base = base.ok_or(Error::NoBase)?;
        Ok(SrcInfo { base, packages })
    }

    /// The pkgbase name.
    pub fn pkgbase(&self) -> &str {
        &self.base.name
    }

    /// The package names this recipe builds.
    pub fn pkgnames(&self) -> Vec<&str> {
        self.packages.iter().map(|p| p.name.as_str()).collect()
    }

    /// `[epoch:]pkgver-pkgrel` as pacman would report it.
    pub fn version(&self) -> String {
        let pkgver = self.base.first("pkgver").unwrap_or("0");
        let pkgrel = self.base.first("pkgrel").unwrap_or("1");
        match self.base.first("epoch") {
            Some(epoch) if epoch != "0" => format!("{epoch}:{pkgver}-{pkgrel}"),
            _ => format!("{pkgver}-{pkgrel}"),
        }
    }

    /// Sources for `arch`, as written (`name::url` or a bare file/url).
    pub fn sources(&self, arch: &str) -> Vec<Source> {
        self.base
            .all_for_arch("source", arch)
            .into_iter()
            .map(Source::parse)
            .collect()
    }

    /// Every checksum value for `arch`, across all `*sums` keys.
    pub fn checksums(&self, arch: &str) -> Vec<(&str, &str)> {
        let suffix = format!("_{arch}");
        self.base
            .fields
            .iter()
            .filter(|(k, _)| {
                let bare = k.strip_suffix(&suffix).unwrap_or(k);
                bare.ends_with("sums") && (k == bare || k.ends_with(&suffix))
            })
            .filter(|(_, value)| !value.is_empty())
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }

    /// Whether any non-VCS source is checksummed with `SKIP`.
    pub fn has_skipped_checksum(&self, arch: &str) -> bool {
        let arch_suffix = format!("_{arch}");
        let mut checked = BTreeSet::new();
        for (key, _) in self.checksums(arch) {
            if !checked.insert(key) {
                continue;
            }
            let source_key = if key.ends_with(&arch_suffix) {
                format!("source{arch_suffix}")
            } else {
                "source".to_string()
            };
            let sources: Vec<Source> = self
                .base
                .all(&source_key)
                .into_iter()
                .map(Source::parse)
                .collect();
            if self
                .base
                .all(key)
                .into_iter()
                .zip(sources)
                .any(|(sum, source)| sum == "SKIP" && !source.is_vcs())
            {
                return true;
            }
        }
        false
    }

    /// Install scriptlets the recipe references.
    pub fn install_files(&self) -> BTreeSet<&str> {
        let mut files: BTreeSet<&str> = self.base.all("install").into_iter().collect();
        for package in &self.packages {
            files.extend(package.all("install"));
        }
        files
    }

    /// Runtime dependencies of `pkgname` for `arch`, merged with the base.
    pub fn depends(&self, pkgname: &str, arch: &str) -> Vec<Dependency> {
        self.merged(pkgname, "depends", arch)
    }

    pub fn makedepends(&self, arch: &str) -> Vec<Dependency> {
        self.base
            .all_for_arch("makedepends", arch)
            .into_iter()
            .map(Dependency::parse)
            .collect()
    }

    pub fn checkdepends(&self, arch: &str) -> Vec<Dependency> {
        self.base
            .all_for_arch("checkdepends", arch)
            .into_iter()
            .map(Dependency::parse)
            .collect()
    }

    pub fn provides(&self, pkgname: &str, arch: &str) -> Vec<Dependency> {
        self.merged(pkgname, "provides", arch)
    }

    /// Whether the recipe may build on `arch`.
    pub fn supports_arch(&self, arch: &str) -> bool {
        let arches = self.base.all("arch");
        arches.iter().any(|a| *a == arch || *a == "any")
    }

    /// The base's values for `key`, unless the package section overrides
    /// them, which is how makepkg treats split packages.
    fn merged(&self, pkgname: &str, key: &str, arch: &str) -> Vec<Dependency> {
        let package = self.packages.iter().find(|p| p.name == pkgname);
        let arch_key = format!("{key}_{arch}");
        let mut values = match package {
            Some(p) if p.fields.iter().any(|(k, _)| k == key) => p.all(key),
            _ => self.base.all(key),
        };
        values.extend(match package {
            Some(p) if p.fields.iter().any(|(k, _)| k == &arch_key) => p.all(&arch_key),
            _ => self.base.all(&arch_key),
        });
        values.into_iter().map(Dependency::parse).collect()
    }
}

fn push_section(base: &mut Option<Section>, packages: &mut Vec<Section>, mut section: Section) {
    let is_base = section.fields.first().is_some_and(|(k, _)| k == "__base");
    if is_base {
        section.fields.remove(0);
        if base.is_none() {
            *base = Some(section);
        }
    } else {
        packages.push(section);
    }
}

/// One `source` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// The local file name, when given as `name::url`.
    pub filename: Option<String>,
    /// The URL or local file name.
    pub url: String,
}

impl Source {
    pub fn parse(text: &str) -> Source {
        match text.split_once("::") {
            Some((name, url)) if !name.contains("://") => Source {
                filename: Some(name.to_string()),
                url: url.to_string(),
            },
            _ => Source {
                filename: None,
                url: text.to_string(),
            },
        }
    }

    /// The scheme (`https`, `git+https`, ...), or `None` for a local file.
    pub fn scheme(&self) -> Option<&str> {
        self.url.split_once("://").map(|(s, _)| s)
    }

    /// The host part of a remote source.
    pub fn host(&self) -> Option<&str> {
        let (_, rest) = self.url.split_once("://")?;
        let rest = rest.split(['#', '?']).next().unwrap_or(rest);
        let host = rest.split('/').next().unwrap_or(rest);
        Some(host.rsplit('@').next().unwrap_or(host))
    }

    /// A version-control source, whose content is not pinned by a
    /// checksum (VCS sources are `SKIP` by convention).
    pub fn is_vcs(&self) -> bool {
        matches!(
            self.scheme().map(|s| s.split('+').next().unwrap_or(s)),
            Some("git" | "hg" | "svn" | "bzr" | "fossil")
        )
    }

    /// A local file shipped in the AUR repository itself.
    pub fn is_local(&self) -> bool {
        self.scheme().is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAY: &str = include_str!("../../fixtures/aur/yay.SRCINFO");
    const CHROME: &str = include_str!("../../fixtures/aur/google-chrome.SRCINFO");

    #[test]
    fn parses_yay() {
        let info = SrcInfo::parse(YAY).unwrap();
        assert_eq!(info.pkgbase(), "yay");
        assert_eq!(info.pkgnames(), ["yay"]);
        assert_eq!(info.version(), "13.0.1-1");
        assert!(info.supports_arch("x86_64") && !info.supports_arch("mips"));
        let sources = info.sources("x86_64");
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].filename.as_deref(), Some("yay-13.0.1.tar.gz"));
        assert_eq!(sources[0].host(), Some("github.com"));
        assert!(!sources[0].is_vcs());
        assert_eq!(info.checksums("x86_64").len(), 1);
        assert!(!info.has_skipped_checksum("x86_64"));
        assert!(info.install_files().is_empty());
        let deps = info.depends("yay", "x86_64");
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "pacman");
        assert_eq!(info.makedepends("x86_64")[0].name, "go");
    }

    #[test]
    fn parses_chrome_with_arch_suffixes_and_install() {
        let info = SrcInfo::parse(CHROME).unwrap();
        assert_eq!(
            info.install_files().into_iter().collect::<Vec<_>>(),
            ["google-chrome.install"]
        );
        let x86 = info.sources("x86_64");
        assert_eq!(x86.len(), 3, "two local files plus the x86_64 deb");
        assert!(x86[0].is_local() && x86[1].is_local());
        assert_eq!(x86[2].host(), Some("dl.google.com"));
        let arm = info.sources("aarch64");
        assert!(arm[2].url.contains("arm64"));
        assert_eq!(info.checksums("x86_64").len(), 3);
        assert_eq!(info.checksums("aarch64").len(), 3);
    }

    #[test]
    fn split_packages_epochs_and_errors() {
        let text = "pkgbase = split\n\tpkgver = 1.0\n\tpkgrel = 2\n\tepoch = 3\n\tdepends = common\n\tsource = git+https://x.y/z.git\n\tsha256sums = SKIP\n\ninstall = base.install\n\npkgname = split-a\n\tdepends = only-a\n\tinstall = a.install\n\npkgname = split-b\n\npkgname = split-empty\n\tdepends =\n\tprovides =\n\tinstall =\n";
        let info = SrcInfo::parse(text).unwrap();
        assert_eq!(info.version(), "3:1.0-2");
        assert_eq!(info.pkgnames(), ["split-a", "split-b", "split-empty"]);
        assert_eq!(info.depends("split-a", "x86_64")[0].name, "only-a");
        assert_eq!(
            info.depends("split-a", "x86_64")
                .into_iter()
                .map(|dependency| dependency.name)
                .collect::<Vec<_>>(),
            ["only-a"]
        );
        assert_eq!(info.depends("split-b", "x86_64")[0].name, "common");
        assert!(info.depends("split-empty", "x86_64").is_empty());
        assert!(info.provides("split-empty", "x86_64").is_empty());
        assert!(!info.install_files().contains(""));
        assert!(
            !info.has_skipped_checksum("x86_64"),
            "SKIP on a VCS source is normal"
        );
        let mixed = SrcInfo::parse(
            "pkgbase = mixed\n\tpkgver = 1\n\tpkgrel = 1\n\tsource = git+https://x/y.git\n\tsource = fix.patch\n\tsha256sums = SKIP\n\tsha256sums = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\npkgname = mixed\n",
        )
        .unwrap();
        assert!(
            !mixed.has_skipped_checksum("x86_64"),
            "a VCS source's SKIP must not taint a hashed sibling"
        );
        assert_eq!(info.install_files().len(), 2);

        assert!(matches!(
            SrcInfo::parse("pkgname = x\n"),
            Err(Error::NoBase)
        ));
        assert!(matches!(
            SrcInfo::parse("\tpkgver = 1\n"),
            Err(Error::FieldBeforeSection { line: 1 })
        ));
        assert!(matches!(
            SrcInfo::parse("pkgbase = x\n\tjunk\n"),
            Err(Error::Malformed { line: 2, .. })
        ));
    }

    #[test]
    fn package_arch_fields_only_override_that_arch() {
        let text = "pkgbase = split\n\tpkgver = 1\n\tpkgrel = 1\n\tdepends = common\n\tdepends_x86_64 = base-x86\n\n pkgname = split\n\tdepends_x86_64 = package-x86\n";
        let info = SrcInfo::parse(text).unwrap();

        let x86: Vec<_> = info
            .depends("split", "x86_64")
            .into_iter()
            .map(|dependency| dependency.name)
            .collect();
        assert_eq!(x86, ["common", "package-x86"]);
        let arm: Vec<_> = info
            .depends("split", "aarch64")
            .into_iter()
            .map(|dependency| dependency.name)
            .collect();
        assert_eq!(arm, ["common"]);
    }

    #[test]
    fn package_unsuffixed_fields_keep_base_arch_fields() {
        let text = "pkgbase = split\n\tpkgver = 1\n\tpkgrel = 1\n\tdepends = base\n\tdepends_x86_64 = base-x86\n\tprovides_x86_64 = virtual-x86\n\npkgname = split\n\tdepends = package\n\tprovides = virtual\n";
        let info = SrcInfo::parse(text).unwrap();

        let depends: Vec<_> = info
            .depends("split", "x86_64")
            .into_iter()
            .map(|dependency| dependency.name)
            .collect();
        assert_eq!(depends, ["package", "base-x86"]);
        let provides: Vec<_> = info
            .provides("split", "x86_64")
            .into_iter()
            .map(|dependency| dependency.name)
            .collect();
        assert_eq!(provides, ["virtual", "virtual-x86"]);
    }

    #[test]
    fn sources() {
        let s = Source::parse("https://example.com/a.tar.gz");
        assert_eq!(s.filename, None);
        assert_eq!(s.host(), Some("example.com"));
        let s = Source::parse("renamed.tar.gz::https://user@example.com:8443/a.tar.gz?x=1#frag");
        assert_eq!(s.filename.as_deref(), Some("renamed.tar.gz"));
        assert_eq!(s.host(), Some("example.com:8443"));
        let s = Source::parse("repo::git+https://github.com/o/r.git#commit=abc");
        assert!(s.is_vcs());
        assert_eq!(s.host(), Some("github.com"));
        assert!(Source::parse("local.patch").is_local());
    }
}
