//! AUR package repositories as git checkouts, driven through the `git`
//! binary, which base-devel already requires.
//!
//! A checkout is a cache: `origin` is the AUR, the history is what policy
//! reads, and building happens at an exact commit. Nothing here writes
//! commits.

use std::path::{Path, PathBuf};
use std::process::Command;

use eyre::{Context as _, Result, bail};

/// Where AUR repositories are cloned from: `<base>/<pkgbase>.git`.
#[derive(Debug, Clone)]
pub struct Remote {
    pub base: String,
}

impl Remote {
    pub fn aur() -> Remote {
        Remote {
            base: "https://aur.archlinux.org".to_string(),
        }
    }

    pub fn url(&self, pkgbase: &str) -> String {
        format!("{}/{pkgbase}.git", self.base.trim_end_matches('/'))
    }
}

/// One commit in a package's history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub hash: String,
    pub author: String,
    pub email: String,
    /// Committer time, unix seconds.
    pub time: i64,
    pub subject: String,
}

/// A checkout of one pkgbase.
#[derive(Debug, Clone)]
pub struct Checkout {
    pub pkgbase: String,
    pub dir: PathBuf,
}

impl Checkout {
    /// Clone `pkgbase` under `cache_dir`, or fetch if it is already there.
    /// The working tree is left at the remote's current head.
    pub fn sync(remote: &Remote, cache_dir: &Path, pkgbase: &str) -> Result<Checkout> {
        if !valid_pkgbase(pkgbase) {
            bail!("invalid AUR package base {pkgbase:?}");
        }
        let _lock = super::locking::acquire(cache_dir, pkgbase)?;
        let dir = cache_dir.join(pkgbase);
        let checkout = Checkout {
            pkgbase: pkgbase.to_string(),
            dir,
        };
        if checkout.dir.join(".git").is_dir() {
            let url = remote.url(pkgbase);
            checkout.git(&["remote", "set-url", "origin", &url])?;
            checkout.git(&["fetch", "--quiet", "origin"])?;
            checkout.git(&["checkout", "--quiet", "--force", "--detach", "origin/HEAD"])?;
        } else {
            std::fs::create_dir_all(cache_dir)
                .wrap_err_with(|| format!("creating {}", cache_dir.display()))?;
            let url = remote.url(pkgbase);
            let output = git_command()
                .args(["clone", "--quiet", &url])
                .arg(&checkout.dir)
                .output()
                .wrap_err("running git clone")?;
            if !output.status.success() {
                bail!(
                    "git clone {url} failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            // A freshly cloned empty repository (a name that does not exist
            // on the AUR clones as empty) has no history to review.
            if checkout.git(&["rev-parse", "--verify", "HEAD"]).is_err() {
                let _ = std::fs::remove_dir_all(&checkout.dir);
                bail!("{pkgbase} is not on the AUR (the repository is empty)");
            }
            checkout.git(&["checkout", "--quiet", "--force", "--detach", "HEAD"])?;
        }
        Ok(checkout)
    }

    /// Open an existing checkout without touching the network.
    pub fn open(cache_dir: &Path, pkgbase: &str) -> Option<Checkout> {
        if !valid_pkgbase(pkgbase) {
            return None;
        }
        let dir = cache_dir.join(pkgbase);
        dir.join(".git").is_dir().then(|| Checkout {
            pkgbase: pkgbase.to_string(),
            dir,
        })
    }

    fn git(&self, args: &[&str]) -> Result<String> {
        Ok(String::from_utf8_lossy(&self.git_bytes(args)?).into_owned())
    }

    fn git_bytes(&self, args: &[&str]) -> Result<Vec<u8>> {
        let output = git_command()
            .arg("-C")
            .arg(&self.dir)
            .args(args)
            .output()
            .wrap_err("running git")?;
        if !output.status.success() {
            bail!(
                "git {} failed in {}: {}",
                args.join(" "),
                self.dir.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(output.stdout)
    }

    /// The remote's current head.
    pub fn remote_head(&self) -> Result<String> {
        let head = self.git(&["rev-parse", "origin/HEAD"])?;
        Ok(head.trim().to_string())
    }

    /// The commit the working tree is at.
    pub fn head(&self) -> Result<String> {
        Ok(self.git(&["rev-parse", "HEAD"])?.trim().to_string())
    }

    /// Whether `commit` exists in this checkout.
    pub fn has_commit(&self, commit: &str) -> bool {
        self.git(&["cat-file", "-e", &format!("{commit}^{{commit}}")])
            .is_ok()
    }

    /// Move the working tree to an exact commit.
    pub fn checkout(&self, commit: &str) -> Result<()> {
        self.git(&["checkout", "--quiet", "--force", "--detach", commit])?;
        Ok(())
    }

    /// Export raw Git blobs, without applying archive attributes or checkout filters.
    pub fn export(&self, commit: &str, destination: &std::path::Path) -> Result<()> {
        use std::os::unix::{ffi::OsStringExt as _, fs::PermissionsExt as _};
        use std::path::Component;
        let tree = self.bounded_git(&["ls-tree", "-rlz", "--full-tree", commit], 1024 * 1024)?;
        std::fs::create_dir_all(destination)?;
        let mut remaining = 64 * 1024 * 1024usize;
        for entry in tree.split(|b| *b == 0).filter(|e| !e.is_empty()) {
            let tab = entry
                .iter()
                .position(|b| *b == b'\t')
                .ok_or_else(|| eyre::eyre!("invalid Git tree entry"))?;
            let header = std::str::from_utf8(&entry[..tab])?;
            let fields: Vec<_> = header.split_whitespace().collect();
            if fields.len() != 4 || fields[1] != "blob" {
                bail!("recipe exports support files and symlinks, not submodules");
            }
            let name =
                std::path::PathBuf::from(std::ffi::OsString::from_vec(entry[tab + 1..].to_vec()));
            if name
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
                || name.components().any(|c| c.as_os_str() == ".git")
            {
                bail!("unsafe recipe path {}", name.display());
            }
            let size: usize = fields[3].parse()?;
            if size > remaining {
                bail!("recipe tree exceeds the 64 MiB export limit");
            }
            remaining -= size;
            let bytes = self.bounded_git(&["cat-file", "blob", fields[2]], size)?;
            let path = destination.join(name);
            std::fs::create_dir_all(
                path.parent()
                    .ok_or_else(|| eyre::eyre!("recipe path has no parent"))?,
            )?;
            match fields[0] {
                "120000" => std::os::unix::fs::symlink(std::ffi::OsString::from_vec(bytes), path)?,
                "100644" | "100755" => {
                    std::fs::write(&path, bytes)?;
                    std::fs::set_permissions(
                        path,
                        std::fs::Permissions::from_mode(if fields[0] == "100755" {
                            0o755
                        } else {
                            0o644
                        }),
                    )?;
                }
                mode => bail!("unsupported recipe file mode {mode}"),
            }
        }
        Ok(())
    }

    fn bounded_git(&self, args: &[&str], limit: usize) -> Result<Vec<u8>> {
        use std::io::Read as _;
        use std::process::Stdio;
        let mut child = git_command()
            .arg("-C")
            .arg(&self.dir)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut bytes = Vec::new();
        let read = child
            .stdout
            .take()
            .ok_or_else(|| eyre::eyre!("missing git output"))?
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes);
        if read.is_err() || bytes.len() > limit {
            let _ = child.kill();
            let _ = child.wait();
            read?;
            bail!("Git recipe export exceeds its size limit");
        }
        if !child.wait()?.success() {
            bail!("Git recipe export failed");
        }
        Ok(bytes)
    }

    /// History from `commit` back, newest first, at most `limit` entries.
    pub fn log(&self, commit: &str, limit: usize) -> Result<Vec<Commit>> {
        let format = "--format=%H%x1f%an%x1f%ae%x1f%ct%x1f%s";
        let limit = limit.to_string();
        let out = self.git(&["log", format, "-n", &limit, commit])?;
        Ok(out
            .lines()
            .filter_map(|line| {
                let mut parts = line.split('\x1f');
                Some(Commit {
                    hash: parts.next()?.to_string(),
                    author: parts.next()?.to_string(),
                    email: parts.next()?.to_string(),
                    time: parts.next()?.parse().ok()?,
                    subject: parts.next().unwrap_or_default().to_string(),
                })
            })
            .collect())
    }

    /// The first commit's time: when the package appeared on the AUR.
    pub fn first_commit_time(&self, commit: &str) -> Result<Option<i64>> {
        let out = self.git(&["log", "--format=%ct", "--reverse", commit])?;
        Ok(out.lines().next().and_then(|l| l.trim().parse().ok()))
    }

    /// A file's content at a commit, `None` when it does not exist there.
    pub fn show(&self, commit: &str, path: &str) -> Result<Option<String>> {
        let listed = self.git_bytes(&["ls-tree", "-z", "--name-only", commit, "--", path])?;
        if listed
            .split(|byte| *byte == 0)
            .any(|candidate| candidate == path.as_bytes())
        {
            Ok(Some(self.git(&["show", &format!("{commit}:{path}")])?))
        } else {
            Ok(None)
        }
    }

    /// Files changed between two commits (`from` may be `None` for the
    /// whole tree at `to`).
    pub fn changed_files(&self, from: Option<&str>, to: &str) -> Result<Vec<String>> {
        let out = match from {
            Some(from) => self.git_bytes(&["diff", "--name-only", "-z", from, to])?,
            None => self.git_bytes(&["ls-tree", "--name-only", "-z", "-r", to])?,
        };
        Ok(out
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
            .map(|path| String::from_utf8_lossy(path).into_owned())
            .collect())
    }

    /// A unified diff of `paths` between two commits.
    pub fn diff(&self, from: &str, to: &str, paths: &[&str]) -> Result<String> {
        let mut args = vec!["diff", "--no-color", from, to, "--"];
        args.extend(paths);
        self.git(&args)
    }

    /// A unified diff with complete file context, for parsers whose state
    /// cannot safely be reconstructed from Git's three context lines.
    pub fn diff_full(&self, from: &str, to: &str, paths: &[&str]) -> Result<String> {
        let mut args = vec!["diff", "--no-color", "--unified=1000000", from, to, "--"];
        args.extend(paths);
        self.git(&args)
    }

    /// Lines added plus removed between two commits, across the tree.
    pub fn diff_size(&self, from: &str, to: &str) -> Result<usize> {
        let out = self.git(&["diff", "--numstat", from, to])?;
        Ok(numstat_size(&out))
    }

    /// Total text lines in the tree, used as a conservative diff size when
    /// an approved commit disappeared from rewritten history.
    pub fn tree_size(&self, commit: &str) -> Result<usize> {
        let mut lines = 0;
        for path in self.changed_files(None, commit)? {
            if let Some(text) = self.show(commit, &path)? {
                lines += text.lines().count();
            }
        }
        Ok(lines)
    }

    /// The `.SRCINFO` at a commit, parsed.
    pub fn srcinfo(&self, commit: &str) -> Result<super::srcinfo::SrcInfo> {
        let text = self
            .show(commit, ".SRCINFO")?
            .ok_or_else(|| eyre::eyre!("{} has no .SRCINFO at {commit}", self.pkgbase))?;
        super::srcinfo::SrcInfo::parse(&text)
            .wrap_err_with(|| format!("{} at {commit}", self.pkgbase))
    }
}

pub(super) fn valid_pkgbase(pkgbase: &str) -> bool {
    !pkgbase.is_empty()
        && !pkgbase.starts_with('.')
        && pkgbase.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'@' | b'.' | b'_' | b'+' | b'-')
        })
}

fn git_command() -> Command {
    let mut command = Command::new("git");
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_NAMESPACE",
        "GIT_CEILING_DIRECTORIES",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    ] {
        command.env_remove(name);
    }
    command
}

fn numstat_size(out: &str) -> usize {
    out.lines().fold(0, |total, line| {
        let mut parts = line.split('\t');
        let Some(added) = parts.next() else {
            return total;
        };
        let Some(removed) = parts.next() else {
            return total;
        };
        if added == "-" || removed == "-" {
            return usize::MAX;
        }
        let size = added
            .parse::<usize>()
            .ok()
            .zip(removed.parse::<usize>().ok())
            .map(|(added, removed)| added.saturating_add(removed))
            .unwrap_or(0);
        total.saturating_add(size)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_numstat_is_unbounded_for_review_gates() {
        assert_eq!(numstat_size("-\t-\timage.bin\n"), usize::MAX);
        assert_eq!(numstat_size("2\t3\tPKGBUILD\n"), 5);
    }

    #[test]
    fn checkout_names_cannot_escape_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("cache");
        let remote = Remote::aur();
        for name in [
            "",
            ".",
            "..",
            ".git",
            ".hidden",
            "../outside",
            "nested/package",
            "/tmp/package",
        ] {
            assert!(Checkout::sync(&remote, &cache, name).is_err(), "{name:?}");
            assert!(Checkout::open(&cache, name).is_none(), "{name:?}");
        }
        assert!(valid_pkgbase("foo-bin_2+git@aur"));
    }

    /// A bare "AUR" with one package that has two commits.
    fn fake_aur() -> (tempfile::TempDir, Remote) {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let run = |args: &[&str], cwd: &Path| {
            let out = Command::new("git")
                .args(args)
                .current_dir(cwd)
                .env("GIT_AUTHOR_NAME", "Alice")
                .env("GIT_AUTHOR_EMAIL", "alice@example.com")
                .env("GIT_COMMITTER_NAME", "Alice")
                .env("GIT_COMMITTER_EMAIL", "alice@example.com")
                .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
                .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        run(&["init", "--quiet", "-b", "master"], &work);
        std::fs::write(work.join("PKGBUILD"), "pkgname=foo\npkgver=1\npkgrel=1\n").unwrap();
        std::fs::write(
            work.join(".SRCINFO"),
            "pkgbase = foo\n\tpkgver = 1\n\tpkgrel = 1\n\npkgname = foo\n",
        )
        .unwrap();
        run(&["add", "."], &work);
        run(&["commit", "--quiet", "-m", "initial"], &work);
        std::fs::write(
            work.join("PKGBUILD"),
            "pkgname=foo\npkgver=2\npkgrel=1\nsource=(https://evil.example/x)\n",
        )
        .unwrap();
        std::fs::write(work.join(".SRCINFO"), "pkgbase = foo\n\tpkgver = 2\n\tpkgrel = 1\n\tsource = https://evil.example/x\n\tsha256sums = SKIP\n\npkgname = foo\n").unwrap();
        std::fs::write(work.join("foo.install"), "post_install() { :; }\n").unwrap();
        std::fs::write(work.join("café install"), "post_install() { :; }\n").unwrap();
        run(&["add", "."], &work);
        run(&["commit", "--quiet", "-m", "bump to 2"], &work);
        let bare = dir.path().join("foo.git");
        run(
            &[
                "clone",
                "--quiet",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            dir.path(),
        );
        // Bare clones from a local path do not set origin/HEAD; point it.
        let remote = Remote {
            base: format!("file://{}", dir.path().display()),
        };
        (dir, remote)
    }

    #[test]
    fn clone_fetch_history_and_diff() {
        let (dir, remote) = fake_aur();
        let cache = dir.path().join("cache");
        let checkout = Checkout::sync(&remote, &cache, "foo").unwrap();
        assert!(Checkout::open(&cache, "foo").is_some());
        assert!(Checkout::open(&cache, "bar").is_none());

        let head = checkout.head().unwrap();
        assert_eq!(head, checkout.remote_head().unwrap());
        let log = checkout.log(&head, 10).unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].subject, "bump to 2");
        assert_eq!(log[0].author, "Alice");
        assert_eq!(log[1].subject, "initial");
        assert_eq!(
            checkout.first_commit_time(&head).unwrap(),
            log[1].time.into()
        );

        let first = &log[1].hash;
        assert!(checkout.has_commit(first));
        assert!(!checkout.has_commit("0000000000000000000000000000000000000000"));
        assert_eq!(
            checkout.changed_files(Some(first), &head).unwrap(),
            [".SRCINFO", "PKGBUILD", "café install", "foo.install"]
        );
        assert!(
            checkout
                .changed_files(None, first)
                .unwrap()
                .contains(&"PKGBUILD".to_string())
        );
        let diff = checkout.diff(first, &head, &["PKGBUILD"]).unwrap();
        assert!(diff.contains("+source=(https://evil.example/x)"), "{diff}");
        assert!(checkout.diff_size(first, &head).unwrap() >= 4);

        let old = checkout.srcinfo(first).unwrap();
        assert_eq!(old.version(), "1-1");
        let new = checkout.srcinfo(&head).unwrap();
        assert!(new.has_skipped_checksum("x86_64"));
        assert_eq!(checkout.show(first, "foo.install").unwrap(), None);
        assert_eq!(
            checkout.show(&head, "café install").unwrap().as_deref(),
            Some("post_install() { :; }\n")
        );
        assert!(
            checkout
                .show("0000000000000000000000000000000000000000", ".SRCINFO")
                .is_err()
        );

        checkout.checkout(first).unwrap();
        assert_eq!(checkout.head().unwrap(), *first);
        assert_eq!(
            std::fs::read_to_string(checkout.dir.join("PKGBUILD")).unwrap(),
            "pkgname=foo\npkgver=1\npkgrel=1\n"
        );

        // A second sync repairs a stale origin, fetches, and returns to the
        // requested remote's head.
        checkout
            .git(&["remote", "set-url", "origin", "file:///does/not/exist"])
            .unwrap();
        let again = Checkout::sync(&remote, &cache, "foo").unwrap();
        assert_eq!(again.head().unwrap(), head);
    }

    #[test]
    fn unknown_package_is_an_error() {
        let (dir, remote) = fake_aur();
        let cache = dir.path().join("cache");
        let err = Checkout::sync(&remote, &cache, "nope")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("git clone") || err.contains("not on the AUR"),
            "{err}"
        );
        assert!(!cache.join("nope/.git").exists());
    }

    #[test]
    fn git_commands_remove_repository_overrides() {
        let command = git_command();
        let env: std::collections::BTreeMap<_, _> = command.get_envs().collect();
        for name in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
        ] {
            assert_eq!(env.get(std::ffi::OsStr::new(name)), Some(&None), "{name}");
        }
    }
}
