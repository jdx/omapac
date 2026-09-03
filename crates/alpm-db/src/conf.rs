//! `pacman.conf` parsing, following `src/pacman/conf.c` and
//! `src/common/ini.c` in pacman.
//!
//! The rules that matter and are easy to get wrong:
//!
//! - A line is trimmed; empty lines and lines starting with `#` are skipped.
//!   There are no inline comments.
//! - `[name]` opens a section. `[options]` is the global section; any other
//!   name declares a repository, in file order, and that order is the
//!   precedence order for packages with the same name.
//! - `Key = Value` splits at the first `=`; a key with no `=` has no value.
//!   List-valued directives split their value on whitespace.
//! - `Include = pattern` may appear anywhere, is glob-expanded, and the
//!   included file is parsed inside the current section, which is how a
//!   mirrorlist adds servers to the repo that included it.
//! - `SigLevel` tokens are applied left to right on a bit set with a mask
//!   recording which bits the tokens touched, and a repo's level is merged
//!   over the global level through that mask, so `[repo] SigLevel =
//!   PackageOptional` keeps the global database level.
//! - `$repo` and `$arch` in `Server` are substituted after parsing; `$arch`
//!   with no `Architecture` is an error, and `auto` means the host's.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::vercmp;

/// Where pacman looks for its configuration.
pub const DEFAULT_PATH: &str = "/etc/pacman.conf";

const MAX_INCLUDE_DEPTH: usize = 10;

/// A parsed `pacman.conf`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub options: Options,
    /// Repositories in declaration order, which is their precedence order.
    pub repos: Vec<Repo>,
    /// Non-fatal problems pacman would log as warnings.
    pub warnings: Vec<Warning>,
}

/// The `[options]` section, with pacman's defaults for what is unset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub root_dir: Option<PathBuf>,
    pub db_path: Option<PathBuf>,
    pub cache_dirs: Vec<PathBuf>,
    pub hook_dirs: Vec<PathBuf>,
    pub gpg_dir: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
    pub hold_pkg: Vec<String>,
    pub ignore_pkg: Vec<String>,
    pub ignore_group: Vec<String>,
    pub no_upgrade: Vec<String>,
    pub no_extract: Vec<String>,
    /// As written, so `auto` stays `auto`. See [`Options::arch`].
    pub architectures: Vec<String>,
    pub xfer_command: Option<String>,
    pub clean_method: Vec<String>,
    pub sig_level: SigLevel,
    pub local_file_sig_level: SigLevel,
    pub remote_file_sig_level: SigLevel,
    pub use_syslog: bool,
    pub color: bool,
    pub no_progress_bar: bool,
    pub check_space: bool,
    pub verbose_pkg_lists: bool,
    pub disable_download_timeout: bool,
    pub disable_sandbox: bool,
    pub disable_sandbox_filesystem: bool,
    pub disable_sandbox_syscalls: bool,
    pub i_love_candy: bool,
    pub parallel_downloads: Option<u32>,
    pub download_user: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            root_dir: None,
            db_path: None,
            cache_dirs: Vec::new(),
            hook_dirs: Vec::new(),
            gpg_dir: None,
            log_file: None,
            hold_pkg: Vec::new(),
            ignore_pkg: Vec::new(),
            ignore_group: Vec::new(),
            no_upgrade: Vec::new(),
            no_extract: Vec::new(),
            architectures: Vec::new(),
            xfer_command: None,
            clean_method: Vec::new(),
            sig_level: SigLevel::DEFAULT,
            local_file_sig_level: SigLevel::DEFAULT,
            remote_file_sig_level: SigLevel::DEFAULT,
            use_syslog: false,
            color: false,
            no_progress_bar: false,
            check_space: false,
            verbose_pkg_lists: false,
            disable_download_timeout: false,
            disable_sandbox: false,
            disable_sandbox_filesystem: false,
            disable_sandbox_syscalls: false,
            i_love_candy: false,
            parallel_downloads: None,
            download_user: None,
        }
    }
}

impl Options {
    /// `RootDir`, or `/`.
    pub fn root_dir(&self) -> PathBuf {
        self.root_dir.clone().unwrap_or_else(|| PathBuf::from("/"))
    }

    /// `DBPath`, or `var/lib/pacman` below `RootDir`.
    pub fn db_path(&self) -> PathBuf {
        self.db_path
            .clone()
            .unwrap_or_else(|| self.root_dir().join("var/lib/pacman"))
    }

    /// `CacheDir` entries, or `/var/cache/pacman/pkg`.
    pub fn cache_dirs(&self) -> Vec<PathBuf> {
        if self.cache_dirs.is_empty() {
            vec![PathBuf::from("/var/cache/pacman/pkg")]
        } else {
            self.cache_dirs.clone()
        }
    }

    /// `GPGDir`, or `/etc/pacman.d/gnupg`.
    pub fn gpg_dir(&self) -> PathBuf {
        self.gpg_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("/etc/pacman.d/gnupg"))
    }

    /// `LogFile`, or `var/log/pacman.log` below `RootDir`.
    pub fn log_file(&self) -> PathBuf {
        self.log_file
            .clone()
            .unwrap_or_else(|| self.root_dir().join("var/log/pacman.log"))
    }

    /// The first `Architecture`, with `auto` resolved to the host's, which
    /// is what `$arch` expands to. `None` when no architecture is set.
    pub fn arch(&self) -> Option<String> {
        self.architectures.first().map(|arch| {
            if arch == "auto" {
                host_arch().to_string()
            } else {
                arch.clone()
            }
        })
    }
}

/// What `uname -m` reports on this machine, for `Architecture = auto`.
pub fn host_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86" => "i686",
        "arm" => "armv7l",
        other => other,
    }
}

/// A `[repo]` section after `Include` expansion and `$var` substitution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    pub name: String,
    /// `Server` URLs in order, with `$repo` and `$arch` substituted.
    pub servers: Vec<String>,
    /// `CacheServer` URLs in order, substituted the same way.
    pub cache_servers: Vec<String>,
    /// The effective level after merging over `[options]`.
    pub sig_level: SigLevel,
    /// Whether the section set `SigLevel` itself, even partially.
    pub sig_level_explicit: bool,
    pub usage: Usage,
    /// The file and line where the section was declared.
    pub declared_at: Location,
}

/// A file and line, for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    pub path: PathBuf,
    pub line: usize,
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.path.display(), self.line)
    }
}

/// A non-fatal problem pacman would warn about and continue past.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    pub at: Location,
    pub message: String,
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.at, self.message)
    }
}

/// Why a configuration could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("config file {path} could not be read")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("config file {at}: {message}")]
    Syntax { at: Location, message: String },
    #[error("config parsing exceeded max recursion depth of {MAX_INCLUDE_DEPTH} at {at}")]
    TooDeep { at: Location },
}

/// When a signature is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    Never,
    Optional,
    Required,
}

/// Which signatures are accepted when one is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    TrustedOnly,
    TrustAll,
}

/// A signature verification level, as libalpm's bit set.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SigLevel {
    bits: u8,
}

const SIG_PACKAGE: u8 = 1 << 0;
const SIG_PACKAGE_OPTIONAL: u8 = 1 << 1;
const SIG_PACKAGE_MARGINAL_OK: u8 = 1 << 2;
const SIG_PACKAGE_UNKNOWN_OK: u8 = 1 << 3;
const SIG_DATABASE: u8 = 1 << 4;
const SIG_DATABASE_OPTIONAL: u8 = 1 << 5;
const SIG_DATABASE_MARGINAL_OK: u8 = 1 << 6;
const SIG_DATABASE_UNKNOWN_OK: u8 = 1 << 7;

impl SigLevel {
    /// pacman's built-in default: `Required TrustedOnly` for both.
    pub const DEFAULT: SigLevel = SigLevel {
        bits: SIG_PACKAGE | SIG_DATABASE,
    };

    /// `Never` for both packages and databases.
    pub const NEVER: SigLevel = SigLevel { bits: 0 };

    pub fn package(&self) -> Check {
        check(self.bits, SIG_PACKAGE, SIG_PACKAGE_OPTIONAL)
    }

    pub fn database(&self) -> Check {
        check(self.bits, SIG_DATABASE, SIG_DATABASE_OPTIONAL)
    }

    pub fn package_trust(&self) -> Trust {
        trust(self.bits, SIG_PACKAGE_MARGINAL_OK | SIG_PACKAGE_UNKNOWN_OK)
    }

    pub fn database_trust(&self) -> Trust {
        trust(
            self.bits,
            SIG_DATABASE_MARGINAL_OK | SIG_DATABASE_UNKNOWN_OK,
        )
    }

    /// Parse a whitespace-separated token list on top of the default, the
    /// way a `SigLevel` line in `[options]` is read.
    pub fn parse(tokens: &str) -> Result<SigLevel, String> {
        let mut level = SigLevel::DEFAULT;
        let mut mask = 0;
        level.apply(&mut mask, tokens)?;
        Ok(level)
    }

    /// Apply tokens left to right, recording touched bits in `mask`. This
    /// is `process_siglevel` in pacman.
    fn apply(&mut self, mask: &mut u8, tokens: &str) -> Result<(), String> {
        for original in tokens.split_whitespace() {
            let (value, package, database) = if let Some(rest) = original.strip_prefix("Package") {
                (rest, true, false)
            } else if let Some(rest) = original.strip_prefix("Database") {
                (rest, false, true)
            } else {
                (original, true, true)
            };
            match value {
                "Never" => {
                    if package {
                        unset(&mut self.bits, mask, SIG_PACKAGE);
                    }
                    if database {
                        unset(&mut self.bits, mask, SIG_DATABASE);
                    }
                }
                "Optional" => {
                    if package {
                        set(&mut self.bits, mask, SIG_PACKAGE | SIG_PACKAGE_OPTIONAL);
                    }
                    if database {
                        set(&mut self.bits, mask, SIG_DATABASE | SIG_DATABASE_OPTIONAL);
                    }
                }
                "Required" => {
                    if package {
                        set(&mut self.bits, mask, SIG_PACKAGE);
                        unset(&mut self.bits, mask, SIG_PACKAGE_OPTIONAL);
                    }
                    if database {
                        set(&mut self.bits, mask, SIG_DATABASE);
                        unset(&mut self.bits, mask, SIG_DATABASE_OPTIONAL);
                    }
                }
                "TrustedOnly" => {
                    if package {
                        unset(
                            &mut self.bits,
                            mask,
                            SIG_PACKAGE_MARGINAL_OK | SIG_PACKAGE_UNKNOWN_OK,
                        );
                    }
                    if database {
                        unset(
                            &mut self.bits,
                            mask,
                            SIG_DATABASE_MARGINAL_OK | SIG_DATABASE_UNKNOWN_OK,
                        );
                    }
                }
                "TrustAll" => {
                    if package {
                        set(
                            &mut self.bits,
                            mask,
                            SIG_PACKAGE_MARGINAL_OK | SIG_PACKAGE_UNKNOWN_OK,
                        );
                    }
                    if database {
                        set(
                            &mut self.bits,
                            mask,
                            SIG_DATABASE_MARGINAL_OK | SIG_DATABASE_UNKNOWN_OK,
                        );
                    }
                }
                _ => return Err(format!("invalid value for 'SigLevel' : '{original}'")),
            }
        }
        Ok(())
    }

    /// `merge_siglevel` in pacman: bits the override touched win, the rest
    /// come from the base.
    fn merge(base: SigLevel, over: SigLevel, mask: u8) -> SigLevel {
        if mask == 0 {
            base
        } else {
            SigLevel {
                bits: (over.bits & mask) | (base.bits & !mask),
            }
        }
    }

    /// The canonical token list that reproduces this level, in pacman's
    /// idiom: an unprefixed token states the package level and a
    /// `Database` token follows only when the database level differs.
    pub fn tokens(&self) -> Vec<String> {
        let mut tokens = vec![check_token(self.package()).to_string()];
        if self.database() != self.package() {
            tokens.push(format!("Database{}", check_token(self.database())));
        }
        let (pt, dt) = (self.package_trust(), self.database_trust());
        if pt == Trust::TrustAll {
            tokens.push("TrustAll".to_string());
        }
        if dt != pt {
            tokens.push(format!("Database{}", trust_token(dt)));
        }
        tokens
    }
}

impl Default for SigLevel {
    fn default() -> Self {
        SigLevel::DEFAULT
    }
}

impl fmt::Debug for SigLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigLevel({})", self)
    }
}

impl fmt::Display for SigLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.tokens().join(" "))
    }
}

fn set(level: &mut u8, mask: &mut u8, bits: u8) {
    *level |= bits;
    *mask |= bits;
}

fn unset(level: &mut u8, mask: &mut u8, bits: u8) {
    *level &= !bits;
    *mask |= bits;
}

fn check(bits: u8, on: u8, optional: u8) -> Check {
    if bits & on == 0 {
        Check::Never
    } else if bits & optional != 0 {
        Check::Optional
    } else {
        Check::Required
    }
}

fn trust(bits: u8, all: u8) -> Trust {
    if bits & all != 0 {
        Trust::TrustAll
    } else {
        Trust::TrustedOnly
    }
}

fn check_token(check: Check) -> &'static str {
    match check {
        Check::Never => "Never",
        Check::Optional => "Optional",
        Check::Required => "Required",
    }
}

fn trust_token(trust: Trust) -> &'static str {
    match trust {
        Trust::TrustedOnly => "TrustedOnly",
        Trust::TrustAll => "TrustAll",
    }
}

/// What a repository may be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    pub sync: bool,
    pub search: bool,
    pub install: bool,
    pub upgrade: bool,
}

impl Usage {
    pub const ALL: Usage = Usage {
        sync: true,
        search: true,
        install: true,
        upgrade: true,
    };

    const NONE: Usage = Usage {
        sync: false,
        search: false,
        install: false,
        upgrade: false,
    };

    fn apply(&mut self, tokens: &str) -> Result<(), String> {
        for token in tokens.split_whitespace() {
            match token {
                "Sync" => self.sync = true,
                "Search" => self.search = true,
                "Install" => self.install = true,
                "Upgrade" => self.upgrade = true,
                "All" => *self = Usage::ALL,
                _ => return Err(format!("invalid value for 'Usage' : '{token}'")),
            }
        }
        Ok(())
    }
}

impl Default for Usage {
    fn default() -> Self {
        Usage::ALL
    }
}

/// How the parser reaches files, so tests need no real filesystem.
pub trait Loader {
    /// Read one file.
    fn read(&self, path: &Path) -> io::Result<String>;
    /// Expand an `Include` pattern. A pattern that matches nothing yields
    /// itself, as `glob(3)` with `GLOB_NOCHECK` does, so a missing file is
    /// then reported as unreadable rather than silently skipped.
    fn expand(&self, pattern: &str) -> Vec<PathBuf>;
}

/// The real filesystem, optionally under a sysroot like `pacman --sysroot`.
#[derive(Debug, Default, Clone)]
pub struct FsLoader {
    pub sysroot: Option<PathBuf>,
}

impl FsLoader {
    fn rooted(&self, path: &Path) -> PathBuf {
        match &self.sysroot {
            Some(root) => {
                let relative = path.strip_prefix("/").unwrap_or(path);
                root.join(relative)
            }
            None => path.to_path_buf(),
        }
    }
}

impl Loader for FsLoader {
    fn read(&self, path: &Path) -> io::Result<String> {
        std::fs::read_to_string(self.rooted(path))
    }

    fn expand(&self, pattern: &str) -> Vec<PathBuf> {
        let rooted = self.rooted(Path::new(pattern));
        let rooted = rooted.to_string_lossy();
        let mut matches: Vec<PathBuf> = match glob::glob(&rooted) {
            Ok(paths) => paths.filter_map(Result::ok).collect(),
            Err(_) => Vec::new(),
        };
        matches.sort();
        if matches.is_empty() {
            matches.push(PathBuf::from(rooted.as_ref()));
        }
        // Report paths as pacman would see them, without the sysroot.
        match &self.sysroot {
            Some(root) => matches
                .into_iter()
                .map(|p| {
                    p.strip_prefix(root)
                        .map(|rel| Path::new("/").join(rel))
                        .unwrap_or(p)
                })
                .collect(),
            None => matches,
        }
    }
}

/// An in-memory set of files, for tests and for parsing config text that
/// came from somewhere other than disk.
#[derive(Debug, Default, Clone)]
pub struct MemoryLoader {
    pub files: BTreeMap<PathBuf, String>,
}

impl MemoryLoader {
    pub fn with(mut self, path: impl Into<PathBuf>, contents: impl Into<String>) -> Self {
        self.files.insert(path.into(), contents.into());
        self
    }
}

impl Loader for MemoryLoader {
    fn read(&self, path: &Path) -> io::Result<String> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, path.display().to_string()))
    }

    fn expand(&self, pattern: &str) -> Vec<PathBuf> {
        let matcher = match glob::Pattern::new(pattern) {
            Ok(m) => m,
            Err(_) => return vec![PathBuf::from(pattern)],
        };
        let matches: Vec<PathBuf> = self
            .files
            .keys()
            .filter(|path| matcher.matches_path(path))
            .cloned()
            .collect();
        if matches.is_empty() {
            vec![PathBuf::from(pattern)]
        } else {
            matches
        }
    }
}

impl Config {
    /// Load `/etc/pacman.conf`.
    pub fn load_default() -> Result<Config, Error> {
        Config::load(Path::new(DEFAULT_PATH))
    }

    /// Load a configuration file from disk.
    pub fn load(path: &Path) -> Result<Config, Error> {
        Config::load_with(path, &FsLoader::default())
    }

    /// Load a configuration file through a [`Loader`].
    pub fn load_with(path: &Path, loader: &dyn Loader) -> Result<Config, Error> {
        let mut parser = Parser {
            loader,
            config: Config {
                options: Options::default(),
                repos: Vec::new(),
                warnings: Vec::new(),
            },
            repo_masks: Vec::new(),
            local_file_mask: 0,
            remote_file_mask: 0,
            section: None,
            depth: 0,
        };
        parser.parse_file(path)?;
        parser.finish()
    }

    /// Look a repository up by name.
    pub fn repo(&self, name: &str) -> Option<&Repo> {
        self.repos.iter().find(|repo| repo.name == name)
    }

    /// Whether `version` is at least `min` by pacman's ordering, a small
    /// convenience for callers that gate on a repo's package versions.
    pub fn version_at_least(version: &str, min: &str) -> bool {
        vercmp::vercmp(version, min) != std::cmp::Ordering::Less
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Section {
    Options,
    Repo(usize),
}

struct Parser<'a> {
    loader: &'a dyn Loader,
    config: Config,
    /// Per-repo SigLevel masks, parallel to `config.repos`.
    repo_masks: Vec<u8>,
    local_file_mask: u8,
    remote_file_mask: u8,
    section: Option<Section>,
    depth: usize,
}

impl Parser<'_> {
    fn parse_file(&mut self, path: &Path) -> Result<(), Error> {
        let text = self.loader.read(path).map_err(|source| Error::Read {
            path: path.to_path_buf(),
            source,
        })?;
        for (index, raw) in text.lines().enumerate() {
            let line = index + 1;
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let at = || Location {
                path: path.to_path_buf(),
                line,
            };
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                let name = &trimmed[1..trimmed.len() - 1];
                self.open_section(name, at());
                continue;
            }
            let (key, value) = match trimmed.split_once('=') {
                Some((key, value)) => (key.trim(), Some(value.trim())),
                None => (trimmed, None),
            };
            self.directive(key, value, at())?;
        }
        Ok(())
    }

    fn open_section(&mut self, name: &str, at: Location) {
        if name == "options" {
            self.section = Some(Section::Options);
        } else {
            self.config.repos.push(Repo {
                name: name.to_string(),
                servers: Vec::new(),
                cache_servers: Vec::new(),
                sig_level: SigLevel::DEFAULT,
                sig_level_explicit: false,
                usage: Usage::NONE,
                declared_at: at,
            });
            self.repo_masks.push(0);
            self.section = Some(Section::Repo(self.config.repos.len() - 1));
        }
    }

    fn directive(&mut self, key: &str, value: Option<&str>, at: Location) -> Result<(), Error> {
        if key == "Include" {
            return self.include(value, at);
        }
        match self.section.clone() {
            None => Err(Error::Syntax {
                at,
                message: "All directives must belong to a section.".to_string(),
            }),
            Some(Section::Options) => self.option(key, value, at),
            Some(Section::Repo(index)) => self.repo_directive(index, key, value, at),
        }
    }

    fn include(&mut self, value: Option<&str>, at: Location) -> Result<(), Error> {
        let Some(pattern) = value else {
            return Err(needs_value("Include", at));
        };
        if self.depth >= MAX_INCLUDE_DEPTH {
            return Err(Error::TooDeep { at });
        }
        self.depth += 1;
        let result = (|| {
            for path in self.loader.expand(pattern) {
                self.parse_file(&path)?;
            }
            Ok(())
        })();
        self.depth -= 1;
        result
    }

    fn option(&mut self, key: &str, value: Option<&str>, at: Location) -> Result<(), Error> {
        let options = &mut self.config.options;
        let list = |value: Option<&str>| -> Vec<String> {
            value
                .map(|v| v.split_whitespace().map(str::to_string).collect())
                .unwrap_or_default()
        };
        macro_rules! required {
            () => {
                match value {
                    Some(v) if !v.is_empty() => v,
                    _ => return Err(needs_value(key, at)),
                }
            };
        }
        match key {
            "UseSyslog" => options.use_syslog = true,
            "ILoveCandy" => options.i_love_candy = true,
            "VerbosePkgLists" => options.verbose_pkg_lists = true,
            "DisableDownloadTimeout" => options.disable_download_timeout = true,
            "DisableSandbox" => options.disable_sandbox = true,
            "DisableSandboxFilesystem" => options.disable_sandbox_filesystem = true,
            "DisableSandboxSyscalls" => options.disable_sandbox_syscalls = true,
            "CheckSpace" => options.check_space = true,
            "Color" => options.color = true,
            "NoProgressBar" => options.no_progress_bar = true,
            "NoUpgrade" => options.no_upgrade.extend(list(value)),
            "NoExtract" => options.no_extract.extend(list(value)),
            "IgnorePkg" => options.ignore_pkg.extend(list(value)),
            "IgnoreGroup" => options.ignore_group.extend(list(value)),
            "HoldPkg" => options.hold_pkg.extend(list(value)),
            "CacheDir" => options
                .cache_dirs
                .extend(list(value).into_iter().map(PathBuf::from)),
            "HookDir" => options
                .hook_dirs
                .extend(list(value).into_iter().map(PathBuf::from)),
            "Architecture" => options.architectures.extend(list(value)),
            "DBPath" => options.db_path = Some(PathBuf::from(required!())),
            "RootDir" => options.root_dir = Some(PathBuf::from(required!())),
            "GPGDir" => options.gpg_dir = Some(PathBuf::from(required!())),
            "LogFile" => options.log_file = Some(PathBuf::from(required!())),
            "XferCommand" => options.xfer_command = Some(required!().to_string()),
            "DownloadUser" => options.download_user = Some(required!().to_string()),
            "CleanMethod" => {
                for token in list(value) {
                    match token.as_str() {
                        "KeepInstalled" | "KeepCurrent" => options.clean_method.push(token),
                        other => {
                            return Err(Error::Syntax {
                                at,
                                message: format!("invalid value for 'CleanMethod' : '{other}'"),
                            });
                        }
                    }
                }
            }
            "ParallelDownloads" => {
                let raw = required!();
                match raw.parse::<u32>() {
                    Ok(n) if n > 0 => options.parallel_downloads = Some(n),
                    _ => {
                        return Err(Error::Syntax {
                            at,
                            message: format!("invalid value for '{key}' : '{raw}'"),
                        });
                    }
                }
            }
            "SigLevel" => {
                let tokens = required!();
                let mut mask = 0;
                options
                    .sig_level
                    .apply(&mut mask, tokens)
                    .map_err(|message| Error::Syntax { at, message })?;
            }
            "LocalFileSigLevel" => {
                let tokens = required!();
                options
                    .local_file_sig_level
                    .apply(&mut self.local_file_mask, tokens)
                    .map_err(|message| Error::Syntax { at, message })?;
            }
            "RemoteFileSigLevel" => {
                let tokens = required!();
                options
                    .remote_file_sig_level
                    .apply(&mut self.remote_file_mask, tokens)
                    .map_err(|message| Error::Syntax { at, message })?;
            }
            _ => self.config.warnings.push(Warning {
                at,
                message: format!("directive '{key}' in section 'options' not recognized."),
            }),
        }
        Ok(())
    }

    fn repo_directive(
        &mut self,
        index: usize,
        key: &str,
        value: Option<&str>,
        at: Location,
    ) -> Result<(), Error> {
        let repo = &mut self.config.repos[index];
        let value = match value {
            Some(v) if !v.is_empty() => Some(v),
            _ => None,
        };
        match key {
            "Server" | "CacheServer" | "SigLevel" | "Usage" if value.is_none() => {
                return Err(needs_value(key, at));
            }
            "Server" => repo.servers.push(value.unwrap_or_default().to_string()),
            "CacheServer" => repo
                .cache_servers
                .push(value.unwrap_or_default().to_string()),
            "SigLevel" => {
                repo.sig_level
                    .apply(&mut self.repo_masks[index], value.unwrap_or_default())
                    .map_err(|message| Error::Syntax { at, message })?;
            }
            "Usage" => repo
                .usage
                .apply(value.unwrap_or_default())
                .map_err(|message| Error::Syntax { at, message })?,
            _ => {
                let name = repo.name.clone();
                self.config.warnings.push(Warning {
                    at,
                    message: format!("directive '{key}' in section '{name}' not recognized."),
                });
            }
        }
        Ok(())
    }

    /// pacman's `setdefaults` and `prepend_sysroot` tail: merge levels,
    /// default usage, and substitute server variables.
    fn finish(mut self) -> Result<Config, Error> {
        let global = self.config.options.sig_level;
        let options = &mut self.config.options;
        options.local_file_sig_level =
            SigLevel::merge(global, options.local_file_sig_level, self.local_file_mask);
        options.remote_file_sig_level =
            SigLevel::merge(global, options.remote_file_sig_level, self.remote_file_mask);
        let arch = options.arch();
        for (index, repo) in self.config.repos.iter_mut().enumerate() {
            let mask = self.repo_masks[index];
            repo.sig_level = SigLevel::merge(global, repo.sig_level, mask);
            repo.sig_level_explicit = mask != 0;
            if repo.usage == Usage::NONE {
                repo.usage = Usage::ALL;
            }
            for server in repo.servers.iter_mut().chain(repo.cache_servers.iter_mut()) {
                if server.contains("$arch") {
                    let Some(arch) = &arch else {
                        return Err(Error::Syntax {
                            at: repo.declared_at.clone(),
                            message: format!(
                                "mirror '{server}' contains the '$arch' variable, but no 'Architecture' is defined."
                            ),
                        });
                    };
                    *server = server.replace("$arch", arch);
                }
                *server = server.replace("$repo", &repo.name);
            }
        }
        Ok(self.config)
    }
}

fn needs_value(key: &str, at: Location) -> Error {
    Error::Syntax {
        at,
        message: format!("directive '{key}' needs a value"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OMARCHY_STABLE: &str = include_str!("../fixtures/omarchy/pacman-stable.conf");
    const OMARCHY_MIRRORLIST: &str = include_str!("../fixtures/omarchy/mirrorlist-stable");

    fn omarchy() -> Config {
        let loader = MemoryLoader::default()
            .with("/etc/pacman.conf", OMARCHY_STABLE)
            .with("/etc/pacman.d/mirrorlist", OMARCHY_MIRRORLIST);
        Config::load_with(Path::new("/etc/pacman.conf"), &loader).expect("parses")
    }

    #[test]
    fn omarchy_stable_config() {
        let config = omarchy();
        let names: Vec<&str> = config.repos.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["core", "extra", "multilib", "omarchy"]);
        let arch = host_arch();
        assert_eq!(
            config.repo("core").unwrap().servers,
            [format!("https://stable-mirror.omarchy.org/core/os/{arch}")]
        );
        assert_eq!(
            config.repo("omarchy").unwrap().servers,
            [format!("https://pkgs.omarchy.org/stable/{arch}")]
        );
        assert_eq!(config.options.hold_pkg, ["pacman", "glibc"]);
        assert_eq!(config.options.parallel_downloads, Some(5));
        assert_eq!(config.options.download_user.as_deref(), Some("alpm"));
        assert!(config.options.color && config.options.i_love_candy);
        assert_eq!(
            config.options.sig_level.to_string(),
            "Required DatabaseOptional"
        );
        assert_eq!(config.options.local_file_sig_level.to_string(), "Optional");
        assert_eq!(
            config.options.remote_file_sig_level.to_string(),
            "Required DatabaseOptional"
        );
        for repo in &config.repos {
            assert_eq!(repo.sig_level, config.options.sig_level, "{}", repo.name);
            assert!(!repo.sig_level_explicit);
            assert_eq!(repo.usage, Usage::ALL);
        }
        assert!(config.warnings.is_empty(), "{:?}", config.warnings);
    }

    #[test]
    fn siglevel_tokens_and_merge() {
        assert_eq!(SigLevel::DEFAULT.to_string(), "Required");
        assert_eq!(SigLevel::parse("Never").unwrap().to_string(), "Never");
        assert_eq!(
            SigLevel::parse("Optional TrustAll").unwrap().to_string(),
            "Optional TrustAll"
        );
        assert_eq!(
            SigLevel::parse("Required DatabaseOptional")
                .unwrap()
                .to_string(),
            "Required DatabaseOptional"
        );
        assert_eq!(
            SigLevel::parse("PackageNever").unwrap().to_string(),
            "Never DatabaseRequired"
        );
        assert_eq!(
            SigLevel::parse("DatabaseTrustAll").unwrap().to_string(),
            "Required DatabaseTrustAll"
        );
        assert!(SigLevel::parse("Sometimes").is_err());

        let level = SigLevel::parse("Optional TrustAll").unwrap();
        assert_eq!(level.package(), Check::Optional);
        assert_eq!(level.package_trust(), Trust::TrustAll);
    }

    #[test]
    fn repo_siglevel_inherits_untouched_bits() {
        let conf = "[options]\nSigLevel = Required DatabaseOptional\n\
                    [a]\nServer = file:///a\nSigLevel = PackageOptional\n\
                    [b]\nServer = file:///b\nSigLevel = Never\n\
                    [c]\nServer = file:///c\nSigLevel = TrustAll\n\
                    [d]\nServer = file:///d\n";
        let loader = MemoryLoader::default().with("/pacman.conf", conf);
        let config = Config::load_with(Path::new("/pacman.conf"), &loader).unwrap();
        assert_eq!(config.repo("a").unwrap().sig_level.to_string(), "Optional");
        assert!(config.repo("a").unwrap().sig_level_explicit);
        assert_eq!(config.repo("b").unwrap().sig_level.to_string(), "Never");
        assert_eq!(
            config.repo("c").unwrap().sig_level.to_string(),
            "Required DatabaseOptional TrustAll"
        );
        assert_eq!(
            config.repo("d").unwrap().sig_level.to_string(),
            "Required DatabaseOptional"
        );
        assert!(!config.repo("d").unwrap().sig_level_explicit);
    }

    #[test]
    fn include_inside_a_repo_adds_servers_to_that_repo() {
        let loader = MemoryLoader::default()
            .with(
                "/pacman.conf",
                "[options]\nArchitecture = x86_64\n[core]\nServer = https://first/$repo/$arch\nInclude = /mirrors/*.list\n[extra]\nInclude = /mirrors/a.list\n",
            )
            .with("/mirrors/a.list", "## comment\nServer = https://a/$repo/os/$arch\n")
            .with("/mirrors/b.list", "Server = https://b/$repo/os/$arch\n");
        let config = Config::load_with(Path::new("/pacman.conf"), &loader).unwrap();
        assert_eq!(
            config.repo("core").unwrap().servers,
            [
                "https://first/core/x86_64",
                "https://a/core/os/x86_64",
                "https://b/core/os/x86_64"
            ]
        );
        assert_eq!(
            config.repo("extra").unwrap().servers,
            ["https://a/extra/os/x86_64"]
        );
    }

    #[test]
    fn include_can_declare_sections() {
        let loader = MemoryLoader::default()
            .with(
                "/pacman.conf",
                "[options]\nArchitecture = x86_64\n[core]\nServer = https://x/$repo\nInclude = /etc/pacman.d/custom.conf\n",
            )
            .with(
                "/etc/pacman.d/custom.conf",
                "[chaotic-aur]\nServer = https://chaotic/$repo/$arch\nSigLevel = Never\n",
            );
        let config = Config::load_with(Path::new("/pacman.conf"), &loader).unwrap();
        let names: Vec<&str> = config.repos.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["core", "chaotic-aur"]);
        let chaotic = config.repo("chaotic-aur").unwrap();
        assert_eq!(chaotic.servers, ["https://chaotic/chaotic-aur/x86_64"]);
        assert_eq!(chaotic.sig_level, SigLevel::NEVER);
        assert_eq!(
            chaotic.declared_at.path,
            Path::new("/etc/pacman.d/custom.conf")
        );
        assert_eq!(chaotic.declared_at.line, 1);
    }

    #[test]
    fn missing_include_is_an_error() {
        let loader = MemoryLoader::default().with("/pacman.conf", "[options]\nInclude = /nope\n");
        let err = Config::load_with(Path::new("/pacman.conf"), &loader).unwrap_err();
        assert!(matches!(err, Error::Read { path, .. } if path == Path::new("/nope")));
    }

    #[test]
    fn errors_match_pacman() {
        let cases = [
            ("Color\n", "All directives must belong to a section."),
            ("[options]\nDBPath\n", "directive 'DBPath' needs a value"),
            (
                "[options]\nSigLevel = Maybe\n",
                "invalid value for 'SigLevel' : 'Maybe'",
            ),
            (
                "[options]\nParallelDownloads = 0\n",
                "invalid value for 'ParallelDownloads' : '0'",
            ),
            (
                "[options]\nCleanMethod = KeepAll\n",
                "invalid value for 'CleanMethod' : 'KeepAll'",
            ),
            ("[core]\nServer\n", "directive 'Server' needs a value"),
            (
                "[core]\nUsage = Sometimes\n",
                "invalid value for 'Usage' : 'Sometimes'",
            ),
            (
                "[core]\nServer = https://x/$arch\n",
                "contains the '$arch' variable, but no 'Architecture' is defined.",
            ),
        ];
        for (conf, expected) in cases {
            let loader = MemoryLoader::default().with("/pacman.conf", conf);
            let err = Config::load_with(Path::new("/pacman.conf"), &loader).unwrap_err();
            assert!(err.to_string().contains(expected), "{conf:?}: {err}");
        }
    }

    #[test]
    fn unknown_directives_warn() {
        let loader = MemoryLoader::default().with(
            "/pacman.conf",
            "[options]\nTotallyMadeUp = 1\n[core]\nServer = file:///x\nWhatever\n",
        );
        let config = Config::load_with(Path::new("/pacman.conf"), &loader).unwrap();
        let messages: Vec<String> = config.warnings.iter().map(ToString::to_string).collect();
        assert_eq!(
            messages,
            [
                "/pacman.conf:2: directive 'TotallyMadeUp' in section 'options' not recognized.",
                "/pacman.conf:5: directive 'Whatever' in section 'core' not recognized."
            ]
        );
    }

    #[test]
    fn usage_tokens() {
        let loader = MemoryLoader::default().with(
            "/pacman.conf",
            "[a]\nServer = file:///a\nUsage = Sync Search\n[b]\nServer = file:///b\nUsage = All\n",
        );
        let config = Config::load_with(Path::new("/pacman.conf"), &loader).unwrap();
        assert_eq!(
            config.repo("a").unwrap().usage,
            Usage {
                sync: true,
                search: true,
                install: false,
                upgrade: false
            }
        );
        assert_eq!(config.repo("b").unwrap().usage, Usage::ALL);
    }

    #[test]
    fn include_depth_is_bounded() {
        let loader =
            MemoryLoader::default().with("/loop.conf", "[options]\nInclude = /loop.conf\n");
        let err = Config::load_with(Path::new("/loop.conf"), &loader).unwrap_err();
        assert!(matches!(err, Error::TooDeep { .. }), "{err}");
    }

    #[test]
    fn defaults_when_unset() {
        let options = Options::default();
        assert_eq!(options.db_path(), Path::new("/var/lib/pacman"));
        assert_eq!(options.root_dir(), Path::new("/"));
        assert_eq!(
            options.cache_dirs(),
            [PathBuf::from("/var/cache/pacman/pkg")]
        );
        assert_eq!(options.gpg_dir(), Path::new("/etc/pacman.d/gnupg"));
        assert_eq!(options.log_file(), Path::new("/var/log/pacman.log"));
        assert_eq!(options.arch(), None);
    }

    #[test]
    fn root_dir_scopes_default_database_and_log_paths() {
        let options = Options {
            root_dir: Some(PathBuf::from("/chroot")),
            ..Options::default()
        };

        assert_eq!(options.db_path(), Path::new("/chroot/var/lib/pacman"));
        assert_eq!(options.log_file(), Path::new("/chroot/var/log/pacman.log"));
    }

    #[test]
    fn fs_loader_with_sysroot() {
        let dir = tempfile::tempdir().unwrap();
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(etc.join("pacman.d")).unwrap();
        std::fs::write(
            etc.join("pacman.conf"),
            "[options]\nArchitecture = x86_64\n[core]\nInclude = /etc/pacman.d/mirror*\n",
        )
        .unwrap();
        std::fs::write(
            etc.join("pacman.d/mirrorlist"),
            "Server = https://m/$repo/os/$arch\n",
        )
        .unwrap();
        let loader = FsLoader {
            sysroot: Some(dir.path().to_path_buf()),
        };
        let config = Config::load_with(Path::new("/etc/pacman.conf"), &loader).unwrap();
        assert_eq!(
            config.repo("core").unwrap().servers,
            ["https://m/core/os/x86_64"]
        );
    }
}
