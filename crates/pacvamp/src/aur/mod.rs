//! The AUR as a source: metadata from the RPC, package recipes from git,
//! and `.SRCINFO` parsing. Nothing here builds anything; see `PLAN.md`,
//! "AUR is commit-bound".

pub mod build;
pub mod git;
pub mod review;
pub mod rpc;
pub mod srcinfo;

use std::path::PathBuf;

/// Where AUR checkouts live: `$XDG_CACHE_HOME/pacvamp/aur`.
pub fn cache_dir() -> PathBuf {
    let cache_home = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        // An environment-less process should fail safely rather than share a
        // predictable world-writable checkout with other users.
        .unwrap_or_else(|| PathBuf::from("/root/.cache"));
    cache_home.join("pacvamp/aur")
}

/// Seconds since a unix timestamp, rendered as `3 days ago`.
pub fn format_age(then: i64, now: i64) -> String {
    let secs = now.saturating_sub(then).max(0);
    let (value, unit) = if secs < 60 {
        return "just now".to_string();
    } else if secs < 3600 {
        (secs / 60, "minute")
    } else if secs < 86_400 {
        (secs / 3600, "hour")
    } else if secs < 30 * 86_400 {
        (secs / 86_400, "day")
    } else if secs < 365 * 86_400 {
        (secs / (30 * 86_400), "month")
    } else {
        (secs / (365 * 86_400), "year")
    };
    format!("{value} {unit}{} ago", if value == 1 { "" } else { "s" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ages() {
        let now = 1_756_800_000;
        assert_eq!(format_age(now - 5, now), "just now");
        assert_eq!(format_age(now - 120, now), "2 minutes ago");
        assert_eq!(format_age(now - 3600, now), "1 hour ago");
        assert_eq!(format_age(now - 3 * 86_400, now), "3 days ago");
        assert_eq!(format_age(now - 45 * 86_400, now), "1 month ago");
        assert_eq!(format_age(now - 800 * 86_400, now), "2 years ago");
        assert_eq!(format_age(now + 100, now), "just now");
    }
}

mod locking;

pub mod receipt;

pub mod chroot;

pub mod cache;
