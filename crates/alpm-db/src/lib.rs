//! Readers for pacman's on-disk state: `pacman.conf`, the local package
//! database, sync databases, and the version comparison pacman uses.
//!
//! Everything here is read-only and parses files directly. Nothing links
//! libalpm, so a soname bump in pacman cannot break a consumer of this crate.
//! See `PLAN.md`, "Engine trait", for why that matters.

#![forbid(unsafe_code)]
