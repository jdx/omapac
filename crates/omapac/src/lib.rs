//! The omapac client as a library, so the binary is a thin `main` and the
//! pieces can be tested and reused.
//!
//! See `PLAN.md` for the design. The module layout follows its
//! "Architecture" section.

#![forbid(unsafe_code)]

pub mod aur;
pub mod channel;
pub mod cli;
pub mod engine;
pub mod host;
pub mod jail;
pub mod ledger;
pub mod lockfile;
pub mod manifest;
pub mod resolve;
pub mod trust;
pub mod ui;
pub mod update;
