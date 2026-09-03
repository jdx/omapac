//! The findings engine: turns evidence about a package (AUR metadata, git
//! history, PKGBUILD content, verdicts, advisories) into findings, and applies
//! a policy that maps each finding to allow, warn, or deny.
//!
//! The client runs it before building an AUR commit; the server runs the same
//! code in the AUR sync gate. See `PLAN.md`, "Client-side features".

#![forbid(unsafe_code)]
