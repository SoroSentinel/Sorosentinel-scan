//! Static triage of Soroban WASM. Produces indicators and a `not_checked`
//! list, never a verdict, and never executes the module.
#![forbid(unsafe_code)]

pub mod detectors;
pub mod limits;
pub mod parse;
pub mod report;

pub use report::{ClaimedMeta, Indicator, KnownBadHashes, ScanError, ScanReport, scan};

/// Stamped into every report. Change it whenever detectors or caps change.
pub const RULESET_VERSION: &str = "2026.10.1";
