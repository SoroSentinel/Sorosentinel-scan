//! ScanReport, conforming to sorosentinel-intel schemas/jsonschema/ScanReport.json.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::RULESET_VERSION;
use crate::detectors::{SPEC_SECTION, detect};
use crate::limits::MAX_KNOWN_BAD_HASHES;
use crate::parse::parse;

/// Always reported: what this ruleset does not examine.
pub const NOT_CHECKED: &[&str] = &[
    "NC-AUTH-CHECKS",
    "NC-RUNTIME-BEHAVIOR",
    "NC-SDK-VERSION",
    "NC-SEP41-CONFORMANCE",
    "NC-SOURCE-CODE",
    "NC-UPGRADE-AUTHORITY",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Indicator {
    pub code: &'static str,
    pub informational: bool,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub facts: BTreeMap<String, String>,
}

/// Values read from the module's own custom sections: untrusted claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClaimedMeta {
    pub spec_present: bool,
    /// The protocol version the module claims to target. Omitted when the
    /// module made no readable claim, which is not the same as claiming zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanReport {
    pub wasm_sha256: String,
    pub ruleset_version: &'static str,
    pub indicators: Vec<Indicator>,
    pub not_checked: Vec<&'static str>,
    pub claimed_meta: ClaimedMeta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanError {
    TooLarge,
    Invalid,
    NotCoreModule,
    LimitExceeded(&'static str),
    BadHashList,
}

impl ScanError {
    /// Stable code for the CLI's error output. Intel maps any error to unanalyzable.
    pub fn code(&self) -> &'static str {
        match self {
            ScanError::TooLarge => "too_large",
            ScanError::Invalid => "invalid_wasm",
            ScanError::NotCoreModule => "not_core_module",
            ScanError::LimitExceeded(_) => "limit_exceeded",
            ScanError::BadHashList => "bad_hash_list",
        }
    }
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::LimitExceeded(what) => write!(f, "limit_exceeded: {what}"),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for ScanError {}

/// Known-bad WASM hashes supplied by Intel at run time (never baked in).
#[derive(Debug, Default)]
pub struct KnownBadHashes(BTreeSet<String>);

impl KnownBadHashes {
    /// One lowercase hex SHA-256 per line; blank lines ignored. Any other line is an error.
    pub fn parse(text: &str) -> Result<Self, ScanError> {
        let mut set = BTreeSet::new();
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let valid =
                line.len() == 64 && line.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
            if !valid || set.len() >= MAX_KNOWN_BAD_HASHES {
                return Err(ScanError::BadHashList);
            }
            set.insert(line.to_owned());
        }
        Ok(Self(set))
    }

    pub fn contains(&self, sha256_hex: &str) -> bool {
        self.0.contains(sha256_hex)
    }
}

/// Scans `bytes`. Deterministic for the same bytes, hash list and RULESET_VERSION.
pub fn scan(bytes: &[u8], known_bad: &KnownBadHashes) -> Result<ScanReport, ScanError> {
    let module = parse(bytes)?;
    let wasm_sha256 = hex(&Sha256::digest(bytes));
    let claim = crate::meta::claim(&module.env_meta_bodies);
    let indicators = detect(&module, known_bad.contains(&wasm_sha256), claim);
    Ok(ScanReport {
        claimed_meta: ClaimedMeta {
            spec_present: module.has_custom_section(SPEC_SECTION),
            protocol_version: claim.map(|c| c.protocol),
        },
        wasm_sha256,
        ruleset_version: RULESET_VERSION,
        indicators,
        not_checked: NOT_CHECKED.to_vec(),
    })
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}
