//! v1 indicators. Coarse by design: they describe capabilities present in the
//! bytecode, not intent, and informational ones never raise a level alone.
//!
//! Host imports are compact (module, function) codes. Verified against
//! soroban-env-common/env.json at rs-soroban-env v30.0.0:
//!   ledger.update_current_contract_wasm      = ("l", "6")
//!   ledger.create_contract                   = ("l", "3")
//!   ledger.create_contract_with_constructor  = ("l", "e")
//!   call.call                                = ("d", "_")
//!   call.try_call                            = ("d", "0")
//! Custom section names verified against soroban-sdk v29.0.1 and
//! rs-soroban-env v30.0.0: contractspecv0, contractmetav0, contractenvmetav0.

use std::collections::BTreeMap;

use crate::meta::EnvMetaClaim;
use crate::parse::Module;
use crate::report::Indicator;
use crate::spec::{self, Sep41Claim};

pub use crate::spec::SPEC_SECTION;

/// `S-OLD-SDK` fires when the module claims an interface version below this.
/// The floor is a rule choice, not a network fact, so it is stated with its
/// evidence: measured 2026-10-28 across the 73 distinct contract modules
/// deployed in 3000 testnet ledgers, every claim was 21..=29. Anything under
/// 21 is older than anything live in that sample. Informational only, and it
/// never raises a level on its own.
pub const OLD_PROTOCOL_FLOOR: u32 = 21;

const UPDATE_CURRENT_CONTRACT_WASM: (&str, &str) = ("l", "6");
const CREATE_CONTRACT: (&str, &str) = ("l", "3");
const CREATE_CONTRACT_WITH_CONSTRUCTOR: (&str, &str) = ("l", "e");
const CALL: (&str, &str) = ("d", "_");
const TRY_CALL: (&str, &str) = ("d", "0");

/// Runs every detector. Output is sorted by code, so it is deterministic.
/// `claim` is what the module says about its own interface version, if anything.
pub fn detect(
    m: &Module,
    known_bad: bool,
    claim: Option<EnvMetaClaim>,
    sep41: Option<&Sep41Claim>,
) -> Vec<Indicator> {
    let mut out = Vec::new();
    let has = |(module, name): (&str, &str)| m.imports(module, name);

    if has(UPDATE_CURRENT_CONTRACT_WASM) {
        out.push(informational("S-UPGRADEABLE"));
    }
    if has(CREATE_CONTRACT) || has(CREATE_CONTRACT_WITH_CONSTRUCTOR) {
        out.push(informational("S-CREATES-CONTRACTS"));
    }
    if has(CALL) || has(TRY_CALL) {
        out.push(informational("S-CROSS-CALL"));
    }
    if !m.has_custom_section(SPEC_SECTION) {
        out.push(informational("S-NO-SPEC"));
    }
    if let Some(claim) = claim.filter(|c| c.protocol < OLD_PROTOCOL_FLOOR) {
        let mut facts = BTreeMap::new();
        facts.insert(
            "claimed_protocol_version".to_owned(),
            claim.protocol.to_string(),
        );
        facts.insert(
            "claimed_pre_release".to_owned(),
            claim.pre_release.to_string(),
        );
        out.push(Indicator {
            code: "S-OLD-SDK",
            informational: true,
            facts,
        });
    }
    if let Some(claim) = sep41 {
        out.push(sep41_indicator(claim));
    }
    if known_bad {
        out.push(Indicator {
            code: "S-KNOWN-BAD-HASH",
            informational: false,
            facts: BTreeMap::new(),
        });
    }
    out.sort_by(|a, b| a.code.cmp(b.code));
    out
}

/// At most this many deviations are named in one fact; the count is always
/// reported, so truncating the list never hides how much deviated.
const DEVIATION_FACT_LIMIT: usize = 3;

/// The observed gap between what the module's own spec says and the SEP-41
/// interface. Names and signatures only: the contract's behaviour, events and
/// the meaning of its types are not examined, so `NC-SEP41-CONFORMANCE` stays
/// in `not_checked` even when this fires.
fn sep41_indicator(claim: &Sep41Claim) -> Indicator {
    let mut facts = BTreeMap::new();
    facts.insert(
        "declared_interface_functions".to_owned(),
        claim.declared.to_string(),
    );
    facts.insert("interface_required_functions".to_owned(), "10".to_owned());
    facts.insert(
        "required_function_names".to_owned(),
        spec::SEP41
            .iter()
            .map(|(name, _, _)| *name)
            .collect::<Vec<_>>()
            .join(","),
    );
    facts.insert(
        "missing_function_count".to_owned(),
        claim.missing.len().to_string(),
    );
    if !claim.missing.is_empty() {
        // At most ten names, all from the fixed baseline, so this list is
        // bounded by construction and never needs truncating.
        facts.insert("missing_functions".to_owned(), claim.missing.join(","));
    }
    let deviations: Vec<String> = claim
        .mismatched
        .iter()
        .map(|(name, expected, observed)| format!("{name}: expected {expected}, reads {observed}"))
        .collect();
    facts.insert(
        "deviating_function_count".to_owned(),
        deviations.len().to_string(),
    );
    if !deviations.is_empty() {
        facts.insert("deviating_functions".to_owned(), bounded_join(&deviations));
    }
    Indicator {
        code: "S-SEP41-DEVIATION",
        informational: true,
        facts,
    }
}

/// Joins at most `DEVIATION_FACT_LIMIT` entries and says so, keeping the value
/// inside the schema's 512-character fact limit.
fn bounded_join(items: &[String]) -> String {
    let shown = items
        .iter()
        .take(DEVIATION_FACT_LIMIT)
        .cloned()
        .collect::<Vec<_>>();
    let mut s = shown.join("; ");
    if items.len() > shown.len() {
        s.push_str(&format!("; ({} more)", items.len() - shown.len()));
    }
    s
}

fn informational(code: &'static str) -> Indicator {
    Indicator {
        code,
        informational: true,
        facts: BTreeMap::new(),
    }
}
