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

pub const SPEC_SECTION: &str = "contractspecv0";

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
pub fn detect(m: &Module, known_bad: bool, claim: Option<EnvMetaClaim>) -> Vec<Indicator> {
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

fn informational(code: &'static str) -> Indicator {
    Indicator {
        code,
        informational: true,
        facts: BTreeMap::new(),
    }
}
