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

use crate::parse::Module;
use crate::report::Indicator;

pub const SPEC_SECTION: &str = "contractspecv0";

const UPDATE_CURRENT_CONTRACT_WASM: (&str, &str) = ("l", "6");
const CREATE_CONTRACT: (&str, &str) = ("l", "3");
const CREATE_CONTRACT_WITH_CONSTRUCTOR: (&str, &str) = ("l", "e");
const CALL: (&str, &str) = ("d", "_");
const TRY_CALL: (&str, &str) = ("d", "0");

/// Runs every detector. Output is sorted by code, so it is deterministic.
pub fn detect(m: &Module, known_bad: bool) -> Vec<Indicator> {
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
