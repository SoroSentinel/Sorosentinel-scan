//! SARIF 2.1.0 output (PRD S-4), so a Scan report can be read by code-scanning
//! tools. The JSON `ScanReport` stays the complete record and the default.
//!
//! Nothing here writes a sentence. AGENTS.md §5 reserves user-visible prose for
//! Intel's approved templates, and Scan pins Intel's schemas but not its wording
//! files, so every string in this output is either an identifier (the tool name,
//! a ruleset version, an indicator or `not_checked` code) or `key=value` data
//! already present in the report. A rule therefore carries only its `id` and no
//! description, and `message.text` is the code followed by its facts. Approved
//! rule text is a separate change: an Intel template plus a pin.
//!
//! Property names and values follow the OASIS SARIF 2.1.0 JSON schema (errata
//! 01), which sets `additionalProperties: false` throughout, so a property the
//! schema does not define makes the output invalid rather than merely unusual.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::report::ScanReport;

/// The `version` value the schema's enum accepts, and the only correct one here.
const SARIF_VERSION: &str = "2.1.0";

/// The URI the schema declares as its own id, so a consumer can find the rules
/// this output was checked against.
const SARIF_SCHEMA_URI: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

/// Matches the CLI binary, so a tool can attribute the results.
const TOOL_NAME: &str = "sorosentinel-scan";

/// §3.27.9: `"informational"` is a result from a rule that was evaluated and
/// that "does not indicate the presence of a problem". Every informational
/// indicator maps here, which is also why none of them raises a level alone.
const KIND_INFORMATIONAL: &str = "informational";

/// §3.27.9: `"review"` is a result that "requires review by a human user to
/// decide if it represents a problem", including where a tool is "unable to
/// check for certain conditions" yet wants the possibility surfaced. The
/// `not_checked` codes are that case verbatim, and an indicator whose evidence
/// came from a hash list still needs the human confirmation §3.3 requires.
const KIND_REVIEW: &str = "review";

/// §3.27.10: when `kind` is present with any value other than `"fail"`, `level`
/// SHALL be `"none"`. No Scan result is a determination, so no Scan result
/// claims a severity and every level in this log is this constant.
const LEVEL_NONE: &str = "none";

/// §3.29.1: the artifact role for the thing that was analyzed.
const ROLE_ANALYSIS_TARGET: &str = "analysisTarget";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema_uri: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRun {
    tool: SarifTool,
    artifacts: Vec<SarifArtifact>,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: &'static str,
    version: &'static str,
    rules: Vec<SarifRule>,
}

/// `id` is the only required property, and the only one this repo may write: a
/// `shortDescription` would be prose.
#[derive(Serialize)]
struct SarifRule {
    id: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifArtifact {
    location: ArtifactLocation,
    hashes: BTreeMap<&'static str, String>,
    /// `roles` is an array; a whole-module observation needs exactly one role.
    roles: [&'static str; 1],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactLocation {
    /// The module is named by its own hash, so the same bytes produce the same
    /// log wherever the file happens to live. Owned, so no log type needs a
    /// lifetime and a location can be built wherever one is needed.
    uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: &'static str,
    kind: &'static str,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: PhysicalLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PhysicalLocation {
    /// The schema requires `address` or `artifactLocation`. A whole-module
    /// observation has no region, so it names the artifact and nothing more.
    artifact_location: ArtifactLocation,
}

/// Renders `report` as a SARIF log. Deterministic: result order is the report's
/// own (indicators, then `not_checked`), rules are sorted by code, and no wall
/// clock, path or environment value is read.
///
/// The value comes out of the private types below, so a property the schema does
/// not define cannot be added without changing one of those structs.
pub fn to_sarif(report: &ScanReport) -> serde_json::Value {
    let uri = format!("{}.wasm", report.wasm_sha256);

    let results: Vec<SarifResult> = report
        .indicators
        .iter()
        .map(|indicator| SarifResult {
            rule_id: indicator.code,
            kind: if indicator.informational {
                KIND_INFORMATIONAL
            } else {
                KIND_REVIEW
            },
            level: LEVEL_NONE,
            message: SarifMessage {
                text: message_text(indicator.code, &indicator.facts),
            },
            locations: vec![module_location(&uri)],
        })
        .chain(report.not_checked.iter().copied().map(|code| SarifResult {
            rule_id: code,
            kind: KIND_REVIEW,
            level: LEVEL_NONE,
            message: SarifMessage {
                text: code.to_owned(),
            },
            locations: vec![module_location(&uri)],
        }))
        .collect();

    let mut ids: Vec<&'static str> = results.iter().map(|result| result.rule_id).collect();
    ids.sort_unstable();
    ids.dedup();

    let log = SarifLog {
        schema_uri: SARIF_SCHEMA_URI,
        version: SARIF_VERSION,
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: TOOL_NAME,
                    version: report.ruleset_version,
                    rules: ids.iter().copied().map(|id| SarifRule { id }).collect(),
                },
            },
            artifacts: vec![SarifArtifact {
                location: ArtifactLocation { uri: uri.clone() },
                hashes: BTreeMap::from([("sha-256", report.wasm_sha256.clone())]),
                roles: [ROLE_ANALYSIS_TARGET],
            }],
            results,
        }],
    };
    // Infallible: every field is a string, a map of strings, or a vector of those.
    serde_json::to_value(log).expect("SARIF log serialization cannot fail")
}

/// A whole-module observation, located at the artifact and nowhere else.
fn module_location(uri: &str) -> SarifLocation {
    SarifLocation {
        physical_location: PhysicalLocation {
            artifact_location: ArtifactLocation {
                uri: uri.to_owned(),
            },
        },
    }
}

/// `CODE key=value key=value`: identifiers and the report's own facts, never a
/// sentence. Facts are a `BTreeMap`, so their order is fixed.
fn message_text(code: &str, facts: &BTreeMap<String, String>) -> String {
    let mut text = String::with_capacity(code.len() + facts.len() * 16);
    text.push_str(code);
    for (key, value) in facts {
        text.push(' ');
        text.push_str(key);
        text.push('=');
        text.push_str(value);
    }
    text
}
