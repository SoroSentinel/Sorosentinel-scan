//! SARIF 2.1.0 output: the properties the schema requires, the kinds and levels
//! AGENTS.md §3 permits, and the §5 rule that this repo writes no prose.
//!
//! The schema sets `additionalProperties: false` on every object it defines, so
//! each shape test asserts the exact property-name set rather than only the
//! members it expects.

mod common;

use std::collections::BTreeMap;

use common::module;
use scan_core::{Indicator, KnownBadHashes, RULESET_VERSION, ScanReport, scan, to_sarif};
use serde_json::Value;

const SPEC: (&str, &[u8]) = ("contractspecv0", b"");
const HOSTILE_IMPORTS: &[(&str, &str)] = &[("l", "6"), ("l", "3"), ("d", "_")];

fn scan_bytes(bytes: &[u8]) -> ScanReport {
    scan(bytes, &KnownBadHashes::default()).expect("scan")
}

fn log(report: &ScanReport) -> Value {
    to_sarif(report)
}

/// Owned copies: a test that fails mid-assertion needs the value printed, and
/// borrowing out of a `log()` temporary cannot work.
fn run(report: &ScanReport) -> Value {
    log(report)["runs"][0].clone()
}

fn results(report: &ScanReport) -> Vec<Value> {
    run(report)["results"]
        .as_array()
        .expect("results array")
        .clone()
}

/// The keys present on an object, so a comparison is against the whole set.
fn keys(value: &Value) -> Vec<String> {
    let mut names: Vec<String> = value.as_object().expect("object").keys().cloned().collect();
    names.sort();
    names
}

fn sorted(names: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = names.iter().map(|s| (*s).to_owned()).collect();
    out.sort();
    out
}

#[test]
fn root_has_exactly_version_schema_and_runs() {
    let value = log(&scan_bytes(&module(&[], &["hello"], &[SPEC])));
    assert_eq!(keys(&value), sorted(&["$schema", "version", "runs"]));
    assert_eq!(value["version"], "2.1.0");
    assert_eq!(
        value["$schema"],
        "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
    );
    assert_eq!(value["runs"].as_array().expect("runs").len(), 1);
}

#[test]
fn driver_is_the_binary_and_the_pinned_ruleset() {
    let driver = run(&scan_bytes(&module(HOSTILE_IMPORTS, &[], &[])))["tool"]["driver"].clone();
    assert_eq!(keys(&driver), sorted(&["name", "rules", "version"]));
    assert_eq!(driver["name"], "sorosentinel-scan");
    assert_eq!(driver["version"], RULESET_VERSION);
}

#[test]
fn the_artifact_is_the_module_named_by_its_own_hash() {
    let report = scan_bytes(&module(&[], &["hello"], &[SPEC]));
    let artifact = run(&report)["artifacts"][0].clone();
    assert_eq!(keys(&artifact), sorted(&["hashes", "location", "roles"]));
    assert_eq!(
        artifact["roles"],
        Value::Array(vec!["analysisTarget".into()])
    );
    assert_eq!(keys(&artifact["hashes"]), sorted(&["sha-256"]));
    assert_eq!(artifact["hashes"]["sha-256"], report.wasm_sha256);
    assert_eq!(keys(&artifact["location"]), sorted(&["uri"]));
    assert_eq!(
        artifact["location"]["uri"],
        format!("{}.wasm", report.wasm_sha256)
    );
}

#[test]
fn informational_indicators_are_informational_and_claim_no_severity() {
    let report = scan_bytes(&module(HOSTILE_IMPORTS, &[], &[]));
    let results = results(&report);
    assert!(
        results
            .iter()
            .any(|r| r["ruleId"] == "S-UPGRADEABLE" && r["kind"] == "informational")
    );
    assert!(
        results
            .iter()
            .all(|r| r["level"] == "none" && r["kind"] != "fail"),
        "a Scan result may not be a determination: {results:?}"
    );
}

#[test]
fn every_result_carries_exactly_the_properties_this_repo_controls() {
    let report = scan_bytes(&module(HOSTILE_IMPORTS, &[], &[]));
    let results = results(&report);
    for result in &results {
        assert_eq!(
            keys(result),
            sorted(&["kind", "level", "locations", "message", "ruleId"]),
            "{result:?}"
        );
        assert_eq!(keys(&result["message"]), sorted(&["text"]));
        // A whole-module observation has no region, so it locates the artifact only.
        let location = &result["locations"][0];
        assert_eq!(keys(location), sorted(&["physicalLocation"]));
        let physical = &location["physicalLocation"];
        assert_eq!(keys(physical), sorted(&["artifactLocation"]));
        assert_eq!(keys(&physical["artifactLocation"]), sorted(&["uri"]));
    }
}

#[test]
fn known_bad_hash_is_a_review_not_a_failure() {
    let bytes = module(&[], &[], &[SPEC]);
    let sha = scan_bytes(&bytes).wasm_sha256;
    let list = KnownBadHashes::parse(&format!("{sha}\n")).expect("hash list");
    let report = scan(&bytes, &list).expect("scan");
    let results = results(&report);
    let bad = results
        .iter()
        .find(|r| r["ruleId"] == "S-KNOWN-BAD-HASH")
        .expect("indicator");
    // §3.3: an automated signal needs human confirmation, which is what `review` says.
    assert_eq!(bad["kind"], "review");
    assert_eq!(bad["level"], "none");
    assert_eq!(bad["message"]["text"], "S-KNOWN-BAD-HASH");
}

#[test]
fn not_checked_codes_are_review_results_on_every_scan() {
    let report = scan_bytes(&module(&[], &["hello"], &[SPEC]));
    let results = results(&report);
    assert!(report.indicators.is_empty());
    assert_eq!(results.len(), report.not_checked.len());
    for code in &report.not_checked {
        let found = results
            .iter()
            .filter(|r| r["ruleId"] == *code)
            .collect::<Vec<_>>();
        assert_eq!(found.len(), 1, "{code} reported once");
        assert_eq!(found[0]["kind"], "review", "{code}");
        assert_eq!(found[0]["level"], "none", "{code}");
        assert_eq!(found[0]["message"]["text"], *code);
    }
}

#[test]
fn a_fact_becomes_key_equals_value_and_nothing_else() {
    let mut facts = BTreeMap::new();
    facts.insert("claimed_protocol_version".to_owned(), "19".to_owned());
    facts.insert("claimed_pre_release".to_owned(), "false".to_owned());
    let report = ScanReport {
        wasm_sha256: "a".repeat(64),
        ruleset_version: RULESET_VERSION,
        indicators: vec![Indicator {
            code: "S-OLD-SDK",
            informational: true,
            facts,
        }],
        not_checked: vec![],
        claimed_meta: scan_bytes(&module(&[], &[], &[SPEC])).claimed_meta,
    };
    let results = results(&report);
    assert_eq!(results.len(), 1);
    // Facts are a BTreeMap, so their order in the message is fixed.
    assert_eq!(
        results[0]["message"]["text"],
        "S-OLD-SDK claimed_pre_release=false claimed_protocol_version=19"
    );
}

#[test]
fn no_message_is_a_sentence_and_no_string_uses_a_blocked_term() {
    let bytes = module(HOSTILE_IMPORTS, &[], &[]);
    let report = scan_bytes(&bytes);
    for result in results(&report) {
        let text = result["message"]["text"].as_str().expect("text");
        let mut words = text.split(' ');
        let code = words.next().expect("code first");
        assert_eq!(result["ruleId"], code);
        for token in words {
            assert!(token.contains('='), "{token} is not a key=value fact");
            assert!(!token.contains('.'), "{token} looks like prose");
        }
    }
    // AGENTS.md §5 blocklist, plus the §3.1 word, checked over the whole log.
    let rendered = serde_json::to_string(&log(&report)).expect("serialize");
    for blocked in [
        "safe",
        "scam",
        "fraud",
        "fake",
        "stolen",
        "theft",
        "hack",
        "criminal",
        "illegal",
        "malicious",
        "rug pull",
        "ponzi",
        "designed to",
        "tries to",
    ] {
        assert!(
            !rendered.to_lowercase().contains(blocked),
            "blocked term {blocked:?} in the log"
        );
    }
}

#[test]
fn rules_are_the_distinct_result_codes_in_order() {
    let report = scan_bytes(&module(HOSTILE_IMPORTS, &[], &[]));
    let run = run(&report);
    let rules = run["tool"]["driver"]["rules"].as_array().expect("rules");
    let mut ids: Vec<String> = results(&report)
        .iter()
        .filter_map(|r| r["ruleId"].as_str().map(str::to_owned))
        .collect();
    ids.sort();
    ids.dedup();
    let declared: Vec<String> = rules
        .iter()
        .map(|rule| {
            assert_eq!(
                keys(rule),
                sorted(&["id"]),
                "a rule may carry no prose: {rule:?}"
            );
            rule["id"].as_str().expect("id").to_owned()
        })
        .collect();
    assert_eq!(declared, ids);
    assert!(!declared.is_empty());
}

#[test]
fn the_same_bytes_and_ruleset_give_the_same_bytes_out() {
    for bytes in [
        module(&[], &["hello"], &[SPEC]),
        module(HOSTILE_IMPORTS, &[], &[]),
        module(&[], &[], &[]),
    ] {
        let a = serde_json::to_string(&log(&scan_bytes(&bytes))).expect("first");
        let b = serde_json::to_string(&log(&scan_bytes(&bytes))).expect("second");
        assert_eq!(a, b);
    }
}

#[test]
fn a_module_that_fails_to_parse_is_an_error_not_an_empty_log() {
    // Nothing to assert about SARIF here: the caller only converts a report, and
    // an unparseable module never produces one. Pinned so a future change that
    // swallowed parse errors into an empty log is caught.
    assert!(scan(b"not wasm at all", &KnownBadHashes::default()).is_err());
}
