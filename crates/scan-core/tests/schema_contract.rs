//! Contract test: every ScanReport validates against Intel's ScanReport schema,
//! pinned in intel-schemas/ (scripts/pin-intel-schemas.sh, `make schemas-check`).
//!
//! No JSON Schema crate: the validator below covers exactly the keywords the
//! pinned schema uses and panics on any other, so a schema change that adds a
//! constraint fails here instead of being skipped. Patterns are read from the
//! schema file, never copied into this test.

mod common;

use std::path::PathBuf;

use common::module;
use scan_core::{KnownBadHashes, scan};
use serde_json::{Map, Value, json};

const SCAN_REPORT_ID: &str = "urn:sorosentinel:schema:v1:ScanReport";
const COMMON_ID: &str = "urn:sorosentinel:schema:v1:common";
const SPEC: (&str, &[u8]) = ("contractspecv0", b"");

fn load(file: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../intel-schemas")
        .join(file);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path:?}: {e}"))
}

struct Schemas {
    root: Value,
    common: Value,
}

impl Schemas {
    fn pinned() -> Self {
        let s = Self {
            root: load("ScanReport.json"),
            common: load("common.json"),
        };
        assert_eq!(s.root["$id"], SCAN_REPORT_ID);
        assert_eq!(s.common["$id"], COMMON_ID);
        s
    }

    /// Resolves `urn:...:common#/$defs/<name>`; any other reference is unsupported.
    fn resolve(&self, reference: &str) -> &Value {
        let name = reference
            .strip_prefix(COMMON_ID)
            .and_then(|r| r.strip_prefix("#/$defs/"))
            .unwrap_or_else(|| panic!("unsupported $ref {reference}"));
        self.common["$defs"]
            .get(name)
            .unwrap_or_else(|| panic!("unresolved $ref {reference}"))
    }

    /// Returns every violation of `schema` by `value`, each prefixed with its path.
    fn validate(&self, schema: &Value, value: &Value, path: &str) -> Vec<String> {
        let mut errs = Vec::new();
        let s = schema
            .as_object()
            .unwrap_or_else(|| panic!("{path}: schema is not an object"));
        for (kw, arg) in s {
            match kw.as_str() {
                "$schema" | "$id" | "title" | "description" | "format" => {}
                "$ref" => errs.extend(self.validate(self.resolve(str_arg(arg)), value, path)),
                "type" => {
                    if !has_type(value, str_arg(arg)) {
                        errs.push(format!("{path}: not of type {arg}"));
                    }
                }
                "required" => {
                    for key in arg.as_array().unwrap() {
                        let key = str_arg(key);
                        if value.as_object().is_some_and(|o| !o.contains_key(key)) {
                            errs.push(format!("{path}: missing required {key}"));
                        }
                    }
                }
                "properties" => {
                    if let Some(obj) = value.as_object() {
                        for (key, sub) in arg.as_object().unwrap() {
                            if let Some(v) = obj.get(key) {
                                errs.extend(self.validate(sub, v, &format!("{path}.{key}")));
                            }
                        }
                    }
                }
                "additionalProperties" => {
                    if let Some(obj) = value.as_object() {
                        let declared = s.get("properties").and_then(Value::as_object);
                        let extra = obj
                            .iter()
                            .filter(|(k, _)| declared.is_none_or(|d| !d.contains_key(*k)));
                        for (key, v) in extra {
                            match arg {
                                Value::Bool(true) => {}
                                Value::Bool(false) => {
                                    errs.push(format!("{path}: unexpected key {key}"))
                                }
                                sub => errs.extend(self.validate(sub, v, &format!("{path}.{key}"))),
                            }
                        }
                    }
                }
                "items" => {
                    if let Some(items) = value.as_array() {
                        for (i, v) in items.iter().enumerate() {
                            errs.extend(self.validate(arg, v, &format!("{path}[{i}]")));
                        }
                    }
                }
                "minItems" => {
                    if value.as_array().is_some_and(|a| a.len() < usize_arg(arg)) {
                        errs.push(format!("{path}: fewer than {arg} items"));
                    }
                }
                "maxLength" => {
                    if value
                        .as_str()
                        .is_some_and(|v| v.chars().count() > usize_arg(arg))
                    {
                        errs.push(format!("{path}: longer than {arg}"));
                    }
                }
                "minimum" => {
                    if value.as_i64().is_some_and(|v| v < arg.as_i64().unwrap()) {
                        errs.push(format!("{path}: below minimum {arg}"));
                    }
                }
                "pattern" => {
                    if let Some(v) = value.as_str()
                        && !Pattern::compile(str_arg(arg)).matches(v)
                    {
                        errs.push(format!("{path}: {v:?} does not match {arg}"));
                    }
                }
                other => panic!("{path}: unsupported schema keyword {other}"),
            }
        }
        errs
    }

    fn check(&self, report: &Value) -> Vec<String> {
        self.validate(&self.root, report, "$")
    }
}

fn str_arg(v: &Value) -> &str {
    v.as_str()
        .unwrap_or_else(|| panic!("expected string, got {v}"))
}

fn usize_arg(v: &Value) -> usize {
    usize::try_from(
        v.as_u64()
            .unwrap_or_else(|| panic!("expected count, got {v}")),
    )
    .unwrap()
}

fn has_type(v: &Value, ty: &str) -> bool {
    match ty {
        "object" => v.is_object(),
        "array" => v.is_array(),
        "string" => v.is_string(),
        "boolean" => v.is_boolean(),
        "integer" => v.is_i64() || v.is_u64(),
        other => panic!("unsupported type {other}"),
    }
}

/// Anchored regex subset: literals, `\` escapes, `[...]` classes with ranges,
/// and the quantifiers `+ * ? {n} {n,} {n,m}`. Anything else panics.
struct Pattern(Vec<(Atom, usize, usize)>);

enum Atom {
    Char(char),
    Class(Vec<(char, char)>),
}

impl Atom {
    fn matches(&self, c: char) -> bool {
        match self {
            Atom::Char(a) => *a == c,
            Atom::Class(ranges) => ranges.iter().any(|(lo, hi)| (*lo..=*hi).contains(&c)),
        }
    }
}

impl Pattern {
    fn compile(src: &str) -> Self {
        let body = src
            .strip_prefix('^')
            .and_then(|s| s.strip_suffix('$'))
            .unwrap_or_else(|| panic!("pattern {src} is not anchored"));
        let mut chars = body.chars().peekable();
        let mut atoms = Vec::new();
        while let Some(c) = chars.next() {
            let atom = match c {
                '\\' => Atom::Char(chars.next().unwrap()),
                '[' => {
                    let mut ranges = Vec::new();
                    loop {
                        match chars.next() {
                            Some(']') => break,
                            Some('^') if ranges.is_empty() => panic!("negated class in {src}"),
                            Some(lo) => {
                                let mut ahead = chars.clone();
                                if ahead.next() == Some('-')
                                    && ahead.peek().is_some_and(|c| *c != ']')
                                {
                                    chars.next();
                                    ranges.push((lo, chars.next().unwrap()));
                                } else {
                                    ranges.push((lo, lo));
                                }
                            }
                            None => panic!("unterminated class in {src}"),
                        }
                    }
                    Atom::Class(ranges)
                }
                '(' | ')' | '|' | '.' | '^' | '$' | '+' | '*' | '?' | '{' | '}' => {
                    panic!("unsupported regex syntax {c:?} in {src}")
                }
                c => Atom::Char(c),
            };
            let (min, max) = match chars.peek() {
                Some('+') => (1, usize::MAX),
                Some('*') => (0, usize::MAX),
                Some('?') => (0, 1),
                Some('{') => {
                    chars.next();
                    let spec: String = chars.by_ref().take_while(|c| *c != '}').collect();
                    let num = |s: &str| s.parse::<usize>().unwrap_or_else(|_| panic!("{src}"));
                    let bounds = match spec.split_once(',') {
                        None => (num(&spec), num(&spec)),
                        Some((lo, "")) => (num(lo), usize::MAX),
                        Some((lo, hi)) => (num(lo), num(hi)),
                    };
                    atoms.push((atom, bounds.0, bounds.1));
                    continue;
                }
                _ => {
                    atoms.push((atom, 1, 1));
                    continue;
                }
            };
            chars.next();
            atoms.push((atom, min, max));
        }
        Pattern(atoms)
    }

    fn matches(&self, s: &str) -> bool {
        let chars: Vec<char> = s.chars().collect();
        Self::match_from(&self.0, &chars)
    }

    fn match_from(atoms: &[(Atom, usize, usize)], s: &[char]) -> bool {
        let Some(((atom, min, max), rest)) = atoms.split_first() else {
            return s.is_empty();
        };
        let run = s.iter().take_while(|c| atom.matches(**c)).count();
        (*min..=run.min(*max))
            .rev()
            .any(|n| Self::match_from(rest, &s[n..]))
    }
}

fn report_json(bytes: &[u8], known_bad: &KnownBadHashes) -> Value {
    serde_json::to_value(scan(bytes, known_bad).unwrap()).unwrap()
}

/// One module per indicator, every indicator at once, and a known-bad hit.
fn sample_reports() -> Vec<Value> {
    let none = KnownBadHashes::default();
    let mut out: Vec<Value> = [
        module(&[], &["hello"], &[SPEC]),
        module(&[], &["hello"], &[]),
        module(&[("l", "6")], &["f"], &[SPEC]),
        module(&[("l", "3"), ("l", "e")], &[], &[SPEC]),
        module(&[("d", "_"), ("d", "0")], &[], &[SPEC]),
        module(&[("d", "_"), ("l", "6"), ("l", "3")], &["a", "b"], &[]),
        module(&[], &[], &[("contractspecv0", &[0xff; 64])]),
    ]
    .iter()
    .map(|m| report_json(m, &none))
    .collect();

    let bad = module(&[("l", "6")], &[], &[SPEC]);
    let sha = scan(&bad, &none).unwrap().wasm_sha256;
    out.push(report_json(&bad, &KnownBadHashes::parse(&sha).unwrap()));
    out
}

#[test]
fn every_report_validates_against_pinned_schema() {
    let schemas = Schemas::pinned();
    let reports = sample_reports();
    let codes: Vec<&str> = reports
        .iter()
        .flat_map(|r| r["indicators"].as_array().unwrap())
        .map(|i| i["code"].as_str().unwrap())
        .collect();
    for code in [
        "S-CREATES-CONTRACTS",
        "S-CROSS-CALL",
        "S-KNOWN-BAD-HASH",
        "S-NO-SPEC",
        "S-UPGRADEABLE",
    ] {
        assert!(codes.contains(&code), "no sample emits {code}");
    }
    for r in &reports {
        let errs = schemas.check(r);
        assert!(errs.is_empty(), "{r}\n{errs:#?}");
    }
}

#[test]
fn top_level_keys_are_exactly_the_schema_properties() {
    let schemas = Schemas::pinned();
    assert_eq!(schemas.root["additionalProperties"], false);
    let declared: Vec<&String> = schemas.root["properties"]
        .as_object()
        .unwrap()
        .keys()
        .collect();
    let required: Vec<&str> = schemas.root["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(str_arg)
        .collect();
    for r in sample_reports() {
        let keys: Vec<&String> = r.as_object().unwrap().keys().collect();
        assert_eq!(keys, declared);
        assert!(required.iter().all(|k| r.get(*k).is_some()));
    }
}

#[test]
fn claimed_meta_keys_are_allowed_by_schema() {
    let schemas = Schemas::pinned();
    let meta = &schemas.root["properties"]["claimed_meta"];
    assert_eq!(meta["additionalProperties"], false);
    let allowed = meta["properties"].as_object().unwrap();
    for r in sample_reports() {
        for key in r["claimed_meta"].as_object().unwrap().keys() {
            assert!(
                allowed.contains_key(key),
                "claimed_meta.{key} not in schema"
            );
        }
    }
}

// ---- the validator rejects what the schema forbids ----

fn mutated(f: impl FnOnce(&mut Map<String, Value>)) -> Value {
    let mut r = report_json(
        &module(&[("l", "6")], &[], &[SPEC]),
        &KnownBadHashes::default(),
    );
    f(r.as_object_mut().unwrap());
    r
}

#[test]
fn validator_rejects_schema_violations() {
    let schemas = Schemas::pinned();
    let cases: Vec<(&str, Value)> = vec![
        (
            "extra top-level key",
            mutated(|r| {
                r.insert("verdict".into(), json!("x"));
            }),
        ),
        (
            "missing required",
            mutated(|r| {
                r.remove("not_checked");
            }),
        ),
        (
            "uppercase sha256",
            mutated(|r| {
                r.insert("wasm_sha256".into(), json!("A".repeat(64)));
            }),
        ),
        (
            "short sha256",
            mutated(|r| {
                r.insert("wasm_sha256".into(), json!("a".repeat(63)));
            }),
        ),
        (
            "ruleset_version shape",
            mutated(|r| {
                r.insert("ruleset_version".into(), json!("26.10.1"));
            }),
        ),
        (
            "ruleset_version trailing",
            mutated(|r| {
                r.insert("ruleset_version".into(), json!("2026.10.1x"));
            }),
        ),
        (
            "indicator code prefix",
            mutated(|r| {
                r["indicators"][0]["code"] = json!("G-UPGRADEABLE");
            }),
        ),
        (
            "indicator code lowercase",
            mutated(|r| {
                r["indicators"][0]["code"] = json!("S-upgradeable");
            }),
        ),
        (
            "informational not boolean",
            mutated(|r| {
                r["indicators"][0]["informational"] = json!("true");
            }),
        ),
        (
            "indicator extra key",
            mutated(|r| {
                r["indicators"][0]["level"] = json!("high");
            }),
        ),
        (
            "non-string fact",
            mutated(|r| {
                r["indicators"][0]["facts"] = json!({ "n": 1 });
            }),
        ),
        (
            "empty not_checked",
            mutated(|r| {
                r.insert("not_checked".into(), json!([]));
            }),
        ),
        (
            "not_checked prefix",
            mutated(|r| {
                r.insert("not_checked".into(), json!(["SOURCE-CODE"]));
            }),
        ),
        (
            "claimed_meta extra key",
            mutated(|r| {
                r["claimed_meta"]["safe"] = json!(true);
            }),
        ),
        (
            "claimed_meta wrong type",
            mutated(|r| {
                r["claimed_meta"]["spec_present"] = json!("yes");
            }),
        ),
    ];
    for (name, report) in cases {
        assert!(!schemas.check(&report).is_empty(), "accepted: {name}");
    }
}

#[test]
#[should_panic(expected = "unsupported regex syntax")]
fn pattern_subset_refuses_unknown_syntax() {
    Pattern::compile("^(a|b)$");
}
