//! Synthetic modules are assembled byte by byte below, so no real contract
//! (and no malware) is needed to exercise every indicator and hostile path.

use scan_core::limits::{MAX_CUSTOM_SECTIONS, MAX_MODULE_BYTES};
use scan_core::{KnownBadHashes, RULESET_VERSION, ScanError, scan};

fn leb(mut n: u32, out: &mut Vec<u8>) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn name(s: &str, out: &mut Vec<u8>) {
    leb(s.len() as u32, out);
    out.extend_from_slice(s.as_bytes());
}

fn section(id: u8, body: Vec<u8>, out: &mut Vec<u8>) {
    out.push(id);
    leb(body.len() as u32, out);
    out.extend(body);
}

/// A valid core module: function imports of type () -> (), exported no-op
/// functions, and custom sections at the end.
fn module(imports: &[(&str, &str)], exports: &[&str], customs: &[(&str, &[u8])]) -> Vec<u8> {
    let mut m = b"\0asm\x01\0\0\0".to_vec();
    section(1, vec![1, 0x60, 0, 0], &mut m);
    if !imports.is_empty() {
        let mut b = Vec::new();
        leb(imports.len() as u32, &mut b);
        for (module, field) in imports {
            name(module, &mut b);
            name(field, &mut b);
            b.extend([0x00, 0x00]); // func, type 0
        }
        section(2, b, &mut m);
    }
    if !exports.is_empty() {
        let mut funcs = Vec::new();
        leb(exports.len() as u32, &mut funcs);
        funcs.extend(std::iter::repeat_n(0u8, exports.len()));
        section(3, funcs, &mut m);
        let mut ex = Vec::new();
        leb(exports.len() as u32, &mut ex);
        for (i, e) in exports.iter().enumerate() {
            name(e, &mut ex);
            ex.push(0x00);
            leb((imports.len() + i) as u32, &mut ex);
        }
        section(7, ex, &mut m);
        let mut code = Vec::new();
        leb(exports.len() as u32, &mut code);
        for _ in exports {
            code.extend([2, 0, 0x0b]); // size, no locals, end
        }
        section(10, code, &mut m);
    }
    for (n, data) in customs {
        let mut b = Vec::new();
        name(n, &mut b);
        b.extend_from_slice(data);
        section(0, b, &mut m);
    }
    m
}

fn codes(bytes: &[u8]) -> Vec<&'static str> {
    scan(bytes, &KnownBadHashes::default())
        .unwrap()
        .indicators
        .iter()
        .map(|i| i.code)
        .collect()
}

const SPEC: (&str, &[u8]) = ("contractspecv0", b"");

#[test]
fn minimal_contract_reports_only_what_was_not_checked() {
    let r = scan(
        &module(&[], &["hello"], &[SPEC]),
        &KnownBadHashes::default(),
    )
    .unwrap();
    assert!(r.indicators.is_empty());
    assert!(r.claimed_meta.spec_present);
    assert_eq!(r.ruleset_version, RULESET_VERSION);
    assert!(!r.not_checked.is_empty());
    assert_eq!(r.wasm_sha256.len(), 64);
}

#[test]
fn missing_spec_section() {
    let bytes = module(&[], &["hello"], &[]);
    assert_eq!(codes(&bytes), ["S-NO-SPEC"]);
    assert!(
        !scan(&bytes, &KnownBadHashes::default())
            .unwrap()
            .claimed_meta
            .spec_present
    );
}

#[test]
fn upgradeable() {
    assert_eq!(
        codes(&module(&[("l", "6")], &["f"], &[SPEC])),
        ["S-UPGRADEABLE"]
    );
}

#[test]
fn creates_contracts_either_host_function() {
    assert_eq!(
        codes(&module(&[("l", "3")], &[], &[SPEC])),
        ["S-CREATES-CONTRACTS"]
    );
    assert_eq!(
        codes(&module(&[("l", "e")], &[], &[SPEC])),
        ["S-CREATES-CONTRACTS"]
    );
}

#[test]
fn cross_call_either_host_function() {
    assert_eq!(
        codes(&module(&[("d", "_")], &[], &[SPEC])),
        ["S-CROSS-CALL"]
    );
    assert_eq!(
        codes(&module(&[("d", "0")], &[], &[SPEC])),
        ["S-CROSS-CALL"]
    );
}

#[test]
fn lookalike_imports_do_not_match() {
    // Same function code in a different module, and the module code with another name.
    assert!(codes(&module(&[("x", "6"), ("l", "7"), ("d", "1")], &[], &[SPEC])).is_empty());
}

#[test]
fn indicators_are_sorted_and_informational() {
    let r = scan(
        &module(&[("d", "_"), ("l", "6"), ("l", "3")], &[], &[]),
        &KnownBadHashes::default(),
    )
    .unwrap();
    let got: Vec<_> = r.indicators.iter().map(|i| i.code).collect();
    assert_eq!(
        got,
        [
            "S-CREATES-CONTRACTS",
            "S-CROSS-CALL",
            "S-NO-SPEC",
            "S-UPGRADEABLE"
        ]
    );
    assert!(r.indicators.iter().all(|i| i.informational));
}

#[test]
fn known_bad_hash_is_not_informational() {
    let bytes = module(&[], &[], &[SPEC]);
    let sha = scan(&bytes, &KnownBadHashes::default())
        .unwrap()
        .wasm_sha256;
    let list = KnownBadHashes::parse(&format!("\n{sha}\n")).unwrap();
    let r = scan(&bytes, &list).unwrap();
    assert_eq!(r.indicators.len(), 1);
    assert_eq!(r.indicators[0].code, "S-KNOWN-BAD-HASH");
    assert!(!r.indicators[0].informational);
}

#[test]
fn hash_list_rejects_malformed_lines() {
    for bad in ["xyz", &"A".repeat(64), &"a".repeat(63), &"a".repeat(65)] {
        assert_eq!(
            KnownBadHashes::parse(bad).unwrap_err(),
            ScanError::BadHashList,
            "{bad}"
        );
    }
}

#[test]
fn spec_section_is_a_claim_not_inspected() {
    // Garbage inside contractspecv0 is still just "present".
    let r = scan(
        &module(&[], &[], &[("contractspecv0", &[0xff; 64])]),
        &KnownBadHashes::default(),
    )
    .unwrap();
    assert!(r.claimed_meta.spec_present);
}

#[test]
fn deterministic_json() {
    let bytes = module(&[("l", "6"), ("d", "0")], &["a", "b"], &[]);
    let a = serde_json::to_string(&scan(&bytes, &KnownBadHashes::default()).unwrap()).unwrap();
    let b = serde_json::to_string(&scan(&bytes, &KnownBadHashes::default()).unwrap()).unwrap();
    assert_eq!(a, b);
}

#[test]
fn json_matches_scan_report_schema_shape() {
    let r = scan(&module(&[("l", "6")], &[], &[]), &KnownBadHashes::default()).unwrap();
    let v: serde_json::Value = serde_json::to_value(&r).unwrap();
    let obj = v.as_object().unwrap();
    let mut keys: Vec<_> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "claimed_meta",
            "indicators",
            "not_checked",
            "ruleset_version",
            "wasm_sha256"
        ]
    );
    assert!(r.indicators.iter().all(|i| i.code.starts_with("S-")));
    assert!(r.not_checked.iter().all(|c| c.starts_with("NC-")));
    let ruleset = r.ruleset_version.split('.').collect::<Vec<_>>();
    assert!(ruleset.len() == 3 && ruleset[0].len() == 4 && ruleset[1].len() == 2);
    assert!(
        r.wasm_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
}

// ---- hostile input ----

#[test]
fn rejects_oversized_module_before_parsing() {
    let mut bytes = module(&[], &[], &[]);
    bytes.resize(MAX_MODULE_BYTES + 1, 0);
    assert_eq!(
        scan(&bytes, &KnownBadHashes::default()),
        Err(ScanError::TooLarge)
    );
}

#[test]
fn rejects_garbage_and_truncation() {
    let valid = module(&[("l", "6")], &["f"], &[SPEC]);
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        b"not wasm at all".to_vec(),
        b"\0asm\x02\0\0\0".to_vec(),
        valid[..valid.len() / 2].to_vec(),
    ];
    for bytes in cases {
        assert!(
            scan(&bytes, &KnownBadHashes::default()).is_err(),
            "{bytes:?}"
        );
    }
}

#[test]
fn rejects_invalid_function_reference() {
    // Export points at function index 5, which does not exist.
    let mut m = b"\0asm\x01\0\0\0".to_vec();
    section(7, vec![1, 1, b'f', 0x00, 5], &mut m);
    assert_eq!(
        scan(&m, &KnownBadHashes::default()),
        Err(ScanError::Invalid)
    );
}

#[test]
fn caps_custom_section_count() {
    let many: Vec<(&str, &[u8])> = (0..=MAX_CUSTOM_SECTIONS).map(|_| ("x", &b""[..])).collect();
    assert_eq!(
        scan(&module(&[], &[], &many), &KnownBadHashes::default()),
        Err(ScanError::LimitExceeded("custom_sections"))
    );
}

#[test]
fn caps_name_length() {
    let long = "a".repeat(300);
    assert_eq!(
        scan(
            &module(&[(&long, "6")], &[], &[]),
            &KnownBadHashes::default()
        ),
        Err(ScanError::LimitExceeded("name_length"))
    );
}

#[test]
fn never_panics_on_byte_mutations() {
    let valid = module(&[("l", "6"), ("d", "_")], &["f", "g"], &[SPEC]);
    let mut ok = 0;
    for i in 0..valid.len() {
        for flip in [0x01u8, 0x80, 0xff] {
            let mut m = valid.clone();
            m[i] ^= flip;
            if scan(&m, &KnownBadHashes::default()).is_ok() {
                ok += 1;
            }
        }
    }
    assert!(ok > 0);
}
