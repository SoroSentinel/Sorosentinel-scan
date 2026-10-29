//! End-to-end CLI tests: a real process, real exit codes, both output formats.
//! Scan has no server, so the process boundary is its integration surface.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use scan_core::limits::MAX_MODULE_BYTES;

/// A valid core module with no `contractspecv0`, so it reports `S-NO-SPEC`.
const EMPTY_MODULE: &[u8] = b"\0asm\x01\0\0\0";
/// Right magic, wrong body: parses as nothing.
const NOT_WASM: &[u8] = b"\0asm\x01\x01\x01\x01";

/// Per-process so parallel test runs cannot read each other's fixtures.
fn scratch_dir() -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("sorosentinel-scan-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn fixture(name: &str, bytes: &[u8]) -> PathBuf {
    let mut path = scratch_dir();
    path.push(name);
    let mut file = std::fs::File::create(&path).expect("create fixture");
    file.write_all(bytes).expect("write fixture");
    path
}

/// Runs the binary with `args`, feeding stdin when `input` is `Some`.
fn run(args: &[&str], input: Option<&[u8]>) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sorosentinel-scan"))
        .args(args)
        // Piped explicitly: inherited streams would reach the terminal instead
        // of `Output`, and an assertion on an empty string proves nothing.
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    if let Some(bytes) = input {
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(bytes)
            .expect("write stdin");
    }
    let out = child.wait_with_output().expect("wait");
    (
        out.status.code().expect("exit code"),
        String::from_utf8(out.stdout).expect("utf-8 stdout"),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn stdout_json(args: &[&str]) -> serde_json::Value {
    let (code, stdout, stderr) = run(args, None);
    assert_eq!(code, 0, "exit {code}: {stderr}");
    serde_json::from_str(&stdout).expect("json on stdout")
}

fn rule_ids(log: &serde_json::Value) -> Vec<String> {
    let mut ids: Vec<String> = log["runs"][0]["results"]
        .as_array()
        .expect("results")
        .iter()
        .map(|r| r["ruleId"].as_str().expect("ruleId").to_owned())
        .collect();
    ids.sort();
    ids
}

#[test]
fn json_is_the_default_and_is_the_scan_report() {
    let file = fixture("default.json.wasm", EMPTY_MODULE);
    let report = stdout_json(&[file.to_str().expect("utf-8 path")]);
    assert_eq!(report["wasm_sha256"].as_str().expect("hash").len(), 64);
    assert_eq!(report["ruleset_version"], scan_core::RULESET_VERSION);
    assert_eq!(report["indicators"][0]["code"], "S-NO-SPEC");
    assert!(report["not_checked"].as_array().expect("nc").len() > 1);
}

#[test]
fn sarif_reports_the_same_codes_as_json_and_nothing_else() {
    let file = fixture("both-formats.wasm", EMPTY_MODULE);
    let path = file.to_str().expect("utf-8 path");
    let report = stdout_json(&[path]);
    let log = stdout_json(&[path, "--format", "sarif"]);
    assert_eq!(log["version"], "2.1.0");
    assert_eq!(log["runs"].as_array().expect("runs").len(), 1);
    let mut expected: Vec<String> = report["indicators"]
        .as_array()
        .expect("indicators")
        .iter()
        .map(|i| i["code"].as_str().expect("code").to_owned())
        .chain(
            report["not_checked"]
                .as_array()
                .expect("not_checked")
                .iter()
                .map(|c| c.as_str().expect("code").to_owned()),
        )
        .collect();
    expected.sort();
    assert_eq!(rule_ids(&log), expected);
    // Declared rules and reported results agree, so no consumer sees an unknown id.
    let declared: Vec<String> = log["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules")
        .iter()
        .map(|r| r["id"].as_str().expect("id").to_owned())
        .collect();
    let mut sorted_declared = declared.clone();
    sorted_declared.sort();
    assert_eq!(sorted_declared, expected);
}

#[test]
fn a_known_bad_hash_is_a_review_result_in_sarif() {
    let file = fixture("known-bad.wasm", EMPTY_MODULE);
    let path = file.to_str().expect("utf-8 path");
    let sha = stdout_json(&[path])["wasm_sha256"]
        .as_str()
        .expect("hash")
        .to_owned();
    let list = fixture("known-bad.txt", format!("{sha}\n").as_bytes());
    let list_path = list.to_str().expect("utf-8 path");
    let log = stdout_json(&[path, "--known-bad-hashes", list_path, "--format", "sarif"]);
    let results = log["runs"][0]["results"].as_array().expect("results");
    let bad = results
        .iter()
        .find(|r| r["ruleId"] == "S-KNOWN-BAD-HASH")
        .expect("indicator");
    assert_eq!(bad["kind"], "review");
    assert_eq!(bad["level"], "none");
}

#[test]
fn stdin_and_a_file_give_the_identical_log() {
    let file = fixture("stdin-parity.wasm", EMPTY_MODULE);
    let from_file = stdout_json(&[file.to_str().expect("utf-8 path"), "--format", "sarif"]);
    let (code, stdout, stderr) = run(&["-", "--format", "sarif"], Some(EMPTY_MODULE));
    assert_eq!(code, 0, "exit {code}: {stderr}");
    let from_stdin: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(from_stdin, from_file);
}

#[test]
fn failures_are_loud_on_stderr_and_empty_on_stdout() {
    let bad = fixture("invalid.wasm", NOT_WASM);
    let (code, stdout, stderr) = run(
        &[bad.to_str().expect("utf-8 path"), "--format", "sarif"],
        None,
    );
    // Intel treats any error as unanalyzable, so the code must be machine-readable.
    assert_eq!(code, 1);
    assert_eq!(stdout, "");
    assert_eq!(stderr.trim(), r#"{"error":"invalid_wasm"}"#);

    let mut absent = scratch_dir();
    absent.push("this-file-does-not-exist.wasm");
    let missing = run(&[absent.to_str().expect("utf-8 path")], None);
    assert_eq!(missing.0, 1);
    assert_eq!(missing.1, "");
    assert_eq!(missing.2.trim(), r#"{"error":"unreadable_input"}"#);
}

#[test]
fn an_oversized_module_is_an_error_never_a_truncated_scan() {
    let mut bytes = EMPTY_MODULE.to_vec();
    bytes.resize(MAX_MODULE_BYTES + 1, 0);
    let (code, stdout, stderr) = run(&["-", "--format", "sarif"], Some(&bytes));
    assert_eq!(code, 1);
    assert_eq!(stdout, "");
    assert_eq!(stderr.trim(), r#"{"error":"too_large"}"#);
}

#[test]
fn a_usage_error_exits_2_and_guesses_nothing() {
    for args in [
        vec![],
        vec!["--format", "yaml"],
        vec!["--bogus", "x"],
        vec!["m.wasm", "--format", "sarif", "--format", "json"],
        vec!["m.wasm", "second.wasm"],
    ] {
        let (code, stdout, stderr) = run(&args, None);
        assert_eq!(code, 2, "{args:?}");
        assert_eq!(stdout, "");
        assert!(stderr.starts_with("usage:"), "{args:?} -> {stderr}");
    }
}
