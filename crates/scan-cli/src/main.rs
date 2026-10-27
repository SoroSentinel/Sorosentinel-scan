//! `sorosentinel-scan <file.wasm | -> [--known-bad-hashes <file>]`
//!
//! Prints a ScanReport as JSON on stdout. On failure prints {"error": "<code>"}
//! on stderr and exits 1 (Intel treats any error as unanalyzable); usage
//! errors exit 2. No network access: Intel supplies the bytes.
#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{self, Read};
use std::process::ExitCode;

use scan_core::limits::{MAX_KNOWN_BAD_HASHES, MAX_MODULE_BYTES};
use scan_core::{KnownBadHashes, ScanError, scan};

const USAGE: &str = "usage: sorosentinel-scan <file.wasm | -> [--known-bad-hashes <file>]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (input, hashes) = match args.as_slice() {
        [input] => (input.as_str(), None),
        [input, flag, file] if flag == "--known-bad-hashes" => {
            (input.as_str(), Some(file.as_str()))
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(input, hashes) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(code) => {
            eprintln!("{}", serde_json::json!({ "error": code }));
            ExitCode::FAILURE
        }
    }
}

fn run(input: &str, hashes: Option<&str>) -> Result<String, &'static str> {
    let bytes = if input == "-" {
        read_capped(io::stdin().lock(), MAX_MODULE_BYTES)
    } else {
        File::open(input)
            .map_err(|_| "unreadable_input")
            .and_then(|f| read_capped(f, MAX_MODULE_BYTES))
    }?;
    let known_bad = match hashes {
        None => KnownBadHashes::default(),
        Some(path) => {
            // 65 bytes per line (64 hex + newline) bounds the list size.
            let raw = File::open(path)
                .map_err(|_| "unreadable_hash_list")
                .and_then(|f| read_capped(f, MAX_KNOWN_BAD_HASHES * 65))?;
            let text = String::from_utf8(raw).map_err(|_| ScanError::BadHashList.code())?;
            KnownBadHashes::parse(&text).map_err(|e| e.code())?
        }
    };
    let report = scan(&bytes, &known_bad).map_err(|e| e.code())?;
    serde_json::to_string(&report).map_err(|_| "serialize_failed")
}

/// Reads at most `cap` bytes; more than that is an error, never a truncated scan.
fn read_capped(reader: impl Read, cap: usize) -> Result<Vec<u8>, &'static str> {
    let mut buf = Vec::new();
    reader
        .take(cap as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|_| "unreadable_input")?;
    if buf.len() > cap {
        return Err(ScanError::TooLarge.code());
    }
    Ok(buf)
}
