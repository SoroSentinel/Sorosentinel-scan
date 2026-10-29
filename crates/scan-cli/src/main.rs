//! `sorosentinel-scan <file.wasm | -> [--known-bad-hashes <file>] [--format json|sarif]`
//!
//! Prints a ScanReport as JSON on stdout, or the same report as SARIF 2.1.0 with
//! `--format sarif`. On failure prints {"error": "<code>"} on stderr and exits 1
//! (Intel treats any error as unanalyzable); usage errors exit 2. No network
//! access: Intel supplies the bytes.
#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{self, Read};
use std::process::ExitCode;

use scan_core::limits::{MAX_KNOWN_BAD_HASHES, MAX_MODULE_BYTES};
use scan_core::{KnownBadHashes, ScanError, scan, to_sarif};

const USAGE: &str =
    "usage: sorosentinel-scan <file.wasm | -> [--known-bad-hashes <file>] [--format json|sarif]";

/// JSON is the default and the complete record; SARIF is the same report
/// rendered for code-scanning tools.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    Json,
    Sarif,
}

struct Options {
    input: String,
    hashes: Option<String>,
    format: Format,
}

/// Rejects anything it does not understand: an unknown or repeated flag, a flag
/// with no value, a `--format` other than the two names, or more than one
/// positional argument. Guessing an output format would silently change what a
/// consumer parses.
fn parse(args: &[String]) -> Result<Options, ()> {
    let mut input: Option<&str> = None;
    let mut hashes: Option<&str> = None;
    let mut format: Option<Format> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--known-bad-hashes" => {
                if hashes.is_some() {
                    return Err(());
                }
                hashes = Some(args.get(i + 1).ok_or(())?);
                i += 2;
            }
            "--format" => {
                if format.is_some() {
                    return Err(());
                }
                let value = args.get(i + 1).ok_or(())?;
                format = Some(match value.as_str() {
                    "json" => Format::Json,
                    "sarif" => Format::Sarif,
                    _ => return Err(()),
                });
                i += 2;
            }
            other => {
                // `-` is the documented stdin name, not an unknown flag.
                if input.is_some() || (other.starts_with('-') && other != "-") {
                    return Err(());
                }
                input = Some(other);
                i += 1;
            }
        }
    }
    Ok(Options {
        input: input.ok_or(())?.to_owned(),
        hashes: hashes.map(str::to_owned),
        format: format.unwrap_or(Format::Json),
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let options = match parse(&args) {
        Ok(options) => options,
        Err(()) => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&options) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(code) => {
            eprintln!("{}", serde_json::json!({ "error": code }));
            ExitCode::FAILURE
        }
    }
}

fn run(options: &Options) -> Result<String, &'static str> {
    let bytes = if options.input == "-" {
        read_capped(io::stdin().lock(), MAX_MODULE_BYTES)
    } else {
        File::open(&options.input)
            .map_err(|_| "unreadable_input")
            .and_then(|f| read_capped(f, MAX_MODULE_BYTES))
    }?;
    let known_bad = match &options.hashes {
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
    // The JSON path is unchanged: same struct, same serializer, same bytes.
    match options.format {
        Format::Json => serde_json::to_string(&report).map_err(|_| "serialize_failed"),
        Format::Sarif => serde_json::to_string(&to_sarif(&report)).map_err(|_| "serialize_failed"),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn json_is_the_default_and_stays_first() {
        let parsed = parse(&args(&["m.wasm"])).unwrap();
        assert!(parsed.hashes.is_none());
        assert_eq!(parsed.format, Format::Json);
        assert_eq!(parsed.input, "m.wasm");
    }

    #[test]
    fn flags_work_in_either_order_and_the_input_may_be_stdin() {
        let both = args(&["-", "--format", "sarif", "--known-bad-hashes", "h.txt"]);
        let parsed = parse(&both).unwrap();
        assert_eq!(parsed.input, "-");
        assert_eq!(parsed.format, Format::Sarif);
        assert_eq!(parsed.hashes.as_deref(), Some("h.txt"));

        let flipped = args(&["-", "--known-bad-hashes", "h.txt", "--format", "sarif"]);
        assert_eq!(parse(&flipped).unwrap().format, Format::Sarif);
    }

    #[test]
    fn anything_unrecognized_is_a_usage_error_not_a_guess() {
        for case in [
            vec![],
            args(&["a.wasm", "b.wasm"]),
            args(&["--unknown", "x"]),
            args(&["a.wasm", "--format"]),
            args(&["a.wasm", "--format", "yaml"]),
            args(&["a.wasm", "--format", "sarif", "--format", "json"]),
            args(&[
                "a.wasm",
                "--known-bad-hashes",
                "h1",
                "--known-bad-hashes",
                "h2",
            ]),
            args(&["a.wasm", "--known-bad-hashes"]),
            args(&["--format", "sarif"]),
        ] {
            assert!(parse(&case).is_err(), "accepted {case:?}");
        }
    }
}
