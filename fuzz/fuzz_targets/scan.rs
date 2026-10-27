//! Full scan path as the CLI runs it: validate, parse, detect, serialize.
//! Properties: never panics, output is deterministic and has the schema shape.
#![no_main]

use libfuzzer_sys::fuzz_target;
use scan_core::{KnownBadHashes, scan};

fuzz_target!(|data: &[u8]| {
    let none = KnownBadHashes::default();
    let first = scan(data, &none);
    assert_eq!(first, scan(data, &none), "scan is not deterministic");

    if let Ok(report) = first {
        assert_eq!(report.wasm_sha256.len(), 64);
        assert!(!report.not_checked.is_empty());
        assert!(report.indicators.windows(2).all(|w| w[0].code < w[1].code));
        let json = serde_json::to_string(&report).expect("report serializes");

        // The same bytes on the known-bad list add exactly one indicator.
        let bad = KnownBadHashes::parse(&report.wasm_sha256).expect("own hash parses");
        let flagged = scan(data, &bad).expect("same bytes scan again");
        assert_eq!(flagged.indicators.len(), report.indicators.len() + 1);
        assert!(json.len() < 64 * 1024);
    }
});
