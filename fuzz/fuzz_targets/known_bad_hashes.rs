//! Hash-list parser (the file Intel passes with --known-bad-hashes).
//! Properties: never panics; accepts only 64 lowercase-hex lines.
#![no_main]

use libfuzzer_sys::fuzz_target;
use scan_core::KnownBadHashes;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(list) = KnownBadHashes::parse(text) {
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            assert!(
                line.len() == 64
                    && line
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            );
            assert!(list.contains(line));
        }
    }
});
