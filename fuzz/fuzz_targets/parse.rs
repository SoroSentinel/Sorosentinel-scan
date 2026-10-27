//! Parser alone: validation, payload walk and every cap.
//! Properties: never panics; accepted modules respect the caps.
#![no_main]

use libfuzzer_sys::fuzz_target;
use scan_core::limits::{MAX_CUSTOM_SECTIONS, MAX_EXPORTS, MAX_IMPORTS, MAX_NAME_BYTES};
use scan_core::parse::parse;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = parse(data) {
        assert!(m.function_imports.len() <= MAX_IMPORTS);
        assert!(m.function_exports.len() <= MAX_EXPORTS);
        assert!(m.custom_sections.len() <= MAX_CUSTOM_SECTIONS);
        let names = m
            .function_imports
            .iter()
            .flat_map(|(a, b)| [a, b])
            .chain(&m.function_exports)
            .chain(&m.custom_sections);
        for name in names {
            assert!(name.len() <= MAX_NAME_BYTES);
        }
    }
});
