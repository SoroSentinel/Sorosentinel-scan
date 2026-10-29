//! The `contractspecv0` reader, fed raw section bytes and raw modules.
//! Properties: never panics; a claim only ever comes from exactly one retained
//! body; nothing a module claims can reach a fact as control or non-identifier
//! text; the same bytes always give the same report.
#![no_main]

/// The characters AGENTS.md §5 requires stripping from untrusted text before
/// it can be shown: directional controls, zero-width joiners and the
/// invisible formatting marks used to reorder or hide a displayed name.
fn is_bidi_or_joiner(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
    )
}

use libfuzzer_sys::fuzz_target;
use scan_core::limits::{MAX_SPEC_BYTES, MAX_SPEC_SECTIONS};
use scan_core::{KnownBadHashes, parse, scan, spec};

fuzz_target!(|data: &[u8]| {
    // The reader is total: any body at all either yields signatures or none.
    let signatures = spec::signatures(&[data.to_vec()]);

    // Claims made twice cancel out, whatever they say.
    assert!(spec::signatures(&[data.to_vec(), data.to_vec()]).is_none());

    if let Some(functions) = &signatures {
        for f in functions {
            // Names reach indicator facts, so they must already be safe.
            assert!(
                f.name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "unsafe claimed name: {:?}",
                f.name
            );
            for t in &f.inputs {
                assert!(t.len() <= 512, "rendered type too long for a fact: {t}");
            }
        }
        // A claim only ever comes from a body that was retained whole.
        assert!(data.len() <= MAX_SPEC_BYTES);
    }

    // Whatever the module claims, the comparison is deterministic and its
    // facts stay inside the schema limit.
    let first = scan(data, &KnownBadHashes::default()).ok();
    let second = scan(data, &KnownBadHashes::default()).ok();
    assert_eq!(first, second, "scan is not deterministic");

    if let Some(r) = &first {
        if let Some(deviation) = r.indicators.iter().find(|i| i.code == "S-SEP41-DEVIATION") {
            assert!(deviation.informational, "must never raise a level alone");
            for (key, value) in &deviation.facts {
                assert!(value.len() <= 512, "fact {key} breaks the schema limit");
                assert!(!value.is_empty(), "fact {key} is empty");
                assert!(
                    value.chars().all(|c| !c.is_control() && !is_bidi_or_joiner(c)),
                    "fact {key} carries control or bidi text"
                );
            }
            // Only the ten baseline names may be listed as missing.
            if let Some(missing) = deviation.facts.get("missing_functions") {
                for name in missing.split(',') {
                    assert!(
                        spec::SEP41.iter().any(|entry| entry.0 == name),
                        "missing name is not an interface name: {name}"
                    );
                }
            }
        }
    }

    if let Ok(m) = parse::parse(data) {
        assert!(m.spec_bodies.len() <= MAX_SPEC_SECTIONS);
        assert!(m.spec_bodies.iter().all(|b| b.len() <= MAX_SPEC_BYTES));
        if m.spec_bodies.len() > 1 {
            assert!(spec::signatures(&m.spec_bodies).is_none());
        }
        if spec::signatures(&m.spec_bodies).is_some() {
            // A claim that survived both gates came from exactly one real
            // section, and a non-empty one.
            assert!(m.has_custom_section(spec::SPEC_SECTION));
            assert_eq!(m.spec_bodies.len(), 1);
            assert!(!m.spec_bodies[0].is_empty());
        }
    }
});
