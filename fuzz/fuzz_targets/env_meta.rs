//! The `contractenvmetav0` claim reader, fed raw section bytes and raw modules.
//! Properties: never panics; a claim only ever comes from a 12-byte body; a
//! module that makes two claims yields neither.
#![no_main]

use libfuzzer_sys::fuzz_target;
use scan_core::limits::{MAX_ENV_META_BYTES, MAX_ENV_META_SECTIONS};
use scan_core::meta;
use scan_core::parse;

fuzz_target!(|data: &[u8]| {
    // Only an exactly-12-byte body can produce a claim.
    assert!(meta::parse(Some(data)).is_none_or(|c| data.len() == 12));
    // Duplicated claims cancel out, whatever they say.
    assert!(meta::claim(&[data.to_vec(), data.to_vec()]).is_none());

    if let Ok(m) = parse::parse(data) {
        assert!(m.env_meta_bodies.len() <= MAX_ENV_META_SECTIONS);
        assert!(
            m.env_meta_bodies
                .iter()
                .all(|b| b.len() <= MAX_ENV_META_BYTES)
        );
        if m.env_meta_bodies.len() > 1 {
            assert!(meta::claim(&m.env_meta_bodies).is_none());
        }
        if meta::claim(&m.env_meta_bodies).is_some() {
            // A claim that survived both gates came from exactly one real section.
            assert!(m.has_custom_section(meta::ENV_META_SECTION));
            assert_eq!(meta::sole_body(&m.env_meta_bodies).map(|b| b.len()), Some(12));
        }
    }
});
