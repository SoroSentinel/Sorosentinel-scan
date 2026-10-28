//! Seed inputs for the `scan` and `parse` fuzz targets, built from the same
//! byte builders as the tests so no binary is committed. `make fuzz-seeds`
//! sets SCAN_FUZZ_SEEDS_DIR and this test writes one `<name>.wasm` per seed
//! there; without it the test only checks that each seed still scans.

mod common;

use common::{module, name, section};
use scan_core::{KnownBadHashes, scan};

fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let header = b"\0asm\x01\0\0\0".to_vec();

    let mut spec_only = header.clone();
    let mut custom = Vec::new();
    name("contractspecv0", &mut custom);
    section(0, custom, &mut spec_only);

    vec![
        ("empty_module", header),
        ("spec_only", spec_only),
        // Imports ledger.update_current_contract_wasm (`l`.`6`): upgradeable.
        ("upgradeable", module(&[("l", "6")], &[], &[])),
    ]
}

#[test]
fn fuzz_seeds_scan_and_are_written_on_request() {
    let seeds = seeds();
    for (seed, bytes) in &seeds {
        assert!(
            scan(bytes, &KnownBadHashes::default()).is_ok(),
            "seed {seed} no longer scans"
        );
    }
    if let Some(dir) = std::env::var_os("SCAN_FUZZ_SEEDS_DIR") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (seed, bytes) in seeds {
            std::fs::write(dir.join(format!("{seed}.wasm")), bytes).unwrap();
        }
    }
}
