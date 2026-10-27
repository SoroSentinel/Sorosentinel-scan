# sorosentinel-scan

Static analysis of deployed Soroban WASM for SoroSentinel (Rust): a library
plus CLI that Intel runs as a one-shot sandboxed job. Not a server. Output is
indicators and a `not_checked[]` list, never a verdict. The module is parsed,
never executed.

## Usage

```
sorosentinel-scan <file.wasm | -> [--known-bad-hashes <file>]
```

Prints a `ScanReport` (sorosentinel-intel `schemas/jsonschema/ScanReport.json`)
on stdout. On failure prints `{"error": "<code>"}` on stderr and exits 1;
usage errors exit 2. Intel treats any failure as unanalyzable.

| Indicator | Basis | Informational |
|---|---|---|
| `S-UPGRADEABLE` | imports `update_current_contract_wasm` (`l`.`6`) | yes |
| `S-CREATES-CONTRACTS` | imports `create_contract` (`l`.`3`) or `create_contract_with_constructor` (`l`.`e`) | yes |
| `S-CROSS-CALL` | imports `call` (`d`.`_`) or `try_call` (`d`.`0`) | yes |
| `S-NO-SPEC` | no `contractspecv0` custom section | yes |
| `S-KNOWN-BAD-HASH` | SHA-256 is in the Intel-supplied list | no |

Host-import codes are verified against `soroban-env-common/env.json` at
rs-soroban-env v30.0.0; section names against soroban-sdk v29.0.1.

## Commands

```
make deps     # cargo fetch --locked
make lint     # rustfmt check + clippy -D warnings
make test     # cargo test
make verify   # lint + test + test-contract
make sandbox  # build the sandbox image (Docker)
make fuzz     # each fuzz target for FUZZ_SECONDS (default 60) on a pinned nightly
```

## Fuzzing

One cargo-fuzz target per parser path, in `fuzz/` (its own workspace and lockfile):
`scan` (full CLI path, checks determinism and report shape), `parse` (validation and
every cap), `known_bad_hashes` (hash-list parser). Setup:

```
rustup toolchain install nightly-2026-10-01 --profile minimal
cargo install cargo-fuzz --locked --version 0.13.2
```

Seeds live in `fuzz/seeds/`; the generated corpus and crash artifacts are gitignored.
A scheduled CI job (`.github/workflows/fuzz.yml`) runs every target for 5 minutes
nightly and uploads any crash inputs.

Run one scan in the sandbox: `sandbox/run.sh <file.wasm> [hashes.txt]`
(no network, read-only FS, no capabilities, memory/CPU/PID limits, timeout).
