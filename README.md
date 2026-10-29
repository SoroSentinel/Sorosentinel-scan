<!-- TODO: add a banner/logo image here once one exists. -->

# SoroSentinel Scan

[![CI](https://github.com/SoroSentinel/Sorosentinel-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/SoroSentinel/Sorosentinel-scan/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/SoroSentinel/Sorosentinel-scan/badge)](https://scorecard.dev/viewer/?uri=github.com/SoroSentinel/Sorosentinel-scan)
![Rust](https://img.shields.io/badge/Rust-1.98-DEA584?logo=rust)
![Stellar](https://img.shields.io/badge/Stellar-Soroban-black)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Scan is a Rust library and CLI that inspects deployed Soroban contract bytecode without running it. It validates the WASM under strict size and count limits, reports capability indicators (the contract can replace its own code, deploy other contracts, call other contracts, ships no interface spec, or claims an interface version older than anything currently deployed) and matches against a known-bad hash list. Intel runs it as a one-shot job in a locked-down container. Output is indicators plus what was not checked, never a verdict.

Part of **SoroSentinel**, security tooling for the Stellar ecosystem. It advises; it never controls the network and never touches private keys.

## Maintainers | [Telegram](TODO-telegram-group-link)

| Maintainer | GitHub | Contact |
|---|---|---|
| TODO name | [@TODO](https://github.com/TODO) | [Telegram](https://t.me/TODO) |

## Community

Questions and coordination: [Telegram group](TODO-telegram-group-link).

## How the pieces fit

| Repo | Language | Role |
|---|---|---|
| [Sorosentinel-intel](https://github.com/SoroSentinel/Sorosentinel-intel) | Go | Evidence, detectors, signals, API, signed snapshot, shared schemas |
| [Sorosentinel-guard](https://github.com/SoroSentinel/Sorosentinel-guard) | TypeScript | Pre-signing transaction analysis SDK for wallets |
| [Sorosentinel-scan](https://github.com/SoroSentinel/Sorosentinel-scan) | Rust | Static triage of deployed Soroban WASM |

Data flows Scan → Intel → signed snapshot/API → Guard. The repos only talk through versioned schemas owned by Intel.

## Status

Minimal library complete. In place: the parser with resource caps, seven indicators, deterministic `ScanReport` JSON validated against Intel's pinned schema, the CLI with SARIF 2.1.0 output (see [Output formats](#output-formats)), a sandbox image (no network, read-only, no capabilities, syscall allowlist, resource limits, timeout) and fuzz targets for every parser path. Two of the seven read a module's own claims rather than measuring it. `S-OLD-SDK` reports the protocol version a module writes in its `contractenvmetav0` section. `S-SEP41-DEVIATION` fires once a module declares three or more of the ten SEP-41 function names — enough to read as a token claim — and the signatures it declares then differ from the interface. The absence of that indicator is not conformance: a module that declares nothing token-like is never compared, and behaviour, events and the meaning of the declared types are examined by neither, so `NC-SEP41-CONFORMANCE` stays in `not_checked` even when it fires. Not built: what AGENTS.md §4 puts outside v1, including the Phase 2 items ADR 0007 has approved as scope (the CI action, fuzzy similarity) — approval of scope is not approval of design, and that work still starts at the Phase 1 exit.

## Quick start

Prerequisites: Rust via rustup (the toolchain in `rust-toolchain.toml` installs automatically). Docker for the sandbox.

```bash
git clone https://github.com/SoroSentinel/Sorosentinel-scan.git
cd Sorosentinel-scan
make deps
make verify
cargo run -p scan-cli -- path/to/contract.wasm
```

| Command | What it does |
|---|---|
| `make verify` | rustfmt check, clippy `-D warnings`, tests, contract test |
| `make test` | `cargo test` |
| `make test-contract` | Check pinned schema checksums, validate `ScanReport` output against Intel's pinned schema |
| `make pin-schemas` | Re-pin Intel's schemas at `INTEL_SCHEMAS_TAG` (needs network) |
| `make sandbox` | Build the sandbox image |
| `make fuzz` | Run each fuzz target for `FUZZ_SECONDS` (default 60) |

### Output formats

```bash
cargo run -p scan-cli -- path/to/contract.wasm                 # ScanReport JSON
cargo run -p scan-cli -- path/to/contract.wasm --format sarif  # the same report as SARIF 2.1.0
```

JSON is the default, the complete record, and what Intel consumes. `--format
sarif` renders the same `ScanReport` for code-scanning tools: one run, one
artifact named `<wasm_sha256>.wasm`, one result per indicator and per
`not_checked` code. Informational indicators are SARIF `kind: informational`;
everything else, including the `not_checked` codes, is `kind: review`, and every
result is `level: none` because no Scan output is a determination (§3.3). A rule
carries only its `id`: approved rule text needs an Intel template and a pin,
which this repo does not have yet, so `message.text` is the code plus its
`key=value` facts and nothing else (§5). Failures still exit 1 with
`{"error": "<code>"}` on stderr and no stdout.

`--known-bad-hashes <file>` works with either format.

### Fuzz seeds

`make fuzz` builds synthetic WASM seeds from the same byte builders as the unit
tests (`crates/scan-core/tests/fuzz_seeds.rs`) into the gitignored corpus. Real
deployed modules reach parser paths synthetic seeds do not: drop `.wasm` files in
`fuzz/seeds/scan/` and `make fuzz` passes that directory to every WASM target
(`scan`, `parse`, `env_meta`, `spec`). It is gitignored, so downloaded modules are never
committed; check the license of anything you put there.

Fetching real modules is Intel's job, not this repo's: `sorosentinel-intel`
depends on an HTTP client and the Stellar XDR definitions, and `scan-core`
deliberately depends on neither (`wasmparser`, `sha2`, `serde`). From an Intel
checkout:

```sh
go run ./cmd/intel-fuzz-seeds -out ../Sorosentinel-scan/fuzz/seeds/scan -span 5000
```

Measured on testnet on 2026-10-28: 3000 ledgers yielded 73 distinct modules
(1.1 MB), so use a wide `-span`. Deployed contract bytecode is public ledger
data used here only as parser input; it carries no license grant for anything
else, which is why the directory stays gitignored and nothing is committed.

## Repository layout

| Path | What |
|---|---|
| `crates/scan-core/` | Parser, limits, indicators, `ScanReport` |
| `crates/scan-cli/` | `sorosentinel-scan` binary |
| `sandbox/` | Container image, `run.sh` and the seccomp profile (see `sandbox/README.md`) |
| `intel-schemas/` | Intel's `ScanReport` schema pinned at a tag (generated by `scripts/pin-intel-schemas.sh`; do not edit) |
| `fuzz/` | cargo-fuzz targets and seeds |

## Contributing

Pick an open issue (Wave issues carry the `Stellar Wave` label), comment to be assigned, then follow [CONTRIBUTING.md](CONTRIBUTING.md). Every PR must pass `make verify`. AI coding agents must follow [AGENTS.md](AGENTS.md).

## Security

Do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md). This code is **not audited**.

## Contributors

[![Contributors](https://contrib.rocks/image?repo=SoroSentinel/Sorosentinel-scan)](https://github.com/SoroSentinel/Sorosentinel-scan/graphs/contributors)

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
