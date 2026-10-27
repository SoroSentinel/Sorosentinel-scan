<!-- TODO: add a banner/logo image here once one exists. -->

# SoroSentinel Scan

[![CI](https://github.com/SoroSentinel/Sorosentinel-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/SoroSentinel/Sorosentinel-scan/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/SoroSentinel/Sorosentinel-scan/badge)](https://scorecard.dev/viewer/?uri=github.com/SoroSentinel/Sorosentinel-scan)
![Rust](https://img.shields.io/badge/Rust-1.98-DEA584?logo=rust)
![Stellar](https://img.shields.io/badge/Stellar-Soroban-black)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Scan is a Rust library and CLI that inspects deployed Soroban contract bytecode without running it. It validates the WASM under strict size and count limits, reports capability indicators (the contract can replace its own code, deploy other contracts, call other contracts, or ships no interface spec) and matches against a known-bad hash list. Intel runs it as a one-shot job in a locked-down container. Output is indicators plus what was not checked, never a verdict.

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

Phase 0. In place: the parser with resource caps, five indicators, deterministic `ScanReport` JSON, the CLI, a sandbox image (no network, read-only, no capabilities, syscall allowlist, resource limits, timeout) and fuzz targets for every parser path. Not yet built: SDK-version and SEP-41 checks.

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
| `make verify` | rustfmt check, clippy `-D warnings`, tests |
| `make test` | `cargo test` |
| `make sandbox` | Build the sandbox image |
| `make fuzz` | Run each fuzz target for `FUZZ_SECONDS` (default 60) |

## Repository layout

| Path | What |
|---|---|
| `crates/scan-core/` | Parser, limits, indicators, `ScanReport` |
| `crates/scan-cli/` | `sorosentinel-scan` binary |
| `sandbox/` | Container image, `run.sh` and the seccomp profile (see `sandbox/README.md`) |
| `fuzz/` | cargo-fuzz targets and seeds |

## Contributing

Pick an open issue (Wave issues carry the `Stellar Wave` label), comment to be assigned, then follow [CONTRIBUTING.md](CONTRIBUTING.md). Every PR must pass `make verify`. AI coding agents must follow [AGENTS.md](AGENTS.md).

## Security

Do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md). This code is **not audited**.

## Contributors

[![Contributors](https://contrib.rocks/image?repo=SoroSentinel/Sorosentinel-scan)](https://github.com/SoroSentinel/Sorosentinel-scan/graphs/contributors)

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
