# Changelog

All notable changes to this repository. Versions follow [Semantic Versioning](https://semver.org/); `RULESET_VERSION` changes whenever an indicator's behavior changes.

## [Unreleased]

- Code of conduct and changelog.
- README and CONTRIBUTING: removed dead community links.

## [0.1.0] - 2026-11-01

First release.

- WASM parser with size, section and name caps; `#![forbid(unsafe_code)]`.
- Seven indicators: `S-KNOWN-BAD-HASH`, `S-UPGRADEABLE`, `S-CREATES-CONTRACTS`, `S-CROSS-CALL`, `S-NO-SPEC`, `S-OLD-SDK`, `S-SEP41-DEVIATION`. Only `S-KNOWN-BAD-HASH` can raise a level.
- Deterministic `ScanReport` JSON validated against Intel's pinned schema, with `not_checked` always listed.
- `scan-cli` with JSON and SARIF 2.1.0 output.
- Sandbox image: no network, read-only, no capabilities, seccomp allowlist, resource limits, timeout.
- Fuzz targets for every parser path (`scan`, `parse`, `env_meta`, `spec`, `known_bad_hashes`).

[Unreleased]: https://github.com/SoroSentinel/Sorosentinel-scan/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SoroSentinel/Sorosentinel-scan/releases/tag/v0.1.0
