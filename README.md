# sorosentinel-scan

Static analysis of deployed Soroban WASM for SoroSentinel (Rust): a library
plus CLI that Intel runs as a one-shot sandboxed job. Not a server. Output is
indicators and a `not_checked[]` list, never a verdict.

Status: Phase 0 stub. `make verify` is a no-op until the Rust workspace lands
(docs/project_structure.md §4 and §8 step 9).
