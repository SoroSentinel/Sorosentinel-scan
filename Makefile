# Standard targets shared by all SoroSentinel repos (docs/project_structure.md §2.2).
# Phase 0 stub: the Rust workspace, sandbox and fuzz targets arrive in scaffold step 9.

.PHONY: deps fmt lint test test-contract gen fuzz verify

deps fmt lint test test-contract gen fuzz:
	@echo "$@: nothing to run yet (Rust workspace not scaffolded)"

verify: lint test test-contract
