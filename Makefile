# Standard targets shared by all SoroSentinel repos (docs/project_structure.md §2.2).
# Thin wrapper over cargo; the toolchain is pinned in rust-toolchain.toml.

CARGO ?= cargo

.PHONY: deps fmt lint test test-contract gen fuzz sandbox verify

deps:
	$(CARGO) fetch --locked

fmt:
	$(CARGO) fmt --all

lint:
	$(CARGO) fmt --all --check
	$(CARGO) clippy --locked --all-targets -- -D warnings

test:
	$(CARGO) test --locked

# TODO: validate ScanReport output against a pinned sorosentinel-intel schemas tag.
test-contract:
	@echo "test-contract: no pinned sorosentinel-intel schemas tag yet"

gen:
	@echo "gen: nothing to generate"

# TODO: cargo-fuzz targets per parser path (needs cargo-fuzz and a nightly toolchain).
fuzz:
	@echo "fuzz: not set up yet"

sandbox:
	docker build -f sandbox/Dockerfile -t sorosentinel-scan .

verify: lint test test-contract
