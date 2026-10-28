# Standard targets shared by all SoroSentinel repos (docs/project_structure.md §2.2).
# Thin wrapper over cargo; the toolchain is pinned in rust-toolchain.toml.

CARGO ?= cargo

.PHONY: deps fmt lint test test-contract schemas-check pin-schemas gen fuzz fuzz-seeds sandbox verify

deps:
	$(CARGO) fetch --locked

fmt:
	$(CARGO) fmt --all

lint:
	$(CARGO) fmt --all --check
	$(CARGO) clippy --locked --all-targets -- -D warnings

test:
	$(CARGO) test --locked

# ScanReport output validated against Intel's pinned ScanReport schema.
test-contract: schemas-check
	$(CARGO) test --locked -p scan-core --test schema_contract

# Pinned Intel files match their recorded checksums (offline; no hand edits).
schemas-check:
	cd intel-schemas && shasum -a 256 -c SHA256SUMS
	@grep -q "^tag $(INTEL_SCHEMAS_TAG)$$" intel-schemas/PINNED || { echo "intel-schemas is not pinned at $(INTEL_SCHEMAS_TAG); run make pin-schemas"; exit 1; }

# Re-pin Intel's schemas at a tag (needs network).
INTEL_SCHEMAS_TAG ?= v0.1.0-next.0
pin-schemas:
	scripts/pin-intel-schemas.sh $(INTEL_SCHEMAS_TAG)

gen:
	@echo "gen: nothing to generate"

# One cargo-fuzz target per parser path, each run for FUZZ_SECONDS on a pinned
# nightly. Needs: rustup toolchain install $(FUZZ_TOOLCHAIN) and
# cargo install cargo-fuzz --locked --version 0.13.2.
FUZZ_TOOLCHAIN ?= nightly-2026-10-01
FUZZ_SECONDS ?= 60
FUZZ_TARGETS := scan parse known_bad_hashes
fuzz: fuzz-seeds
	@for t in $(FUZZ_TARGETS); do \
	  seeds=$(FUZZ_WASM_SEEDS); [ $$t = known_bad_hashes ] && seeds=fuzz/seeds/known_bad_hashes; \
	  mkdir -p fuzz/corpus/$$t; \
	  echo "fuzz: $$t for $(FUZZ_SECONDS)s"; \
	  $(CARGO) +$(FUZZ_TOOLCHAIN) fuzz run $$t fuzz/corpus/$$t $$seeds -- \
	    -max_total_time=$(FUZZ_SECONDS) -max_len=65536 || exit 1; \
	done

# WASM seeds are generated (crates/scan-core/tests/fuzz_seeds.rs) into the
# gitignored corpus dir rather than committed as binaries.
FUZZ_WASM_SEEDS := fuzz/corpus/seeds/scan
fuzz-seeds:
	SCAN_FUZZ_SEEDS_DIR=$(CURDIR)/$(FUZZ_WASM_SEEDS) $(CARGO) test --locked -p scan-core --test fuzz_seeds

sandbox:
	docker build -f sandbox/Dockerfile -t sorosentinel-scan .

verify: lint test test-contract
