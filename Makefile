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

# One cargo-fuzz target per parser path, each run for FUZZ_SECONDS on a pinned
# nightly. Needs: rustup toolchain install $(FUZZ_TOOLCHAIN) and
# cargo install cargo-fuzz --locked --version 0.13.2.
FUZZ_TOOLCHAIN ?= nightly-2026-10-01
FUZZ_SECONDS ?= 60
FUZZ_TARGETS := scan parse known_bad_hashes
fuzz:
	@for t in $(FUZZ_TARGETS); do \
	  seeds=fuzz/seeds/scan; [ $$t = known_bad_hashes ] && seeds=fuzz/seeds/known_bad_hashes; \
	  mkdir -p fuzz/corpus/$$t; \
	  echo "fuzz: $$t for $(FUZZ_SECONDS)s"; \
	  $(CARGO) +$(FUZZ_TOOLCHAIN) fuzz run $$t fuzz/corpus/$$t $$seeds -- \
	    -max_total_time=$(FUZZ_SECONDS) -max_len=65536 || exit 1; \
	done

sandbox:
	docker build -f sandbox/Dockerfile -t sorosentinel-scan .

verify: lint test test-contract
