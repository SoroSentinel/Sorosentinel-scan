# One-shot sandbox image for sorosentinel-scan (docs/project_structure.md §4).
# Static musl binary on an empty base: no shell, no package manager, no network tools.
# Build from the repo root: docker build -f sandbox/Dockerfile -t sorosentinel-scan .

# rust:1.98.1-alpine, pinned by digest (Docker Hub, last updated 2026-09-18).
FROM rust:1.98.1-alpine@sha256:7cc1c22d77d9432f7fe012a70e6d3e555af54c2a6832700ed7d553f1769ae89f AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN cargo build --locked --release -p scan-cli

FROM scratch
COPY --from=build /src/target/release/sorosentinel-scan /sorosentinel-scan
USER 65534:65534
ENTRYPOINT ["/sorosentinel-scan"]
