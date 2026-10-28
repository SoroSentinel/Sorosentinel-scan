# One-shot sandbox image for sorosentinel-scan (docs/project_structure.md §4).
# Static musl binary on an empty base: no shell, no package manager, no network tools.
# Build from the repo root: docker build -f sandbox/Dockerfile -t sorosentinel-scan .

# rust:1.98.1-alpine, pinned by digest (Docker Hub, last updated 2026-09-18).
FROM rust:1.99.0-alpine@sha256:0cce0a5e0e8ba67b455257a3a02a1d99005f382748789d6464460028810f1627 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN cargo build --locked --release -p scan-cli

FROM scratch
COPY --from=build /src/target/release/sorosentinel-scan /sorosentinel-scan
USER 65534:65534
ENTRYPOINT ["/sorosentinel-scan"]
