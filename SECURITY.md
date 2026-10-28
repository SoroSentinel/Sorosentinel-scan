# Security Policy

## Status

SoroSentinel Scan is pre-release and **has not been audited**. Do not rely on it to protect funds. There are no tagged releases yet, so only the latest commit on `main` receives security fixes.

## Reporting a vulnerability

Please do not open a public issue, PR or discussion for a vulnerability.

Report it privately through GitHub's private vulnerability reporting:

**https://github.com/SoroSentinel/Sorosentinel-scan/security/advisories/new**

(or the repository's **Security** tab → **Report a vulnerability**). If you cannot use GitHub, email TODO-security-contact.

Include:

- A description of the issue and its impact
- Steps or an input that reproduces it (a minimal WASM module, hash list or command line)
- The commit or version you tested

Keep the report and any proof of concept between you and the maintainers until the advisory is published.

## Disclosure process and timeline

1. **Acknowledgement** within 5 business days of the report.
2. **Triage** within 10 business days: we confirm or decline the issue, agree on its severity with you, and tell you the planned fix date.
3. **Fix** in a private fork attached to the GitHub security advisory. We keep you updated at least every 14 days until it ships.
4. **Disclosure**: we publish the advisory (with a CVE when one applies) once the fix is on `main`, and credit you unless you ask us not to. The default deadline is 90 days from the report; we may agree on a different date with you, for example when a fix needs coordination with other Stellar projects.

If a vulnerability is already public or being exploited, we will move as fast as we can and may publish before the fix ships, with mitigations.

## Scope

In scope (this repository):

- Anything that makes Scan report a clean result for a module it did not fully analyze, or drop entries from `not_checked`
- Crashes, hangs or resource exhaustion from hostile input (WASM modules, custom sections, known-bad hash lists, command-line arguments)
- Non-deterministic `ScanReport` output for the same input and `ruleset_version`
- The WASM parser and its resource caps
- The sandbox (`sandbox/`): escapes, network access, writes outside the container, syscalls the seccomp profile should block, or any path that could execute contract code
- The CI workflows and build (`.github/`, `Makefile`, `Cargo.lock`) where they could let someone change what is built or published

Out of scope:

- The Intel and Guard components: report those in [Sorosentinel-intel](https://github.com/SoroSentinel/Sorosentinel-intel/security/advisories/new) and [Sorosentinel-guard](https://github.com/SoroSentinel/Sorosentinel-guard/security/advisories/new)
- Findings in third-party dependencies with no demonstrated impact on this project (report those upstream)
- Vulnerabilities in Soroban contracts that Scan analyzes (report those to the contract's owner)
- Social engineering, physical attacks, and denial of service by volume against hosted infrastructure
- Disagreements with an indicator for a specific contract: use the review process instead

## Safe harbor

Good-faith research that follows this policy, avoids privacy violations and service disruption, and does not touch other users' funds will not be pursued.
