# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/).

## [Unreleased]

## [0.1.3] - 2026-10-29

### Fixed

- Deeply nested JSON in an export file exits 2 naming the file on every supported Python. Python 3.14 no longer raises `RecursionError` from `json.loads` at the old depth (balanced input parsed, unclosed input was reported as invalid JSON instead), so JSON is now checked for nesting first (limit 200 levels).
- CI tests Python 3.14.

## [0.1.2] - 2026-10-28

### Fixed

- `aos off` no longer suggests an unrelated identity for an unknown name; only close names are offered (#12).
- An export record of the wrong shape (for example a string where Graph returns a list) now ends with a clear error and exit code 2 instead of a Python traceback.
- Out-of-range dates and timestamps in exports are read as "no date" instead of crashing.
- Carriage returns in names no longer break Markdown table rows.
- An export that is not UTF-8 (for example UTF-16 from Windows PowerShell 5.1) or JSON nested too deeply now ends with exit code 2 and a message naming the file, instead of a traceback.
- Dates before the year 1000 were written without a four-digit year on Linux and could not be read back.

### Added

- Property tests with Hypothesis for the date, record, masking and table helpers, and for every command on malformed copies of the demo tenant.
- A seeded fuzz test that replaces each export file with empty, truncated, non-UTF-8, deeply nested or random bytes and runs each command in a subprocess with a timeout.
- A scaling test: the demo tenant copied 10 and 100 times; runtime must grow roughly linearly.
- A CI job that clones the repository, installs it in a new venv and runs the README quick start.
- A Troubleshooting section in the README with real error messages and fixes.

## [0.1.1] - 2026-10-18

### Added

- A demo GIF in the README, recorded from `docs/demo.tape` with vhs on the synthetic demo tenant.
- `ROADMAP.md`, a Contributors section and links to the Discussions boards (#14, #17).

### Changed

- The README demo starts from a fresh clone (#11) and links the write-up (#10).
- Harden the workflows and repository policy for the OpenSSF Scorecard (#18).

## [0.1.0] - 2026-10-09

### Added

- `aos inventory`: one table (Markdown, CSV, JSON) of every non-human identity in saved Microsoft Entra, AWS IAM, GitHub and register exports, with owner, type, credentials, grants, last use and blast radius; flags for no owner, unused, never used, stale and expired credentials.
- `aos review`: findings AOS001 to AOS012 ranked by blast radius, each with its fix, as Markdown, JSON or SARIF 2.1.0.
- `aos off`: an ordered off-switch runbook per identity (disable, revoke sessions and grants, delete credentials, remove role assignments, verify in the audit log) with a verification command for each step and a coverage check. It prints commands and runs none.
- `aos drift`: compares two inventories and exits 1 on unreviewed new identities, new grants or lost ownership; an accept file records reviewed changes.
- Composite GitHub Action (`action.yml`) running review and drift with SARIF upload.
- Synthetic demo tenant (`examples/demo-tenant/`) and drift example (`examples/drift/`).
- Documentation: exports and the commands that produce them, scoring, threat model mapped to the OWASP Top 10 for Agentic Applications, good first issues.
- Container image and release workflow with SBOM, build provenance and signature.

The export readers, scoring lists and runbook steps are adapted from the scripts in [agent-identity-governance-skills](https://github.com/basitalisandhu/agent-identity-governance-skills).

[Unreleased]: https://github.com/basitalisandhu/agent-off-switch/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/basitalisandhu/agent-off-switch/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/basitalisandhu/agent-off-switch/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/basitalisandhu/agent-off-switch/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/basitalisandhu/agent-off-switch/releases/tag/v0.1.0
