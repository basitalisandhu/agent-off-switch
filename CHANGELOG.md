# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/).

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

[0.1.0]: https://github.com/basitalisandhu/agent-off-switch/releases/tag/v0.1.0
