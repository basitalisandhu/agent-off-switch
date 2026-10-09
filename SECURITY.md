# Security policy

agent-off-switch reads saved exports of Microsoft Entra, AWS IAM and GitHub configuration and prints an inventory, a review or a runbook. It makes no network call, starts no process, stores no credential and reports no usage. The `off` subcommand prints commands for a person to run; it never runs them.

## Supported versions

Only the latest release is supported. Pin a tag (or the image digest) if you need stability, and update when a fix is announced in [CHANGELOG.md](CHANGELOG.md).

## Reporting a vulnerability

Please do not open a public issue for a security problem.

1. Use GitHub's private vulnerability reporting on this repository ("Security" tab, "Report a vulnerability").
2. If that is unavailable, open an issue titled "Security contact request" with no details, and the maintainer will reply with a private channel.

Include what you found, how to reproduce it, and what you think the impact is. You will get an acknowledgement within 5 working days and a fix or a mitigation plan within 30 days for confirmed issues.

## What counts

- The package opening a network connection, starting a process, or writing anywhere other than standard output or the `--out` path.
- Output that prints a secret value, or a key id beyond its last four characters.
- Content of an export (a display name, a tag, a register field) that changes a score, hides a finding, or ends up inside a printed command in a way that would run something other than the intended command.
- A runbook step whose verification command would report success while the access is still in place.
- A committed file holding real names, real tenant, account or organisation ids, or a secret-shaped string.

Rule mistakes (a permission that should score higher, an export field read wrongly) are welcome as ordinary issues or pull requests with a test that shows them.

## Handling the outputs

Inventories, reviews and SARIF files name identities, owners and permissions. Keep them where you keep the exports: private repositories, private artefacts, access-controlled folders.
