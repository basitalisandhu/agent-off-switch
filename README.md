# agent-off-switch: find every AI agent identity in Microsoft 365, AWS and GitHub, see what it can reach, and switch it off

![aos review on the demo tenant, then aos off for the riskiest agent identity](docs/demo.gif)

<sub>Recorded from [docs/demo.tape](docs/demo.tape) with [vhs](https://github.com/charmbracelet/vhs) on the synthetic tenant in `examples/demo-tenant`; the text transcript is in [the demo section](#the-60-second-demo).</sub>

[![CI](https://github.com/basitalisandhu/agent-off-switch/actions/workflows/ci.yml/badge.svg)](https://github.com/basitalisandhu/agent-off-switch/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Copilot agents, MCP connectors and coding agents run as Entra app registrations, managed identities, AWS IAM roles, access keys and GitHub Apps. `aos` reads saved exports of those, puts every agent identity in one table with its owner, credentials, grants and last use, ranks what it can reach, and prints the exact steps to switch one off.

- **`aos inventory`**: every non-human identity, with the ones that look like agents marked; flags ownerless identities, identities unused for N days and credentials older than 90 days. Markdown, CSV or JSON.
- **`aos review`**: findings ranked by blast radius, each with its fix. Markdown, JSON or SARIF for GitHub code scanning.
- **`aos off <identity>`**: an ordered runbook (disable, revoke sessions and grants, delete credentials, remove role assignments, verify in the audit log) with the command and the verification command for each step. It prints; it never runs anything.
- **`aos drift old.json new.json`**: new identities, new grants and lost owners since the last inventory; exits 1 while anything new is unreviewed, for CI.

**Why this exists:** agents run as service accounts that nobody owns, recertifies or can stop fast. The argument, the failure modes and the controls are in [Agent identities are the new service accounts](https://basitalisandhu.github.io/posts/agent-identities-are-the-new-service-accounts/).

Standard-library Python 3.10+, offline, read-only. It needs no credentials of its own: you take the exports with read-only commands listed in [docs/exports.md](docs/exports.md).

## The 60-second demo

The repository ships a synthetic tenant in [examples/demo-tenant](examples/demo-tenant): Entra, AWS and GitHub exports plus an `agents.csv` register, with fake ids and the documentation AWS account `111122223333`. The output below is real output from that folder.

```console
$ pip install "git+https://github.com/basitalisandhu/agent-off-switch"
$ aos review examples/demo-tenant --as-of 2026-10-09
# Agent access review

As of 2026-10-09: 13 non-human identities, 11 look like agents. 15 findings (8 error), ranked by blast radius (0 to 100, see docs/scoring.md).

## 4 agent identities nobody owns

- **coding-agent-runner** `aws-role:coding-agent-runner` (blast radius 100): Action * on Resource *
  - switch off: `aos off examples/demo-tenant aws-role:coding-agent-runner`
- **repo-autopilot** `github-app:repo-autopilot` (blast radius 95): administration: write on every repository (settings, branch protection, deletion)
  - switch off: `aos off examples/demo-tenant github-app:repo-autopilot`
- **mail-triage-agent** `entra:aaaaaaaa-0000-4000-8000-000000000001` (blast radius 90): Mail.ReadWrite as an application permission changes data for every user in the tenant
  - switch off: `aos off examples/demo-tenant entra:aaaaaaaa-0000-4000-8000-000000000001`
- **support-bot** `aws-user:support-bot` (blast radius 55): dynamodb:* on named resources
  - switch off: `aos off examples/demo-tenant aws-user:support-bot`
...
```

The full review goes on to rank all 15 findings, each with its fix. Then switch the worst one off:

```console
$ aos off examples/demo-tenant aws-role:coding-agent-runner --as-of 2026-10-09
# Off-switch runbook: coding-agent-runner

Identity `aws-role:coding-agent-runner` (aws-iam-role on aws). Owners: none recorded. Blast radius 100. Exports as of 2026-10-09.

### Step 1: Stop new sessions: replace the trust policy (now trusts Federated: arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com) with a deny-all one; save the current one first
    aws iam get-role --role-name coding-agent-runner --query Role.AssumeRolePolicyDocument > trust-before.json && aws iam update-assume-role-policy --role-name coding-agent-runner --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":["sts:AssumeRole","sts:AssumeRoleWithWebIdentity","sts:AssumeRoleWithSAML","sts:TagSession","sts:SetSourceIdentity"]}]}'

### Step 2: Revoke every session issued before the disable time (the console's Revoke active sessions)
    aws iam put-role-policy --role-name coding-agent-runner --policy-name AWSRevokeOlderSessions --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<disable time, ISO 8601 UTC>"}}}]}'

### Step 4: Delete the inline policy agent-all (save it first with get-role-policy)
    aws iam delete-role-policy --role-name coding-agent-runner --policy-name agent-all

### Step 5: Confirm in CloudTrail that nothing succeeded after the disable time
    aws cloudtrail lookup-events --start-time <disable time> --lookup-attributes AttributeKey=ResourceName,AttributeValue=arn:aws:iam::111122223333:role/coding-agent-runner --output json > after.json   (then look for AssumeRole on coding-agent-runner and any event with a session of this role; expect only AccessDenied)

Every credential and grant in the exports is named by a step.
```

(Condensed: step 3, a note that a role has no long-lived credential, is left out, and the real runbook prints each change and its verification command in its own block, with a checkbox for the time and the person.) And in CI, compare with last month's inventory:

```console
$ aos drift examples/drift/baseline.json examples/demo-tenant --as-of 2026-10-09 --accept examples/drift/accepted.txt
# Agent identity drift

From 2026-09-01 (11 identities) to 2026-10-09 (13 identities): 4 changes, 3 not reviewed.

| Change | Identity | Detail | Reviewed |
|---|---|---|---|
| new-identity | `github-app:repo-autopilot` | repo-autopilot (github-app, no owner, blast radius 95) | **no** |
| new-identity | `github-app:docs-preview-bot` | docs-preview-bot (github-app, web-team@example.com, blast radius 55) | yes |
| new-grant | `aws-role:coding-agent-runner` | agent-all (score 100) | **no** |
| owner-lost | `entra:aaaaaaaa-0000-4000-8000-000000000001` | was owned by messaging-team@example.com; now no owner | **no** |

To accept a change after review, add its key to the accept file (one per line):

```
aws-role:coding-agent-runner|inline-policy:agent-all
entra:aaaaaaaa-0000-4000-8000-000000000001|owner-lost
github-app:repo-autopilot
```
$ echo $?
1
```

## Install

From git (no dependencies at run time):

```bash
pip install "git+https://github.com/basitalisandhu/agent-off-switch@v0.1.0"
aos --help
```

Container image, built by [the release workflow](.github/workflows/publish-github-packages.yml) for each version tag, with an SPDX SBOM, build provenance and a keyless signature:

```bash
docker run --rm -v "$PWD/exports:/work/exports:ro" ghcr.io/basitalisandhu/agent-off-switch:0.1.0 review exports
```

GitHub Action ([action.yml](action.yml)): runs `aos review`, uploads the SARIF to code scanning, and runs `aos drift` when you give it a baseline.

```yaml
permissions:
  contents: read
  security-events: write   # only for the SARIF upload

jobs:
  agent-identities:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7   # pin to a commit SHA
        with:
          persist-credentials: false
      - uses: basitalisandhu/agent-off-switch@v0.1.0   # pin to a commit SHA
        with:
          exports: exports/            # the folder your export job writes
          baseline: inventory/last.json
          accept: inventory/accepted.txt
          fail-on: error
```

Inputs: `exports` (required), `baseline`, `accept`, `fail-on` (`none`, `note`, `warning`, `error`; default `error`), `as-of`, `sarif-file` (default `aos.sarif`), `upload-sarif` (default `true`), `python-version` (default `3.12`). Outputs: `review-exit-code`, `drift-exit-code`, `sarif-file`. Keep the exports and the SARIF in a private repository.

## Usage

```text
aos inventory EXPORTS [--format md|csv|json] [--agents-only] [--fail-on-flags]
aos review    EXPORTS [--format md|json|sarif] [--fail-on none|note|warning|error]
aos off       EXPORTS IDENTITY [--format md|json]
aos drift     OLD NEW [--accept FILE] [--format md|json]

common: --as-of YYYY-MM-DD  --unused-days N (90)  --max-credential-age N (90)
        --include-aws-managed-roles  --out FILE
```

`EXPORTS` is a folder of exports, or for `review`, `off` and `drift` also an inventory saved with `aos inventory --format json`. `IDENTITY` is an aos id (`entra:<appId>`, `aws-role:<name>`, `aws-user:<name>`, `github-app:<slug>`, `github-deploy-key:<repo>#<id>`, `register:<id>`), a display name, an app or object id, or an ARN.

Exit codes: 0 nothing to act on, 1 something needs a person (findings at or above `--fail-on`, unreviewed drift, a runbook that does not cover every grant, or flagged identities with `--fail-on-flags`), 2 bad input.

## How it works

- **One identity model.** Every identity carries an owner list, type, platform, credentials (type, age, expiry, last use, key id shown by its last four characters), grants and last activity. See [src/agent_off_switch/model.py](src/agent_off_switch/model.py).
- **Blast radius.** Each grant scores 0 to 100: tenant-wide Graph application permissions, `*` IAM actions or resources and admin roles score highest. The identity's blast radius is its highest grant. The rules are in [docs/scoring.md](docs/scoring.md).
- **Agents.** An identity is marked as an agent when it is an Entra agent identity, a register row points at it, a tag says so, or its name contains agent, bot, copilot, assistant, mcp, autopilot or llm. Every identity is listed either way.
- **Findings.** Twelve rules (AOS001 to AOS012), from admin roles and tenant-wide permissions to stale and expired credentials, each with a fix.

## What it does not do

- It does not call any cloud API, change any setting or run any command. `off` prints commands for a person to run.
- It does not watch in real time; it sees what the exports saw.
- It does not read Azure role assignments, AWS permission boundaries, service control policies or resource policies, Exchange RBAC for Applications scopes or Conditional Access; a score can overstate reach that one of those limits (see [docs/scoring.md](docs/scoring.md)).
- It does not judge GitHub App activity (the installations export has no last-use date) or see inside agents (prompts, tool calls, memory).
- It does not replace Microsoft Entra Agent ID, an identity governance product or a CNAPP; it gives you one offline list across platforms and a way to act on it.

## Threat model

[docs/threat-model.md](docs/threat-model.md) maps what `aos` covers to the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) (mainly ASI03 Identity & Privilege Abuse, with ASI02, ASI04, ASI05, ASI08 and ASI10) and to Microsoft's [Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id) guidance, and lists what the tool itself must not do.

## FAQ

**Does it need admin rights?** No. The exports need read access only (Global Reader in Entra, `SecurityAudit` in AWS, organisation read in GitHub); `aos` itself needs none.

**Can it switch an agent off for me?** No, by design. The runbook gives the commands in order with a verification for each, so a person can run them and keep the evidence.

**Why does every service principal show up, not only agents?** Many agents run as ordinary app registrations or roles with nothing that marks them. The inventory lists all non-human identities and marks the likely agents; `--agents-only` narrows the table. A row in `agents.csv` makes the link explicit.

**Where do owners come from?** Entra owners and sponsors, an `owner` tag (AWS tag or Entra tag `owner:team@example.com`), or the `owner` column of `agents.csv`.

**Are secrets read or printed?** No. Graph and IAM exports do not contain secret values, and key ids are shown by their last four characters.

**How do I gate pull requests on new agent identities?** Commit an inventory (`aos inventory exports --format json --out inventory/last.json`), run `aos drift inventory/last.json exports` in CI, and add reviewed keys to an accept file.

**Does it work on Windows?** Yes; CI runs the tests on Ubuntu, macOS and Windows with Python 3.10 to 3.13.

## Related repositories

- [agent-identity-governance-skills](https://github.com/basitalisandhu/agent-identity-governance-skills): the agent skills whose export parsing this tool grew from
- [skill-scan-gate](https://github.com/basitalisandhu/skill-scan-gate)
- [m365-governance-skills](https://github.com/basitalisandhu/m365-governance-skills)
- [aws-security-skills](https://github.com/basitalisandhu/aws-security-skills)
- [ai-agent-incidents](https://github.com/basitalisandhu/ai-agent-incidents)
- The hub: <https://basitalisandhu.github.io/>

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md), [docs/good-first-issues.md](docs/good-first-issues.md), [SECURITY.md](SECURITY.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Licensed under [MIT](LICENSE). Changes are listed in [CHANGELOG.md](CHANGELOG.md).
