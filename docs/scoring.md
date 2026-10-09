# Blast-radius scoring

Every grant an identity holds gets a score from 0 to 100: roughly, how much of the organisation the identity can read or change through that grant, and whether it can give itself more. An identity's **blast radius** is the highest score among its grants. Findings are ranked by score.

The scores are fixed rules, not measurements. They are there to put the worst things at the top of a review, and two people reading the same export get the same order. The rules live in [`src/agent_off_switch/scoring.py`](../src/agent_off_switch/scoring.py); a change to a rule comes with a test.

## Bands

| Score | Meaning | SARIF level |
|---|---|---|
| 90 to 100 | can take over the tenant, account or organisation, or grant itself more access | error |
| 70 to 89 | reads or changes data across the whole tenant, account or every repository | error |
| 40 to 69 | write access to a bounded set, or tenant-wide read of low-sensitivity data | warning |
| 0 to 39 | narrow, named access | note |

## Microsoft Entra and Microsoft Graph

Application permissions work without a signed-in user and, unless scoped by Exchange RBAC for Applications or `Sites.Selected`, reach every mailbox, site or user in the tenant. That is why they score higher than the same permission granted as delegated.

| Grant | Score |
|---|---|
| Directory role: Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator | 100 |
| Directory role: Application Administrator, Cloud Application Administrator, Conditional Access Administrator, Hybrid Identity Administrator, Authentication Policy Administrator (can add credentials to other apps or change sign-in policy) | 95 |
| Any other directory role whose name ends in Administrator | 85 |
| Global Reader | 50 |
| Any other directory role | 40 |
| Application permission that can grant more access: `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, `DelegatedPermissionGrant.ReadWrite.All`, `Directory.ReadWrite.All`, `Domain.ReadWrite.All`, `Policy.ReadWrite.ConditionalAccess`, `RoleManagement.ReadWrite.Directory`, `UserAuthenticationMethod.ReadWrite.All` | 95 |
| Application permission that changes tenant-wide data, for example `Mail.ReadWrite`, `Mail.Send`, `Files.ReadWrite.All`, `Sites.FullControl.All`, `Chat.ReadWrite.All`, `User.ReadWrite.All`, `full_access_as_app` | 90 |
| Application permission that reads tenant-wide data, for example `Mail.Read`, `Files.Read.All`, `Sites.Read.All`, `Chat.Read.All`, `Directory.Read.All` | 75 |
| Any other application permission whose name holds ReadWrite, Manage, FullControl or Send | 60 |
| Any other application permission (for example `Sites.Selected`) | 40 |
| Delegated permission from the lists above, consented for all users | 50 |
| Other delegated permission consented for all users | 20 |
| Delegated permission from the lists above, consented for one user | 25 |
| Other delegated permission for one user | 10 |

The full lists are `GRAPH_ESCALATION`, `GRAPH_DATA_WRITE` and `GRAPH_DATA_READ` in the source.

## AWS IAM

Each managed or inline policy is scored by its worst `Allow` statement. Group membership scores as the worst policy of the group.

| Statement | Score |
|---|---|
| `Action: "*"` on `Resource: "*"` | 100 |
| `NotAction` (allows everything not listed) on `*` / on named resources | 95 / 85 |
| `Action: "*"` on named resources | 90 |
| IAM or STS actions that create or assume access (`iam:*`, `iam:Create*`, `iam:Attach*`, `iam:Put*`, `iam:PassRole`, `iam:Update*`, `iam:Add*`, `sts:AssumeRole*`, `organizations:*`) on `*` | 90 |
| A whole service (`s3:*`) on `*` | 75 |
| A whole service on named resources | 55 |
| Write actions on `*` | 45 |
| Read actions (`Get`, `List`, `Describe` and similar) on `*` | 30 |
| Named actions on named resources | 20 |

AWS managed policies are scored by name, because their documents are not in the export: `AdministratorAccess` 100, `IAMFullAccess` 90, `PowerUserAccess` 85, `ReadOnlyAccess` 50, other `*FullAccess` 75, other `*ReadOnly*` 30, `AWSDenyAll` 0, anything else 35. A customer managed policy whose document is missing scores 35.

A role whose trust policy allows any principal (`"AWS": "*"` or `"Principal": "*"`) gets a separate `open-role-trust` finding scored 90.

## GitHub

| Grant | Score |
|---|---|
| App permission `organization_administration: write` | 100 |
| `administration: write` on every repository / on selected repositories | 95 / 70 |
| `members: write` | 85 |
| Write on `contents`, `workflows`, `secrets`, `organization_secrets`, `actions`, `environments`, `pull_requests` or `packages`: every repository / selected | 80 / 55 |
| Other write: every repository / selected | 60 / 40 |
| Read of `contents` or secrets on every repository | 45 |
| Other read: every repository / selected | 30 / 15 |
| Deploy key with write access / read only | 50 / 20 |

## Register (`agents.csv`)

Declared permissions are free text, so they are scored by words: anything with `*`, admin, owner, full control or full access scores 80; write, send, delete, manage, create, update, push or execute 50; anything else 20.

## Findings and their scores

| Rule | Score |
|---|---|
| AOS001 admin-role (directory role scoring 85 or more) | the grant's score |
| AOS002 tenant-wide-application-permission (75 or more) | the grant's score |
| AOS003 wildcard-iam (AWS policy or group scoring 75 or more) | the grant's score |
| AOS004 broad-github-app (70 or more) | the grant's score |
| AOS005 open-role-trust | 90 |
| AOS006 no-owner | the identity's blast radius, at least 30 |
| AOS007 stale-credential (older than `--max-credential-age`, 90 days by default) | blast radius minus 10, at least 30 |
| AOS008 unused-identity (no use for `--unused-days`, 90 by default, or never used) | blast radius minus 20, at least 20 |
| AOS009 expired-credential | 15 |
| AOS010 broad-delegated-permission (50 or more) | the grant's score |
| AOS011 read-write-deploy-key | the grant's score |
| AOS012 broad-declared-permission (80 or more) | the grant's score |

Several grants that trigger the same rule on one identity become one finding, scored by the highest and listing the rest. Disabled identities (a disabled service principal, a suspended installation) are listed by `inventory` but not reviewed.

SARIF `security-severity` is the highest score of the rule's results divided by 10, which GitHub code scanning shows as critical (9.0 and above), high (7.0 to 8.9), medium (4.0 to 6.9) or low.

## What the score does not know

- Conditions on IAM statements, permissions boundaries, service control policies and resource policies. A `*` policy under a strict boundary still scores 100; read the finding as "check the boundary".
- Exchange RBAC for Applications scopes and Conditional Access for workload identities.
- How much data sits behind a grant. `Mail.ReadWrite` on a tenant with ten mailboxes scores the same as on one with ten thousand.
