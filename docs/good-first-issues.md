# Good first issues

Each task is small, has a clear test, and needs no cloud account: build the input inside the test with the helpers in `tests/conftest.py`. Comment on the matching issue (or open one) before you start.

1. **Read Azure role assignments.** Add an optional `azure-role-assignments.json` (`az role assignment list --all --output json`) to `exports.py`, attach each assignment to the Entra identity by `principalId`, score Owner and User Access Administrator at subscription scope as 95 and Contributor as 85, and drop the "not part of the exports" step from the runbook when the file is present. Tests: one per score, plus the runbook change.

2. **Honour permission boundaries.** When a role in `aws-authorization-details.json` has a `PermissionsBoundary`, look up the boundary document and cap each grant's score at the boundary's own score. Tests: a `*` role under a read-only boundary scores 30; without the boundary it stays 100.

3. **Fine-grained personal access tokens.** Read `github-fine-grained-tokens.json` (`gh api --paginate /orgs/ORG/personal-access-tokens`) as identities of type `github-pat`, with the token's expiry and last use, and add an `off` runbook (`gh api -X POST /orgs/ORG/personal-access-tokens/ID` with `action=revoke`). Tests: parser, stale flag, runbook coverage.

4. **Entra credential last use.** Read the beta report `/reports/appCredentialSignInActivities` into `Credential.last_used` for client secrets and certificates, so a stale secret that is still in use can be told apart from one nobody uses. Tests: match by `keyId`, unknown key ids ignored.

5. **`--min-score` for review.** Add `aos review --min-score N` to drop findings below N from every output format, including SARIF. Tests: the demo tenant with `--min-score 70` keeps only error-level findings; SARIF rules list only rules with results.

6. **CSV output for review.** Add `--format csv` to `review` with the columns rank, score, level, rule id, identity, message and fix. Tests: row count equals the finding count; a message holding a comma and a quote survives a round trip through `csv.reader`.

7. **Explain one score.** Add `aos inventory EXPORTS --explain IDENTITY` that prints each grant of one identity with its score and reason, highest first. Tests: the demo's `aws-role:coding-agent-runner` prints `Action * on Resource *` with 100.

8. **Accept-file expiry.** Let a line in the drift accept file end with `until YYYY-MM-DD`; after that date the acceptance no longer counts and the change gates again. Tests: before, on and after the date, and a malformed date as exit code 2.
