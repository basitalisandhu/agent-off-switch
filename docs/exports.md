# Exports: what aos reads and how to produce each file

aos reads one folder. Every file is optional, but at least one must be present; aos uses whatever it finds and says in the Notes section what it could not judge. Put the files in one folder with exactly these names. Every command below only reads.

Keep the folder access-controlled: the exports hold names, application ids, owners and permission lists. aos never reads a secret value (Graph and IAM do not return them), and it shows key ids by their last four characters only.

## Permissions to run the commands

| Platform | Read-only access that is enough |
|---|---|
| Microsoft Entra | `Application.Read.All`, `Directory.Read.All`, `RoleManagement.Read.Directory`, `AuditLog.Read.All` (sign-in activity needs Entra ID P1 or P2); the Global Reader role covers all of them |
| AWS | `iam:GetAccountAuthorizationDetails`, `iam:ListUsers`, `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed` (the AWS managed `SecurityAudit` policy covers them) |
| GitHub | an organisation owner, or a token with `read:org` and admin read on the repositories for deploy keys |

## Microsoft Entra (Graph)

The commands use the Azure CLI (`az login` as a reader, then `az rest`). `--paginate` is not available in `az rest`, so the loops below follow `@odata.nextLink`; the Microsoft Graph PowerShell SDK with `-All` works as well. aos accepts a single Graph page (`{"value": [...]}`), a list of pages, or a bare list.

A helper that follows paging (bash, needs `jq`):

```bash
graph_all() {  # usage: graph_all URL > file.json
  url="$1"; echo '{"value": ['; first=1
  while [ -n "$url" ]; do
    page=$(az rest --method GET --url "$url")
    rows=$(echo "$page" | jq -c '.value[]')
    [ -n "$rows" ] && { [ $first = 1 ] || echo ','; echo "$rows" | paste -sd, -; first=0; }
    url=$(echo "$page" | jq -r '."@odata.nextLink" // empty')
  done
  echo ']}'
}
```

| File | Command |
|---|---|
| `entra-applications.json` | `graph_all 'https://graph.microsoft.com/v1.0/applications?$expand=owners($select=id,userPrincipalName,mail,displayName)' > entra-applications.json` |
| `entra-service-principals.json` | `graph_all 'https://graph.microsoft.com/v1.0/servicePrincipals?$expand=owners($select=id,userPrincipalName,mail,displayName)' > entra-service-principals.json` (managed identities are the rows with `servicePrincipalType` `ManagedIdentity`; Entra agent identities carry an `@odata.type` that names `agentIdentity`, so use the `beta` endpoint if you have them) |
| `entra-app-role-assignments.json` | for each service principal id: `az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals/$ID/appRoleAssignments"`; combine the `value` arrays: `jq -s '{value: map(.value) \| add}' sp-*.json > entra-app-role-assignments.json` |
| `entra-oauth2-grants.json` | `graph_all 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants' > entra-oauth2-grants.json` |
| `entra-resource-sps.json` | the service principals your apps hold roles on, with their `appRoles`, for example Microsoft Graph: `graph_all "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appId eq '00000003-0000-0000-c000-000000000000'&\$select=id,appId,displayName,appRoles" > entra-resource-sps.json` (without this file, permissions show as role ids) |
| `entra-directory-roles.json` | `graph_all 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=roleDefinition($select=id,displayName)' > entra-directory-roles.json` |
| `entra-sign-in-activity.json` | `graph_all 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities' > entra-sign-in-activity.json` |

Notes:

- Microsoft first-party service principals (owned by Microsoft's own tenants) are skipped.
- Owners come from `owners`, `sponsors` (agent identities) and a tag of the form `owner:team@example.com`.
- Azure role assignments (subscriptions, resource groups) are not read; the `off` runbook includes a step that lists and removes them.

## AWS IAM

Run per account with a read-only profile.

| File | Command |
|---|---|
| `aws-authorization-details.json` | `aws iam get-account-authorization-details --output json > aws-authorization-details.json` |
| `aws-access-keys.json` | `for u in $(aws iam list-users --query 'Users[].UserName' --output text); do aws iam list-access-keys --user-name "$u" --output json; done \| jq -s . > aws-access-keys.json` |
| `aws-access-key-last-used.json` | `jq -r '.[].AccessKeyMetadata[].AccessKeyId' aws-access-keys.json \| while read k; do aws iam get-access-key-last-used --access-key-id "$k" --output json \| jq --arg k "$k" '. + {AccessKeyId: $k}'; done \| jq -s . > aws-access-key-last-used.json` |
| `aws-credential-report.csv` (optional) | `aws iam generate-credential-report && aws iam get-credential-report --query Content --output text \| base64 --decode > aws-credential-report.csv` |

Notes:

- `get-access-key-last-used` does not return the key id, so the command above adds it as `AccessKeyId`; aos matches last use to keys by that field.
- IAM users appear when they hold an access key. Roles under `/aws-service-role/` and `/aws-reserved/` are skipped unless you pass `--include-aws-managed-roles`.
- Customer managed policy documents come from the `Policies` list of the authorisation details; AWS managed policies are scored by name (see [scoring.md](scoring.md)).
- Owners come from a tag named `owner` (or `owner-email`).

## GitHub

| File | Command |
|---|---|
| `github-installations.json` | `gh api --paginate /orgs/ORG/installations > github-installations.json` |
| `github-deploy-keys.json` | `for r in $(gh repo list ORG --limit 1000 --json nameWithOwner --jq '.[].nameWithOwner'); do gh api "repos/$r/keys" \| jq --arg r "$r" 'map(. + {repository: $r})'; done \| jq -s 'add' > github-deploy-keys.json` |

Notes:

- The installations list carries no last-use date, so GitHub App activity is not judged.
- A mapping of repository name to key list (`{"ORG/REPO": [...]}`) is also accepted.

## The register: `agents.csv`

A hand-kept CSV for what no export shows: which identity an agent runs as, who owns it, and MCP connectors or API keys that live outside Entra, AWS and GitHub. `register.csv` is read too, for registers kept for agent-identity-governance-skills.

| Column | Meaning |
|---|---|
| `id` | short id of the agent or connector (required, or `name`) |
| `name` | display name |
| `type` | for example `coding-agent`, `mcp-connector`, `agent` |
| `owner` | person or team mailbox that answers for it |
| `purpose` | one line |
| `platform` | where its credential lives (used in the runbook) |
| `identity` | the identity it runs as: an aos id (`aws-role:NAME`, `entra:APPID`, `github-app:SLUG`), an app id, an object id, an ARN or a name; aos stops with an error if no export holds it |
| `permissions` | declared scopes, separated by `;` (rows without `identity` only) |
| `last_used`, `credential_kind`, `credential_id`, `credential_created`, `credential_expires` | for rows without `identity`; `credential_id` is shown by its last four characters |
| `gateway` | the gateway or proxy it calls through (used in the runbook) |

A row with `identity` adds its owner, purpose and name to that identity and marks it as an agent. A row without `identity` becomes its own identity, `register:<id>`.

The demo tenant in [examples/demo-tenant](../examples/demo-tenant) has one file of each kind.
