"""The off-switch runbook for one identity: ordered steps, the exact command for each, and how to verify it.

aos prints these commands and never runs them. The step builders are adapted from kill_switch_runbook.py in
https://github.com/basitalisandhu/agent-identity-governance-skills (MIT licence, same author), reordered into the
five phases below and extended with directory roles, managed identities and agent identities.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

from .model import Credential, Grant, Identity

PHASES = (
    "1 disable",
    "2 revoke sessions and grants",
    "3 rotate or delete credentials",
    "4 remove role assignments",
    "5 verify with the audit log",
)
GRAPH = "https://graph.microsoft.com"


@dataclass
class Step:
    phase: str
    title: str
    change: str
    verify: str
    covers: list[str] = field(default_factory=list)


def _cred(c: Credential) -> str:
    return f"credential {c.ref()}"


def _grant(g: Grant) -> str:
    return f"grant {g.key()}"


def full_key(key_id: str) -> str:
    """Placeholder for the full key id, which the person reads from the verification command."""
    key_id = str(key_id or "")
    if key_id.startswith("****") and len(key_id) > 4:
        return f"<key id ending {key_id[4:]}>"
    return f"<key id {key_id or 'unknown'}>"


# ---- Microsoft Entra -----------------------------------------------------------------------------------------------


def entra_steps(ident: Identity) -> list[Step]:
    refs = ident.refs
    app_id = refs.get("app_id") or "<appId>"
    sp = refs.get("service_principal_id") or "<service principal object id>"
    steps: list[Step] = []
    if ident.type == "entra-managed-identity":
        resource = refs.get("managed_identity_resource") or "<Azure resource id>"
        steps.append(
            Step(
                PHASES[0],
                "Detach the managed identity from the Azure resource that uses it (managed identities cannot be "
                "disabled in Entra)",
                f"Remove the identity from {resource}: for a system-assigned identity, "
                f"az resource update --ids {resource} --set identity.type=None (or the service's own "
                "'identity remove' command); for a user-assigned one, unassign it from every resource",
                f"az ad sp show --id {sp} --query servicePrincipalType   (a deleted system-assigned identity "
                "returns not found); az resource show --ids <resource> --query identity",
            )
        )
    else:
        steps.append(
            Step(
                PHASES[0],
                "Disable the service principal so Entra issues no new tokens",
                f"az rest --method PATCH --url {GRAPH}/v1.0/servicePrincipals/{sp} "
                "--headers Content-Type=application/json --body '{\"accountEnabled\": false}'",
                f'az rest --method GET --url "{GRAPH}/v1.0/servicePrincipals/{sp}?\\$select=accountEnabled"   '
                "(expect false)",
            )
        )
    steps.append(
        Step(
            PHASES[1],
            "Record the disable time: tokens already issued stay valid until they expire",
            "Workload identity access tokens cannot be revoked one by one; they run out (usually within an hour; "
            "longer for clients using continuous access evaluation). Write down the disable time (UTC) for step 5.",
            "Compare against step 5: no sign-in after the disable time plus the token lifetime.",
        )
    )
    for g in ident.grants:
        if g.kind == "delegated-permission":
            steps.append(
                Step(
                    PHASES[1],
                    f"Remove the delegated grant {g.name}",
                    f"az rest --method DELETE --url {GRAPH}/v1.0/oauth2PermissionGrants/{g.ref or '<grant id>'}",
                    f"az rest --method GET --url \"{GRAPH}/v1.0/oauth2PermissionGrants?\\$filter=clientId eq '{sp}'\""
                    "   (expect an empty list)",
                    [_grant(g)],
                )
            )
        elif g.kind == "application-permission":
            steps.append(
                Step(
                    PHASES[1],
                    f"Remove the application permission {g.name}",
                    f"az rest --method DELETE --url {GRAPH}/v1.0/servicePrincipals/{sp}/appRoleAssignments/"
                    f"{g.ref or '<assignment id>'}",
                    f"az rest --method GET --url {GRAPH}/v1.0/servicePrincipals/{sp}/appRoleAssignments   "
                    f"(expect {g.ref or 'the assignment'} gone)",
                    [_grant(g)],
                )
            )
    for c in ident.credentials:
        if c.kind in ("client-secret", "certificate"):
            cert = " --cert" if c.kind == "certificate" else ""
            steps.append(
                Step(
                    PHASES[2],
                    f"Delete the {c.kind} {c.key_id} on the app registration",
                    f"az ad app credential delete --id {app_id} --key-id {full_key(c.key_id)}{cert}",
                    f'az ad app credential list --id {app_id}{cert} --query "[].keyId"   (expect it gone)',
                    [_cred(c)],
                )
            )
        elif c.kind in ("sp-secret", "sp-certificate"):
            cert = " --cert" if c.kind == "sp-certificate" else ""
            steps.append(
                Step(
                    PHASES[2],
                    f"Delete the {c.kind} {c.key_id} on the service principal",
                    f"az ad sp credential delete --id {sp} --key-id {full_key(c.key_id)}{cert}",
                    f'az ad sp credential list --id {sp}{cert} --query "[].keyId"   (expect it gone)',
                    [_cred(c)],
                )
            )
        elif c.kind == "federated":
            steps.append(
                Step(
                    PHASES[2],
                    f"Delete the federated credential {c.key_id}",
                    f"az ad app federated-credential delete --id {app_id} --federated-credential-id "
                    f"{full_key(c.key_id)}",
                    f"az ad app federated-credential list --id {app_id}   (expect it gone)",
                    [_cred(c)],
                )
            )
    for g in ident.grants:
        if g.kind == "directory-role":
            steps.append(
                Step(
                    PHASES[3],
                    f"Remove the directory role {g.name}",
                    f"az rest --method DELETE --url {GRAPH}/v1.0/roleManagement/directory/roleAssignments/"
                    f"{g.ref or '<assignment id>'}",
                    f'az rest --method GET --url "{GRAPH}/v1.0/roleManagement/directory/roleAssignments?'
                    f"\\$filter=principalId eq '{sp}'\"   (expect an empty list)",
                    [_grant(g)],
                )
            )
    steps.append(
        Step(
            PHASES[3],
            "Remove Azure role assignments (not part of the exports, so check them here)",
            f"az role assignment delete --assignee {app_id} --role <role> --scope <scope>   (one per assignment)",
            f"az role assignment list --assignee {app_id} --all --output table   (expect no rows)",
        )
    )
    steps.append(
        Step(
            PHASES[4],
            "Confirm in the sign-in and audit logs that nothing succeeded after the disable time",
            "None (read only).",
            f"az rest --method GET --url \"{GRAPH}/beta/auditLogs/signIns?\\$filter=appId eq '{app_id}' and "
            "signInEventTypes/any(t: t eq 'servicePrincipal') and createdDateTime ge <disable time>\"; "
            f'az rest --method GET --url "{GRAPH}/v1.0/auditLogs/directoryAudits?\\$filter=initiatedBy/app/appId eq '
            f"'{app_id}' and activityDateTime ge <disable time>\"   (expect no successful sign-in, no change)",
        )
    )
    return steps


# ---- AWS -----------------------------------------------------------------------------------------------------------

REVOKE_OLDER = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*",'
    '"Condition":{"DateLessThan":{"aws:TokenIssueTime":"<disable time, ISO 8601 UTC>"}}}]}'
)


def aws_policy_steps(ident: Identity, kind: str, name: str) -> list[Step]:
    flag = "--role-name" if kind == "role" else "--user-name"
    steps = []
    for g in ident.grants:
        if g.kind == "managed-policy":
            steps.append(
                Step(
                    PHASES[3],
                    f"Detach the managed policy {g.name}",
                    f"aws iam detach-{kind}-policy {flag} {name} --policy-arn {g.ref or '<policy arn>'}",
                    f"aws iam list-attached-{kind}-policies {flag} {name}   (expect {g.name} gone)",
                    [_grant(g)],
                )
            )
        elif g.kind == "inline-policy":
            steps.append(
                Step(
                    PHASES[3],
                    f"Delete the inline policy {g.name} (save it first with get-{kind}-policy)",
                    f"aws iam delete-{kind}-policy {flag} {name} --policy-name {g.name}",
                    f"aws iam list-{kind}-policies {flag} {name}   (expect {g.name} gone)",
                    [_grant(g)],
                )
            )
        elif g.kind == "group":
            steps.append(
                Step(
                    PHASES[3],
                    f"Remove the user from the group {g.name}",
                    f"aws iam remove-user-from-group --user-name {name} --group-name {g.name}",
                    f"aws iam list-groups-for-user --user-name {name}   (expect {g.name} gone)",
                    [_grant(g)],
                )
            )
    return steps


def aws_role_steps(ident: Identity) -> list[Step]:
    role = ident.refs.get("role_name") or ident.name
    arn = ident.refs.get("arn") or role
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":["sts:AssumeRole",'
        '"sts:AssumeRoleWithWebIdentity","sts:AssumeRoleWithSAML","sts:TagSession","sts:SetSourceIdentity"]}]}'
    )
    who = ", ".join(ident.trust) or "its trusted principals"
    steps = [
        Step(
            PHASES[0],
            f"Stop new sessions: replace the trust policy (now trusts {who}) with a deny-all one; save the current one first",
            f"aws iam get-role --role-name {role} --query Role.AssumeRolePolicyDocument > trust-before.json && "
            f"aws iam update-assume-role-policy --role-name {role} --policy-document '{trust}'",
            f"aws iam get-role --role-name {role} --query Role.AssumeRolePolicyDocument   (expect only the Deny statement)",
            [f"trust {t}" for t in ident.trust],
        ),
        Step(
            PHASES[1],
            "Revoke every session issued before the disable time (the console's Revoke active sessions)",
            f"aws iam put-role-policy --role-name {role} --policy-name AWSRevokeOlderSessions "
            f"--policy-document '{REVOKE_OLDER}'",
            f"aws iam get-role-policy --role-name {role} --policy-name AWSRevokeOlderSessions",
        ),
        Step(
            PHASES[2],
            "No long-lived credential: a role has none; the trust change in step 1 stops new ones",
            "None.",
            f"aws iam get-role --role-name {role} --query Role.RoleLastUsed   (note the last use for step 5)",
        ),
    ]
    steps += aws_policy_steps(ident, "role", role)
    steps.append(
        Step(
            PHASES[4],
            "Confirm in CloudTrail that nothing succeeded after the disable time",
            "None (read only).",
            f"aws cloudtrail lookup-events --start-time <disable time> --lookup-attributes "
            f"AttributeKey=ResourceName,AttributeValue={arn} --output json > after.json   (then look for "
            f"AssumeRole on {role} and any event with a session of this role; expect only AccessDenied)",
        )
    )
    return steps


def aws_user_steps(ident: Identity) -> list[Step]:
    user = ident.refs.get("user_name") or ident.name
    steps = [
        Step(
            PHASES[0],
            "Attach the AWS managed deny-all policy (it also stops session credentials the user issued)",
            f"aws iam attach-user-policy --user-name {user} --policy-arn arn:aws:iam::aws:policy/AWSDenyAll",
            f"aws iam list-attached-user-policies --user-name {user}   (expect AWSDenyAll)",
        ),
        Step(
            PHASES[1],
            "Revoke sessions issued before the disable time",
            f"aws iam put-user-policy --user-name {user} --policy-name AWSRevokeOlderSessions "
            f"--policy-document '{REVOKE_OLDER}'",
            f"aws iam list-user-policies --user-name {user}   (expect AWSRevokeOlderSessions)",
        ),
    ]
    if ident.refs.get("console_password"):
        steps.append(
            Step(
                PHASES[1],
                "Remove the console password",
                f"aws iam delete-login-profile --user-name {user}",
                f"aws iam get-login-profile --user-name {user}   (expect NoSuchEntity)",
            )
        )
    for c in ident.credentials:
        steps.append(
            Step(
                PHASES[2],
                f"Deactivate access key {c.key_id}, then delete it once the evidence is kept",
                f"aws iam update-access-key --user-name {user} --access-key-id {full_key(c.key_id)} "
                f"--status Inactive && aws iam delete-access-key --user-name {user} --access-key-id "
                f"{full_key(c.key_id)}",
                f"aws iam list-access-keys --user-name {user}   (expect Inactive or gone)",
                [_cred(c)],
            )
        )
    steps += aws_policy_steps(ident, "user", user)
    steps.append(
        Step(
            PHASES[4],
            "Confirm in CloudTrail that nothing succeeded after the disable time",
            "None (read only).",
            f"aws cloudtrail lookup-events --start-time <disable time> --lookup-attributes "
            f"AttributeKey=Username,AttributeValue={user} --output json > after.json   (repeat with "
            "AttributeKey=AccessKeyId for each key; expect only AccessDenied)",
        )
    )
    return steps


# ---- GitHub --------------------------------------------------------------------------------------------------------


def github_steps(ident: Identity) -> list[Step]:
    refs = ident.refs
    if ident.type == "github-deploy-key":
        repo, key_id = refs.get("repository") or "<owner/repo>", refs.get("deploy_key_id") or "<key id>"
        owner = str(repo).split("/")[0]
        return [
            Step(
                PHASES[0],
                f"Delete the deploy key from {repo} (a deploy key cannot be disabled, only deleted)",
                f"gh api -X DELETE repos/{repo}/keys/{key_id}",
                f"gh api repos/{repo}/keys --jq '.[].id'   (expect {key_id} gone)",
                [_cred(c) for c in ident.credentials] + [_grant(g) for g in ident.grants],
            ),
            Step(
                PHASES[4],
                "Confirm in the organisation audit log that the key was removed and not used after",
                "None (read only).",
                f'gh api --paginate "/orgs/{owner}/audit-log?phrase=repo:{repo}+created:>=<disable date>"   '
                "(the audit log API needs GitHub Enterprise Cloud; otherwise use the web audit log)",
            ),
        ]
    account = refs.get("account") or "<organisation>"
    inst = refs.get("installation_id") or "<installation id>"
    return [
        Step(
            PHASES[0],
            "Suspend the app installation: every installation token stops working",
            f"https://github.com/organizations/{account}/settings/installations/{inst} > Suspend "
            "(an organisation owner; there is no owner-token API call for this)",
            f"gh api /orgs/{account}/installations --jq '.installations[] | select(.id=={inst}) | .suspended_at'"
            "   (expect a time)",
        ),
        Step(
            PHASES[1],
            "Installation tokens end with the suspension; user-to-server tokens of the app too",
            "None beyond step 1. If people authorised the app as themselves, ask them to revoke it under "
            "Settings > Applications > Authorized GitHub Apps.",
            f"gh api /orgs/{account}/installations --jq '.installations[] | select(.id=={inst}) | .suspended_at'",
        ),
        Step(
            PHASES[2],
            "If your organisation owns the app, delete its private keys and client secrets",
            f"https://github.com/organizations/{account}/settings/apps/{ident.name} > Private keys: delete each",
            "Re-open the same page: no private key is listed",
            [_cred(c) for c in ident.credentials],
        ),
        Step(
            PHASES[3],
            "Remove the installation, or cut it to the repositories it needs",
            f"https://github.com/organizations/{account}/settings/installations/{inst} > Uninstall (or Only "
            "select repositories)",
            f"gh api /orgs/{account}/installations --jq '.installations[] | select(.id=={inst})'   (expect "
            "nothing, or repository_selection selected)",
            [_grant(g) for g in ident.grants],
        ),
        Step(
            PHASES[4],
            "Confirm in the organisation audit log that nothing ran after the suspension",
            "None (read only).",
            f'gh api --paginate "/orgs/{account}/audit-log?phrase=actor:{ident.name}[bot]+created:>=<disable '
            'date>"   (the audit log API needs GitHub Enterprise Cloud; otherwise use the web audit log)',
        ),
    ]


def register_steps(ident: Identity) -> list[Step]:
    platform = ident.refs.get("platform") or "<platform that issued it>"
    gateway = ident.refs.get("gateway") or "<the gateway or proxy it calls through>"
    return [
        Step(
            PHASES[0],
            "Remove the agent or connector from every configuration that starts it",
            "Delete its entry from the MCP client configuration, agent runtime or plugin list it runs from, and "
            f"add a deny rule for it at {gateway}.",
            "Read the configuration back: the entry is gone. Read the gateway log: requests show as denied.",
        ),
        Step(
            PHASES[1],
            f"Revoke its sessions and OAuth grants at {platform}",
            f"In {platform}, revoke the connector's authorisation (connected apps or OAuth grants page).",
            f"List the connected apps or grants in {platform}: the connector is not listed.",
        ),
        Step(
            PHASES[2],
            f"Revoke its keys and tokens at {platform}",
            f"Revoke each key or token in {platform}'s console or API (one per credential below).",
            f"List the keys or tokens in {platform}: the revoked ones show as revoked or are gone.",
            [_cred(c) for c in ident.credentials],
        ),
        Step(
            PHASES[3],
            "Withdraw the access it was granted",
            "Remove each declared permission or scope at the system that granted it.",
            "List the grants at that system: none remains for this identity.",
            [_grant(g) for g in ident.grants],
        ),
        Step(
            PHASES[4],
            "Confirm in the platform and gateway logs that nothing succeeded after the switch-off",
            "None (read only).",
            f"Export the audit log of {platform} and the gateway from the switch-off time: no successful call.",
        ),
    ]


def build_steps(ident: Identity) -> list[Step]:
    if ident.platform == "entra":
        return entra_steps(ident)
    if ident.type == "aws-iam-role":
        return aws_role_steps(ident)
    if ident.type == "aws-iam-user":
        return aws_user_steps(ident)
    if ident.platform == "github":
        return github_steps(ident)
    return register_steps(ident)


def coverage(ident: Identity, steps: list[Step]) -> list[str]:
    """Credentials and grants of the identity that no step names."""
    named = {c for s in steps for c in s.covers}
    wanted = [_cred(c) for c in ident.credentials] + [_grant(g) for g in ident.grants]
    return [w for w in wanted if w not in named]


@dataclass
class Runbook:
    identity: Identity
    steps: list[Step]
    not_covered: list[str]


def runbook(ident: Identity) -> Runbook:
    steps = build_steps(ident)
    return Runbook(ident, steps, coverage(ident, steps))


def to_markdown(rb: Runbook, as_of: str) -> str:
    i = rb.identity
    lines = [
        f"# Off-switch runbook: {i.name}",
        "",
        f"Identity `{i.id}` ({i.type} on {i.platform}). Owners: {', '.join(i.owners) or 'none recorded'}. "
        f"Blast radius {i.blast_radius}. Exports as of {as_of}.",
        "",
        "aos printed these commands and ran none of them. Run each change in order, then its verification, and "
        "keep the verification output for the incident record. Values in <angle brackets> are for you to fill in.",
        "",
    ]
    current = ""
    for n, s in enumerate(rb.steps, start=1):
        if s.phase != current:
            current = s.phase
            lines += [f"## {s.phase.capitalize()}", ""]
        lines += [
            f"### Step {n}: {s.title}",
            "",
            "Change:",
            "",
            "```",
            s.change,
            "```",
            "",
            "Verify:",
            "",
            "```",
            s.verify,
            "```",
            "",
        ]
        if s.covers:
            lines += ["Covers: " + "; ".join(s.covers), ""]
        lines += ["- [ ] done (UTC time, by whom): ____", ""]
    lines += ["## Coverage", ""]
    if rb.not_covered:
        lines += ["Not covered by any step (add a step by hand):", ""] + [f"- {x}" for x in rb.not_covered]
    else:
        lines.append("Every credential and grant in the exports is named by a step.")
    return "\n".join(lines) + "\n"


def to_json(rb: Runbook, as_of: str) -> str:
    return (
        json.dumps(
            {
                "identity": rb.identity.id,
                "name": rb.identity.name,
                "as_of": as_of,
                "phases": list(PHASES),
                "steps": [asdict(s) for s in rb.steps],
                "not_covered": rb.not_covered,
            },
            indent=2,
        )
        + "\n"
    )
