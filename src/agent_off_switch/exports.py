"""Readers for saved exports: Microsoft Entra (Graph), AWS IAM, GitHub, and the agents register.

Each reader adds to one inventory (a dict of identity id to Identity). Nothing here opens a network connection or
starts a process; every reader reads the files named in FILES from one folder. docs/exports.md lists the read-only
command that produces each file.

The Entra, AWS, GitHub and register readers are adapted from read_entra, read_aws, read_github and read_register in
nhi_inventory.py, https://github.com/basitalisandhu/agent-identity-governance-skills (MIT licence, same author).
Changes here: one typed model, policy documents kept for scoring, directory roles, access key last use, agent
signals, and register rows that point at an existing identity.
"""

from __future__ import annotations

import re
from pathlib import Path

from .model import Credential, Grant, Identity
from .scoring import as_list, policy_document
from .util import InputError, iso, items, load_csv, load_json, mask, parse_dt, tag_owner, tag_values

# Tenants that own Microsoft's first-party applications; their service principals are not yours to govern.
MICROSOFT_TENANTS = {"f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47"}
AGENT_NAME = re.compile(r"(?i)(agent|bot|copilot|assistant|mcp|autopilot|llm)")

FILES = {
    "entra-applications.json": "Graph /applications with owners expanded",
    "entra-service-principals.json": "Graph /servicePrincipals with owners expanded (includes managed identities)",
    "entra-app-role-assignments.json": "Graph appRoleAssignments of each service principal (application permissions)",
    "entra-oauth2-grants.json": "Graph /oauth2PermissionGrants (delegated permissions)",
    "entra-resource-sps.json": "Graph resource service principals with appRoles (names for role ids)",
    "entra-directory-roles.json": "Graph /roleManagement/directory/roleAssignments with roleDefinition expanded",
    "entra-sign-in-activity.json": "Graph beta /reports/servicePrincipalSignInActivities",
    "aws-authorization-details.json": "aws iam get-account-authorization-details",
    "aws-access-keys.json": "aws iam list-access-keys, one result per user",
    "aws-access-key-last-used.json": "aws iam get-access-key-last-used, one result per key with AccessKeyId added",
    "aws-credential-report.csv": "aws iam get-credential-report, decoded (optional)",
    "github-installations.json": "gh api /orgs/ORG/installations",
    "github-deploy-keys.json": "gh api repos/OWNER/REPO/keys, each key with a repository field",
    "agents.csv": "hand-kept register of agents and MCP connectors",
}
REGISTER_NAMES = ("agents.csv", "register.csv")


def _ident(inv: dict[str, Identity], key: str, platform: str, kind: str, name: str, source: str) -> Identity:
    if key not in inv:
        inv[key] = Identity(id=key, name=name, platform=platform, type=kind)
    ident = inv[key]
    ident.add_source(source)
    if AGENT_NAME.search(name or ""):
        ident.mark_agent("name")
    return ident


def _credential(kind: str, key_id, created, expires, status: str = "Active") -> Credential:
    return Credential(
        kind=kind,
        key_id=mask(key_id) if key_id else "****",
        created=iso(parse_dt(created)),
        expires=iso(parse_dt(expires)),
        status=status or "Active",
    )


def _owner_of(obj: dict) -> str:
    return str(obj.get("userPrincipalName") or obj.get("mail") or obj.get("displayName") or obj.get("appId") or "")


def _agent_tags(ident: Identity, tags) -> None:
    for t in tag_values(tags):
        low = t.lower()
        if low.startswith(("agent", "ai-agent", "workload=agent", "purpose=agent", "role=agent")) or "=agent" in low:
            ident.mark_agent(f"tag {t}")


# ---- Microsoft Entra -----------------------------------------------------------------------------------------------


def read_entra(folder: Path, inv: dict[str, Identity], notes: list[str]) -> None:
    apps_path = folder / "entra-applications.json"
    sps_path = folder / "entra-service-principals.json"
    if not apps_path.exists() and not sps_path.exists():
        return
    sp_by_object: dict[str, str] = {}
    for app in items(load_json(apps_path)) if apps_path.exists() else []:
        app_id = str(app.get("appId") or "")
        if not app_id:
            continue
        ident = _ident(
            inv, f"entra:{app_id}", "entra", "entra-app", str(app.get("displayName") or app_id), apps_path.name
        )
        ident.created = iso(parse_dt(app.get("createdDateTime")))
        ident.refs.update({"app_id": app_id, "application_object_id": app.get("id")})
        for o in app.get("owners") or []:
            ident.add_owner(_owner_of(o))
        ident.add_owner(tag_owner(app.get("tags")))
        _agent_tags(ident, app.get("tags"))
        if "agentidentityblueprint" in str(app.get("@odata.type", "")).lower():
            ident.mark_agent("Entra agent identity blueprint")
        for c in app.get("passwordCredentials") or []:
            ident.credentials.append(
                _credential("client-secret", c.get("keyId"), c.get("startDateTime"), c.get("endDateTime"))
            )
        for c in app.get("keyCredentials") or []:
            ident.credentials.append(
                _credential("certificate", c.get("keyId"), c.get("startDateTime"), c.get("endDateTime"))
            )
        for c in app.get("federatedIdentityCredentials") or []:
            fed = _credential("federated", c.get("id") or c.get("name"), None, None)
            fed.status = f"subject {c.get('subject', '?')}"
            ident.credentials.append(fed)
    for sp in items(load_json(sps_path)) if sps_path.exists() else []:
        app_id = str(sp.get("appId") or "")
        if not app_id or str(sp.get("appOwnerOrganizationId") or "") in MICROSOFT_TENANTS:
            continue
        sp_type = str(sp.get("servicePrincipalType") or "Application")
        is_agent_type = "agentidentity" in str(sp.get("@odata.type", "")).lower()
        key = f"entra:{app_id}"
        if key not in inv:
            if is_agent_type:
                kind = "entra-agent-identity"
            elif sp_type == "ManagedIdentity":
                kind = "entra-managed-identity"
            else:
                kind = "entra-enterprise-app"
            _ident(inv, key, "entra", kind, str(sp.get("displayName") or app_id), sps_path.name)
        ident = inv[key]
        ident.add_source(sps_path.name)
        if is_agent_type:
            ident.mark_agent("Entra agent identity")
        ident.refs.update({"app_id": app_id, "service_principal_id": sp.get("id"), "sp_type": sp_type})
        if sp_type == "ManagedIdentity":
            ident.refs["managed_identity_resource"] = (sp.get("alternativeNames") or [""])[-1]
        if sp.get("accountEnabled") is False:
            ident.enabled = False
        ident.created = ident.created or iso(parse_dt(sp.get("createdDateTime")))
        for o in sp.get("owners") or []:
            ident.add_owner(_owner_of(o))
        for s in sp.get("sponsors") or []:
            ident.add_owner(_owner_of(s))
        ident.add_owner(tag_owner(sp.get("tags")))
        _agent_tags(ident, sp.get("tags"))
        for c in sp.get("passwordCredentials") or []:
            ident.credentials.append(
                _credential("sp-secret", c.get("keyId"), c.get("startDateTime"), c.get("endDateTime"))
            )
        for c in sp.get("keyCredentials") or []:
            if str(c.get("usage", "Verify")).lower() == "verify":
                ident.credentials.append(
                    _credential("sp-certificate", c.get("keyId"), c.get("startDateTime"), c.get("endDateTime"))
                )
        if sp.get("id"):
            sp_by_object[str(sp["id"])] = key

    activity = folder / "entra-sign-in-activity.json"
    if activity.exists():
        for ident in inv.values():
            if ident.platform == "entra":
                ident.activity_recorded = True
        for row in items(load_json(activity)):
            key = f"entra:{row.get('appId')}"
            if key not in inv:
                continue
            seen = [
                parse_dt((v or {}).get("lastSignInDateTime"))
                for k, v in row.items()
                if k.lower().endswith("signinactivity") and isinstance(v, dict)
            ]
            seen = [s for s in seen if s]
            if seen:
                inv[key].last_used = iso(max(seen))
                inv[key].add_source(activity.name)
    else:
        notes.append("entra-sign-in-activity.json not found: Entra last use is unknown and not judged")

    role_names: dict[tuple[str, str], str] = {}
    resource_names: dict[str, str] = {}
    res_path = folder / "entra-resource-sps.json"
    if res_path.exists():
        for res in items(load_json(res_path)):
            resource_names[str(res.get("id"))] = str(res.get("displayName") or res.get("appId") or "")
            for role in res.get("appRoles") or []:
                role_names[(str(res.get("id")), str(role.get("id")))] = str(role.get("value") or role.get("id"))

    asg_path = folder / "entra-app-role-assignments.json"
    if asg_path.exists():
        for a in items(load_json(asg_path)):
            key = sp_by_object.get(str(a.get("principalId")))
            if not key:
                continue
            res_id, role_id = str(a.get("resourceId")), str(a.get("appRoleId"))
            perm = role_names.get((res_id, role_id), role_id)
            res = str(a.get("resourceDisplayName") or resource_names.get(res_id) or res_id)
            inv[key].grants.append(
                Grant(
                    kind="application-permission",
                    name=f"{res}: {perm}",
                    ref=str(a.get("id") or ""),
                    detail={"permission": perm, "resource": res, "resource_id": res_id},
                )
            )
            inv[key].add_source(asg_path.name)

    grants_path = folder / "entra-oauth2-grants.json"
    if grants_path.exists():
        for g in items(load_json(grants_path)):
            key = sp_by_object.get(str(g.get("clientId")))
            if not key:
                continue
            res = resource_names.get(str(g.get("resourceId")), str(g.get("resourceId")))
            all_users = g.get("consentType") == "AllPrincipals"
            for scope in str(g.get("scope") or "").split():
                inv[key].grants.append(
                    Grant(
                        kind="delegated-permission",
                        name=f"{res}: {scope} ({'all users' if all_users else 'one user'})",
                        ref=str(g.get("id") or ""),
                        detail={"permission": scope, "all_users": all_users, "resource": res},
                    )
                )
            inv[key].add_source(grants_path.name)

    roles_path = folder / "entra-directory-roles.json"
    if roles_path.exists():
        for r in items(load_json(roles_path)):
            key = sp_by_object.get(str(r.get("principalId")))
            if not key:
                continue
            definition = r.get("roleDefinition") or {}
            role = str(definition.get("displayName") or r.get("roleDefinitionId") or "unknown role")
            scope = str(r.get("directoryScopeId") or "/")
            inv[key].grants.append(
                Grant(
                    kind="directory-role",
                    name=role,
                    scope="tenant" if scope == "/" else f"scope {scope}",
                    ref=str(r.get("id") or ""),
                    detail={"role_definition_id": r.get("roleDefinitionId"), "directory_scope": scope},
                )
            )
            inv[key].add_source(roles_path.name)


# ---- AWS -----------------------------------------------------------------------------------------------------------


def trust_principals(doc) -> list[str]:
    out: list[str] = []
    for st in as_list(policy_document(doc).get("Statement")):
        if not isinstance(st, dict) or st.get("Effect", "Allow") != "Allow":
            continue
        principal = st.get("Principal", {})
        if isinstance(principal, str):
            out.append(f"AWS: {principal}")
            continue
        for kind, vals in principal.items():
            for v in as_list(vals):
                out.append(f"{kind}: {v}")
    return out


def _policy_versions(policy: dict) -> list:
    docs = []
    for v in policy.get("PolicyVersionList") or []:
        if v.get("IsDefaultVersion", True):
            docs.append(v.get("Document"))
    return docs


def read_aws(folder: Path, inv: dict[str, Identity], notes: list[str], include_managed: bool) -> None:
    details_path = folder / "aws-authorization-details.json"
    keys_path = folder / "aws-access-keys.json"
    last_path = folder / "aws-access-key-last-used.json"
    report_path = folder / "aws-credential-report.csv"
    details = load_json(details_path) if details_path.exists() else {}
    if details and not isinstance(details, dict):
        raise InputError(f"{details_path.name}: expected the object printed by get-account-authorization-details")
    users = {str(u.get("UserName")): u for u in items(details, "UserDetailList")} if details else {}
    groups = {str(g.get("GroupName")): g for g in items(details, "GroupDetailList")} if details else {}
    customer_policies = {str(p.get("Arn")): _policy_versions(p) for p in items(details, "Policies")} if details else {}

    def managed_grant(p: dict) -> Grant:
        arn = str(p.get("PolicyArn") or "")
        return Grant(
            kind="managed-policy",
            name=str(p.get("PolicyName") or arn),
            ref=arn,
            detail={"documents": customer_policies.get(arn, [])},
        )

    def inline_grant(p: dict) -> Grant:
        return Grant(
            kind="inline-policy",
            name=str(p.get("PolicyName") or "inline"),
            detail={"document": p.get("PolicyDocument")},
        )

    keys_by_user: dict[str, list[dict]] = {}
    if keys_path.exists():
        for k in items(load_json(keys_path), "AccessKeyMetadata"):
            keys_by_user.setdefault(str(k.get("UserName")), []).append(k)
    last_used: dict[str, dict] = {}
    if last_path.exists():
        for row in items(load_json(last_path)):
            if row.get("AccessKeyId"):
                last_used[str(row["AccessKeyId"])] = row.get("AccessKeyLastUsed") or {}
    report: dict[str, dict] = {}
    if report_path.exists():
        rows = load_csv(report_path)
        if rows and "user" not in rows[0]:
            raise InputError(f"{report_path.name}: no 'user' column; is this the decoded credential report?")
        report = {r["user"]: r for r in rows if r.get("user") and r["user"] != "<root_account>"}
    if keys_by_user and not last_used and not report:
        notes.append("aws-access-key-last-used.json not found: AWS access key last use is unknown and not judged")

    names = set(keys_by_user)
    for name, row in report.items():
        if any(str(row.get(f"access_key_{n}_active", "")).lower() == "true" for n in (1, 2)):
            names.add(name)
    for name in sorted(names):
        u, row = users.get(name, {}), report.get(name, {})
        ident = _ident(inv, f"aws-user:{name}", "aws", "aws-iam-user", name, keys_path.name)
        if u:
            ident.add_source(details_path.name)
        ident.refs.update({"user_name": name, "arn": u.get("Arn") or row.get("arn")})
        ident.created = iso(parse_dt(u.get("CreateDate") or row.get("user_creation_time")))
        ident.add_owner(tag_owner(u.get("Tags")))
        _agent_tags(ident, u.get("Tags"))
        uses = []
        for k in keys_by_user.get(name, []):
            c = _credential("access-key", k.get("AccessKeyId"), k.get("CreateDate"), None, k.get("Status", ""))
            lu = last_used.get(str(k.get("AccessKeyId")))
            if lu is not None:
                ident.activity_recorded = True
                c.last_used = iso(parse_dt(lu.get("LastUsedDate")))
                if c.last_used:
                    uses.append(c.last_used)
                ident.add_source(last_path.name)
            ident.credentials.append(c)
        if not keys_by_user.get(name):
            for n in (1, 2):
                if str(row.get(f"access_key_{n}_active", "")).lower() == "true":
                    c = _credential("access-key", None, row.get(f"access_key_{n}_last_rotated"), None)
                    c.key_id = f"slot {n}"
                    c.last_used = iso(parse_dt(row.get(f"access_key_{n}_last_used_date")))
                    ident.credentials.append(c)
        if row:
            ident.activity_recorded = True
            ident.add_source(report_path.name)
            uses += [iso(parse_dt(row.get(f"access_key_{n}_last_used_date"))) for n in (1, 2)]
            if str(row.get("password_enabled", "")).lower() == "true":
                ident.refs["console_password"] = True
        uses = [x for x in uses if x]
        ident.last_used = max(uses) if uses else None
        for p in u.get("AttachedManagedPolicies") or []:
            ident.grants.append(managed_grant(p))
        for p in u.get("UserPolicyList") or []:
            ident.grants.append(inline_grant(p))
        for gname in u.get("GroupList") or []:
            g = groups.get(str(gname), {})
            policies = [
                {
                    "name": p.get("PolicyName"),
                    "arn": p.get("PolicyArn"),
                    "documents": customer_policies.get(str(p.get("PolicyArn")), []),
                }
                for p in g.get("AttachedManagedPolicies") or []
            ] + [
                {"name": p.get("PolicyName"), "arn": "", "documents": [p.get("PolicyDocument")]}
                for p in g.get("GroupPolicyList") or []
            ]
            ident.grants.append(Grant(kind="group", name=str(gname), detail={"policies": policies}))

    for r in items(details, "RoleDetailList") if details else []:
        path = str(r.get("Path") or "/")
        if not include_managed and (path.startswith("/aws-service-role/") or path.startswith("/aws-reserved/")):
            continue
        name = str(r.get("RoleName"))
        ident = _ident(inv, f"aws-role:{name}", "aws", "aws-iam-role", name, details_path.name)
        ident.refs.update({"role_name": name, "arn": r.get("Arn")})
        ident.created = iso(parse_dt(r.get("CreateDate")))
        ident.activity_recorded = True
        ident.last_used = iso(parse_dt((r.get("RoleLastUsed") or {}).get("LastUsedDate")))
        ident.trust = trust_principals(r.get("AssumeRolePolicyDocument"))
        ident.add_owner(tag_owner(r.get("Tags")))
        _agent_tags(ident, r.get("Tags"))
        for p in r.get("AttachedManagedPolicies") or []:
            ident.grants.append(managed_grant(p))
        for p in r.get("RolePolicyList") or []:
            ident.grants.append(inline_grant(p))


# ---- GitHub --------------------------------------------------------------------------------------------------------


def read_github(folder: Path, inv: dict[str, Identity]) -> None:
    inst_path, keys_path = folder / "github-installations.json", folder / "github-deploy-keys.json"
    if inst_path.exists():
        for i in items(load_json(inst_path), "installations"):
            slug = str(i.get("app_slug") or i.get("app_id") or i.get("id"))
            ident = _ident(inv, f"github-app:{slug}", "github", "github-app", slug, inst_path.name)
            selection = str(i.get("repository_selection") or "unknown")
            ident.refs.update(
                {
                    "installation_id": i.get("id"),
                    "app_id": i.get("app_id"),
                    "account": (i.get("account") or {}).get("login"),
                    "repository_selection": selection,
                }
            )
            ident.created = iso(parse_dt(i.get("created_at")))
            ident.enabled = not i.get("suspended_at")
            for perm, level in sorted((i.get("permissions") or {}).items()):
                ident.grants.append(
                    Grant(kind="app-permission", name=f"{perm}:{level}", detail={"repository_selection": selection})
                )
    if keys_path.exists():
        data = load_json(keys_path)
        rows = items(data)
        if isinstance(data, dict) and not rows:
            rows = [dict(k, repository=repo) for repo, ks in data.items() if isinstance(ks, list) for k in ks]
        for k in rows:
            repo = str(k.get("repository") or "unknown-repository")
            key = f"github-deploy-key:{repo}#{k.get('id')}"
            ident = _ident(inv, key, "github", "github-deploy-key", str(k.get("title") or key), keys_path.name)
            ident.refs.update({"repository": repo, "deploy_key_id": k.get("id")})
            ident.created = iso(parse_dt(k.get("created_at")))
            ident.credentials.append(_credential("deploy-key", k.get("id"), k.get("created_at"), None))
            read_only = k.get("read_only", True) is not False
            ident.grants.append(
                Grant(
                    kind="repository-access",
                    name=f"{repo} ({'read-only' if read_only else 'read-write'})",
                    scope=repo,
                    detail={"repository": repo, "read_only": read_only},
                )
            )
            if "last_used" in k:
                ident.activity_recorded = True
                ident.last_used = iso(parse_dt(k.get("last_used")))


# ---- register of agents and MCP connectors -------------------------------------------------------------------------


def find_identity(inv: dict[str, Identity], value: str) -> Identity | None:
    """An identity by id, name, app id, object id, ARN or role or user name (ignoring case)."""
    value = (value or "").strip()
    if not value:
        return None
    if value in inv:
        return inv[value]
    low = value.lower()
    for ident in inv.values():
        candidates = [ident.id, ident.name] + [str(v) for v in ident.refs.values() if isinstance(v, (str, int))]
        if any(low == str(c).lower() for c in candidates if c):
            return ident
    return None


def read_register(folder: Path, inv: dict[str, Identity]) -> None:
    for fname in REGISTER_NAMES:
        path = folder / fname
        if not path.exists():
            continue
        rows = load_csv(path)
        if rows and "id" not in rows[0] and "name" not in rows[0]:
            raise InputError(f"{path.name}: needs an 'id' or 'name' column")
        for n, row in enumerate(rows, start=2):
            rid = row.get("id") or row.get("name") or ""
            if not rid:
                raise InputError(f"{path.name}: line {n} has no id or name")
            label = row.get("name") or rid
            target = find_identity(inv, row.get("identity", "")) if row.get("identity") else None
            if row.get("identity") and target is None:
                raise InputError(f"{path.name}: line {n} points at identity {row['identity']!r}, which no export holds")
            if target is None:
                target = find_identity(inv, rid) if ":" in rid else None
            if target is None:
                key = rid if ":" in rid else f"register:{rid}"
                kind = row.get("type") or "agent"
                target = _ident(inv, key, "register", kind, label, path.name)
                target.created = iso(parse_dt(row.get("created")))
                if row.get("last_used"):
                    target.activity_recorded = True
                    target.last_used = iso(parse_dt(row.get("last_used")))
                if row.get("credential_created") or row.get("credential_expires") or row.get("credential_id"):
                    target.credentials.append(
                        _credential(
                            row.get("credential_kind") or "api-key",
                            row.get("credential_id"),
                            row.get("credential_created"),
                            row.get("credential_expires"),
                        )
                    )
                for p in filter(None, (x.strip() for x in row.get("permissions", "").split(";"))):
                    target.grants.append(Grant(kind="declared-permission", name=p))
            else:
                target.add_source(path.name)
                if label not in target.used_by:
                    target.used_by.append(label)
            target.mark_agent(f"listed in {path.name}" + (f" as {label}" if label != target.name else ""))
            target.add_owner(row.get("owner", ""))
            target.purpose = target.purpose or row.get("purpose", "")
            target.refs.setdefault("register_line", n)
            for field_name in ("platform", "gateway"):
                if row.get(field_name):
                    target.refs[field_name] = row[field_name]
