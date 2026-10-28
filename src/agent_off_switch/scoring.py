"""Blast-radius scoring: how much one grant lets an identity reach or change, from 0 to 100.

The rules are fixed lists and pattern checks, documented in docs/scoring.md. An identity's blast radius is the
highest score among its grants. The Graph permission list started from the HIGH_RISK set in entra_agent_review.py
(https://github.com/basitalisandhu/agent-identity-governance-skills, MIT licence, same author) and is split here
into escalation, data-write and data-read tiers.
"""

from __future__ import annotations

import json
import re

from . import _jsondepth
from .model import Grant, Identity

# ---- Microsoft Entra and Microsoft Graph -------------------------------------------------------------------------

# Directory roles that can take over the tenant, or grant themselves anything.
ADMIN_ROLES_TOP = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
}
# Directory roles that can add credentials to other applications, change sign-in policy or identity sync.
ADMIN_ROLES_ESCALATION = {
    "Application Administrator",
    "Cloud Application Administrator",
    "Conditional Access Administrator",
    "Hybrid Identity Administrator",
    "Authentication Policy Administrator",
}

# Application permissions that let the holder grant itself more access.
GRAPH_ESCALATION = {
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "DelegatedPermissionGrant.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Domain.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess",
    "RoleManagement.ReadWrite.Directory",
    "UserAuthenticationMethod.ReadWrite.All",
}
# Application permissions that change mail, files, chats or accounts across the whole tenant.
GRAPH_DATA_WRITE = {
    "Calendars.ReadWrite",
    "Chat.ReadWrite.All",
    "Contacts.ReadWrite",
    "Device.ReadWrite.All",
    "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementManagedDevices.PrivilegedOperations.All",
    "Exchange.ManageAsApp",
    "Files.ReadWrite.All",
    "full_access_as_app",
    "Group.ReadWrite.All",
    "GroupMember.ReadWrite.All",
    "IdentityRiskyUser.ReadWrite.All",
    "Mail.ReadWrite",
    "Mail.Send",
    "MailboxSettings.ReadWrite",
    "Sites.FullControl.All",
    "Sites.Manage.All",
    "Sites.ReadWrite.All",
    "User.ReadWrite.All",
}
# Application permissions that read mail, files, chats or the directory across the whole tenant.
GRAPH_DATA_READ = {
    "AuditLog.Read.All",
    "Calendars.Read",
    "ChannelMessage.Read.All",
    "Chat.Read.All",
    "Contacts.Read",
    "Directory.Read.All",
    "Files.Read.All",
    "Mail.Read",
    "MailboxSettings.Read",
    "Sites.Read.All",
    "User.Read.All",
}
HIGH_RISK_GRAPH = GRAPH_ESCALATION | GRAPH_DATA_WRITE | GRAPH_DATA_READ

# ---- AWS -----------------------------------------------------------------------------------------------------------

AWS_MANAGED = {
    "AdministratorAccess": (100, "AWS managed AdministratorAccess: Action * on Resource *"),
    "IAMFullAccess": (90, "AWS managed IAMFullAccess: can create users, keys and policies"),
    "PowerUserAccess": (85, "AWS managed PowerUserAccess: every service except most of IAM"),
    "ReadOnlyAccess": (50, "AWS managed ReadOnlyAccess: reads every service in the account"),
    "AWSDenyAll": (0, "AWS managed AWSDenyAll: denies everything"),
}
IAM_ESCALATION_ACTIONS = re.compile(
    r"(?i)^(iam:(\*|Create\w*|Attach\w*|Put\w*|PassRole|Update\w*|Add\w*)|sts:AssumeRole\w*|organizations:\*)$"
)
READ_ONLY_VERB = re.compile(r"(?i)^[a-z0-9-]+:(Get|List|Describe|Head|Lookup|View|Search|Select|Query|Scan)")

# ---- GitHub ----------------------------------------------------------------------------------------------------------

GITHUB_SENSITIVE_WRITE = {
    "contents",
    "workflows",
    "secrets",
    "organization_secrets",
    "actions",
    "environments",
    "pull_requests",
    "packages",
}

ESCALATION_WORDS = re.compile(r"(?i)(\*|admin|owner|full[ _-]?control|full[ _-]?access)")
WRITE_WORDS = re.compile(r"(?i)(write|send|delete|manage|create|update|push|execute|exec|shell)")


def graph_application_score(permission: str) -> tuple[int, str]:
    if permission in GRAPH_ESCALATION:
        return 95, f"{permission} as an application permission can grant the holder more access across the tenant"
    if permission in GRAPH_DATA_WRITE:
        return 90, f"{permission} as an application permission changes data for every user in the tenant"
    if permission in GRAPH_DATA_READ:
        return 75, f"{permission} as an application permission reads data for every user in the tenant"
    if re.search(r"(?i)(ReadWrite|Manage|FullControl|Send)", permission):
        return 60, f"{permission} is a tenant-wide application permission that changes data"
    return 40, f"{permission} is a tenant-wide application permission"


def delegated_score(permission: str, all_users: bool) -> tuple[int, str]:
    risky = permission in HIGH_RISK_GRAPH or permission == "Directory.AccessAsUser.All"
    if all_users:
        if risky:
            return 50, f"{permission} delegated for all users: it acts for every user who signs in to it"
        return 20, f"{permission} delegated for all users"
    if risky:
        return 25, f"{permission} delegated for one user"
    return 10, f"{permission} delegated for one user"


def directory_role_score(role: str) -> tuple[int, str]:
    if role in ADMIN_ROLES_TOP:
        return 100, f"{role} controls the whole tenant"
    if role in ADMIN_ROLES_ESCALATION:
        return 95, f"{role} can add credentials to other applications or change sign-in policy"
    if role.endswith("Administrator"):
        return 85, f"{role} is an admin role"
    if role == "Global Reader":
        return 50, "Global Reader reads every directory setting"
    return 40, f"{role} is a directory role"


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def policy_document(doc) -> dict:
    """A policy document as a dict, from a dict, JSON text or URL-encoded JSON text."""
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        text = doc
        if "%" in text and not text.lstrip().startswith("{"):
            text = re.sub(r"%([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), text.replace("+", " "))
        try:
            parsed = _jsondepth.loads(text)
        except (json.JSONDecodeError, RecursionError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def aws_document_score(doc) -> tuple[int, str]:
    """Score the Allow statements of one IAM policy document."""
    best, why = 0, "no Allow statement"
    for st in as_list(policy_document(doc).get("Statement")):
        if not isinstance(st, dict) or st.get("Effect") != "Allow":
            continue
        actions = [str(a) for a in as_list(st.get("Action"))]
        resources = [str(r) for r in as_list(st.get("Resource"))]
        any_resource = "*" in resources or "NotResource" in st
        if "NotAction" in st:
            score, reason = (95 if any_resource else 85), "Allow with NotAction grants every action not listed"
        elif "*" in actions and any_resource:
            score, reason = 100, "Action * on Resource *"
        elif "*" in actions:
            score, reason = 90, "Action * on " + ", ".join(resources[:2])
        elif any(IAM_ESCALATION_ACTIONS.match(a) for a in actions) and any_resource:
            hit = next(a for a in actions if IAM_ESCALATION_ACTIONS.match(a))
            score, reason = 90, f"{hit} on Resource * can create or assume other access"
        elif any(a.endswith(":*") for a in actions) and any_resource:
            hit = next(a for a in actions if a.endswith(":*"))
            score, reason = 75, f"{hit} on Resource *"
        elif any(a.endswith(":*") for a in actions):
            hit = next(a for a in actions if a.endswith(":*"))
            score, reason = 55, f"{hit} on named resources"
        elif any_resource and not all(READ_ONLY_VERB.match(a) for a in actions):
            score, reason = 45, "write actions on Resource *"
        elif any_resource:
            score, reason = 30, "read actions on Resource *"
        else:
            score, reason = 20, "named actions on named resources"
        if score > best:
            best, why = score, reason
    return best, why


def aws_policy_score(name: str, arn: str, documents: list) -> tuple[int, str]:
    if arn.startswith("arn:aws:iam::aws:policy/") or (not arn and name in AWS_MANAGED):
        if name in AWS_MANAGED:
            return AWS_MANAGED[name]
        if not documents:
            if name.endswith("FullAccess"):
                return 75, f"AWS managed {name}: every action of one service"
            if "ReadOnly" in name:
                return 30, f"AWS managed {name}: read only"
            return 35, f"AWS managed {name}: document not in the export"
    if documents:
        scored = [aws_document_score(d) for d in documents]
        return max(scored, key=lambda x: x[0])
    return 35, f"{name}: policy document not in the export"


def github_permission_score(permission: str, level: str, all_repos: bool) -> tuple[int, str]:
    where = "every repository" if all_repos else "the selected repositories"
    level = level.lower()
    if permission == "organization_administration" and level in ("write", "admin"):
        return 100, "organisation administration: write changes organisation settings"
    if permission == "administration" and level in ("write", "admin"):
        if all_repos:
            return 95, "administration: write on every repository (settings, branch protection, deletion)"
        return 70, "administration: write on the selected repositories"
    if permission in ("members", "organization_user_blocking") and level == "write":
        return 85, f"{permission}: write changes organisation membership"
    if level in ("write", "admin"):
        if permission in GITHUB_SENSITIVE_WRITE:
            return (80 if all_repos else 55), f"{permission}: write on {where}"
        return (60 if all_repos else 40), f"{permission}: write on {where}"
    if permission in ("contents", "secrets", "organization_secrets") and all_repos:
        return 45, f"{permission}: read on {where}"
    return (30 if all_repos else 15), f"{permission}: {level} on {where}"


def declared_score(text: str) -> tuple[int, str]:
    if ESCALATION_WORDS.search(text):
        return 80, f"declared permission '{text}' reads as admin or wildcard access"
    if WRITE_WORDS.search(text):
        return 50, f"declared permission '{text}' changes data"
    return 20, f"declared permission '{text}'"


def score_grant(g: Grant) -> Grant:
    """Fill in score, reason and scope for one grant from its kind, name and detail."""
    d = g.detail or {}
    if g.kind == "directory-role":
        g.score, g.reason = directory_role_score(g.name)
        g.scope = g.scope or "tenant"
    elif g.kind == "application-permission":
        perm = d.get("permission") or g.name.split(": ")[-1]
        g.score, g.reason = graph_application_score(perm)
        g.scope = "tenant"
    elif g.kind == "delegated-permission":
        perm = d.get("permission") or g.name
        all_users = bool(d.get("all_users"))
        g.score, g.reason = delegated_score(perm, all_users)
        g.scope = "all users" if all_users else "one user"
    elif g.kind in ("managed-policy", "inline-policy"):
        docs = d.get("documents") or ([d["document"]] if d.get("document") else [])
        g.score, g.reason = aws_policy_score(g.name, g.ref if g.kind == "managed-policy" else "", docs)
        g.scope = g.scope or "account"
    elif g.kind == "group":
        scores = [
            aws_policy_score(p.get("name", ""), p.get("arn", ""), p.get("documents") or [])
            for p in d.get("policies") or []
        ]
        if scores:
            s, r = max(scores, key=lambda x: x[0])
            g.score, g.reason = s, f"through group {g.name}: {r}"
        else:
            g.score, g.reason = 30, f"group {g.name}: its policies are not in the export"
        g.scope = g.scope or "account"
    elif g.kind == "app-permission":
        perm, _, level = g.name.partition(":")
        all_repos = d.get("repository_selection") == "all"
        g.score, g.reason = github_permission_score(perm, level, all_repos)
        g.scope = "all repositories" if all_repos else "selected repositories"
    elif g.kind == "repository-access":
        if d.get("read_only", True):
            g.score, g.reason = 20, f"read-only deploy key on {d.get('repository')}"
        else:
            g.score, g.reason = 50, f"read-write deploy key: can push to {d.get('repository')}"
        g.scope = g.scope or str(d.get("repository") or "")
    elif g.kind == "declared-permission":
        g.score, g.reason = declared_score(g.name)
    else:
        g.score, g.reason = 20, f"{g.kind} {g.name}"
    return g


def score_identity(ident: Identity) -> Identity:
    for g in ident.grants:
        score_grant(g)
    ident.blast_radius = max((g.score for g in ident.grants), default=0)
    return ident
