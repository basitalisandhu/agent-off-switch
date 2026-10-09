"""Findings ranked by blast radius, each with its fix, as Markdown, JSON or SARIF 2.1.0."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from . import __version__
from .inventory import Inventory
from .model import Identity

LEVELS = ("none", "note", "warning", "error")


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    title: str
    help: str


RULES = {
    r.name: r
    for r in (
        Rule(
            "AOS001",
            "admin-role",
            "Agent identity holds a directory admin role",
            "An admin role lets the identity change the tenant itself. Remove the role assignment; if the agent "
            "needs one action, grant the narrowest role scoped to an administrative unit, through PIM when possible.",
        ),
        Rule(
            "AOS002",
            "tenant-wide-application-permission",
            "Tenant-wide Microsoft Graph application permission",
            "An application permission works for every mailbox, site or user in the tenant without a signed-in "
            "user. Remove it, use a delegated permission, or scope it (Exchange RBAC for Applications for mail and "
            "calendars, Sites.Selected for SharePoint).",
        ),
        Rule(
            "AOS003",
            "wildcard-iam",
            "IAM policy allows * actions or resources",
            "Replace the policy with the actions and resource ARNs the agent uses (IAM Access Analyzer can "
            "generate one from CloudTrail), and add a permissions boundary to the role.",
        ),
        Rule(
            "AOS004",
            "broad-github-app",
            "GitHub App with admin or write on many repositories",
            "Reduce the installation to the repositories it needs (Only select repositories) and drop "
            "administration and other write permissions it does not use.",
        ),
        Rule(
            "AOS005",
            "open-role-trust",
            "IAM role trusts any principal",
            "Restrict the trust policy to the exact principal, with aws:SourceAccount, sts:ExternalId or an OIDC "
            "subject condition.",
        ),
        Rule(
            "AOS006",
            "no-owner",
            "Agent identity has no owner",
            "Name an owner (Entra owner or sponsor, an owner tag in AWS, a row in agents.csv). If nobody claims it "
            "by the review date, switch it off with aos off.",
        ),
        Rule(
            "AOS007",
            "stale-credential",
            "Credential older than the maximum age",
            "Rotate the credential, or move to a credential with no secret: a managed identity, workload identity "
            "federation, an IAM role with OIDC, or a GitHub App token.",
        ),
        Rule(
            "AOS008",
            "unused-identity",
            "Agent identity not used within the unused window",
            "Confirm with the owner; if nobody needs it, switch it off with aos off and delete it after the "
            "retention period.",
        ),
        Rule(
            "AOS009",
            "expired-credential",
            "Expired credential still attached",
            "Delete the expired credential so it cannot be confused with a live one.",
        ),
        Rule(
            "AOS010",
            "broad-delegated-permission",
            "High-risk delegated permission granted for all users",
            "Remove the tenant-wide consent and let users consent one by one, or require admin approval per user.",
        ),
        Rule(
            "AOS011",
            "read-write-deploy-key",
            "Deploy key can push",
            "Make the deploy key read-only, or replace it with a GitHub App installed on that one repository.",
        ),
        Rule(
            "AOS012",
            "broad-declared-permission",
            "Register declares admin or wildcard access",
            "Narrow the scopes at the system that issued the key or token, and record the narrower set in agents.csv.",
        ),
    )
}

GRANT_RULES = {
    "directory-role": ("admin-role", 85),
    "application-permission": ("tenant-wide-application-permission", 75),
    "managed-policy": ("wildcard-iam", 75),
    "inline-policy": ("wildcard-iam", 75),
    "group": ("wildcard-iam", 75),
    "app-permission": ("broad-github-app", 70),
    "delegated-permission": ("broad-delegated-permission", 50),
    "repository-access": ("read-write-deploy-key", 50),
    "declared-permission": ("broad-declared-permission", 80),
}


@dataclass
class Finding:
    rule: str
    rule_id: str
    identity: str
    name: str
    platform: str
    agent: bool
    score: int
    level: str
    message: str
    fix: str
    evidence: str
    source: str

    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.rule}|{self.identity}|{self.evidence}".encode()).hexdigest()[:32]


def level_for(score: int) -> str:
    if score >= 70:
        return "error"
    if score >= 40:
        return "warning"
    return "note"


def _finding(rule: str, ident: Identity, score: int, message: str, evidence: str) -> Finding:
    r = RULES[rule]
    return Finding(
        rule=rule,
        rule_id=r.id,
        identity=ident.id,
        name=ident.name,
        platform=ident.platform,
        agent=ident.agent,
        score=score,
        level=level_for(score),
        message=message,
        fix=r.help,
        evidence=evidence,
        source=ident.sources[0] if ident.sources else "",
    )


def findings_for(ident: Identity, inv: Inventory) -> list[Finding]:
    out: list[Finding] = []
    who = f"{ident.name} ({ident.id})"
    matched: dict[str, list] = {}
    for g in ident.grants:
        rule, threshold = GRANT_RULES.get(g.kind, ("", 101))
        if rule and g.score >= threshold:
            matched.setdefault(rule, []).append(g)
    for rule, grants in matched.items():
        grants.sort(key=lambda g: (-g.score, g.key()))
        top = grants[0]
        more = f" Also: {'; '.join(g.reason for g in grants[1:])}." if len(grants) > 1 else ""
        evidence = ", ".join(g.key() for g in grants)
        out.append(_finding(rule, ident, top.score, f"{who}: {top.reason}.{more}", evidence))
    for t in ident.trust:
        if t.split(": ", 1)[-1].strip() == "*":
            out.append(_finding("open-role-trust", ident, 90, f"{who}: the trust policy allows {t}.", t))
    if "no-owner" in ident.flags:
        what = "agent identity" if ident.agent else "identity"
        reach = f"; its widest grant scores {ident.blast_radius}" if ident.grants else ""
        out.append(
            _finding(
                "no-owner",
                ident,
                max(30, ident.blast_radius),
                f"{who}: {what} with no owner in any export or the register{reach}.",
                "owners",
            )
        )
    for c in ident.credentials:
        if c.expired:
            out.append(
                _finding(
                    "expired-credential", ident, 15, f"{who}: {c.ref()} expired on {str(c.expires)[:10]}.", c.ref()
                )
            )
        elif (
            c.kind != "federated"
            and str(c.status).lower() != "inactive"
            and c.age_days is not None
            and c.age_days > inv.max_credential_age
        ):
            out.append(
                _finding(
                    "stale-credential",
                    ident,
                    max(30, ident.blast_radius - 10),
                    f"{who}: {c.ref()} is {c.age_days} days old (maximum {inv.max_credential_age}).",
                    c.ref(),
                )
            )
    if {"unused", "never-used"} & set(ident.flags):
        text = (
            f"last used {ident.days_since_use} days ago"
            if ident.days_since_use is not None
            else "never used in the activity export"
        )
        out.append(
            _finding(
                "unused-identity",
                ident,
                max(20, ident.blast_radius - 20),
                f"{who}: {text} (window {inv.unused_days} days).",
                "last_used",
            )
        )
    return out


def review(inv: Inventory) -> list[Finding]:
    found: list[Finding] = []
    for ident in inv.identities:
        if not ident.enabled:
            continue
        found += findings_for(ident, inv)
    return sorted(found, key=lambda f: (-f.score, f.identity, f.rule_id, f.evidence))


def exit_code(found: list[Finding], fail_on: str) -> int:
    if fail_on == "none":
        return 0
    floor = LEVELS.index(fail_on)
    return 1 if any(LEVELS.index(f.level) >= floor for f in found) else 0


# ---- rendering -----------------------------------------------------------------------------------------------------


def to_markdown(inv: Inventory, found: list[Finding], folder_arg: str = "EXPORTS") -> str:
    s = inv.summary()
    errors = sum(1 for f in found if f.level == "error")
    lines = [
        "# Agent access review",
        "",
        f"As of {inv.as_of}: {s['identities']} non-human identities, {s['agents']} look like agents. "
        f"{len(found)} findings ({errors} error), ranked by blast radius (0 to 100, see docs/scoring.md).",
        "",
    ]
    orphans = [i for i in inv.identities if i.agent and "no-owner" in i.flags and i.enabled]
    if orphans:
        orphans.sort(key=lambda i: (-i.blast_radius, i.id))
        lines += [f"## {len(orphans)} agent identities nobody owns", ""]
        for i in orphans:
            top = max(i.grants, key=lambda g: g.score, default=None)
            reach = f"{top.reason}" if top else "no grants in the export"
            lines.append(f"- **{i.name}** `{i.id}` (blast radius {i.blast_radius}): {reach}")
            lines.append(f"  - switch off: `aos off {folder_arg} {i.id}`")
        lines.append("")
    lines += [
        "## Findings",
        "",
        "| # | Score | Level | Rule | Identity | Finding | Fix |",
        "|---|---|---|---|---|---|---|",
    ]
    for n, f in enumerate(found, start=1):
        lines.append(
            f"| {n} | {f.score} | {f.level} | {f.rule_id} {f.rule} | `{f.identity}` | {_cell(f.message)} "
            f"| {_cell(f.fix)} |"
        )
    if not found:
        lines.append("| - | - | - | - | - | No findings. | - |")
    if inv.notes:
        lines += ["", "## Notes", ""] + [f"- {n}" for n in inv.notes]
    return "\n".join(lines) + "\n"


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def to_json(inv: Inventory, found: list[Finding]) -> str:
    doc = {
        "tool": "agent-off-switch",
        "version": __version__,
        "as_of": inv.as_of,
        "summary": inv.summary() | {"findings": len(found)},
        "findings": [asdict(f) | {"fingerprint": f.fingerprint()} for f in found],
    }
    return json.dumps(doc, indent=2) + "\n"


def _artifact_uri(folder: str, source: str, base: str | None, pathmod=os.path) -> str:
    """A relative, forward-slash URI for the export file, so GitHub code scanning can place the result.

    pathmod is os.path at run time; tests pass ntpath or posixpath to check Windows and POSIX behaviour.
    """
    path = pathmod.join(folder, source) if source else folder
    try:
        rel = pathmod.relpath(path, base or os.getcwd())
    except ValueError:  # another drive on Windows: keep the absolute path as a file URI
        return "file:///" + path.replace("\\", "/").lstrip("/")
    return rel.replace("\\", "/")


def _line_of(folder: str, source: str, ident: Identity) -> int:
    path = Path(folder) / source
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeDecodeError):
        return 1
    needles = [str(v) for k, v in ident.refs.items() if k in ("app_id", "role_name", "user_name", "installation_id")]
    needles += [ident.name]
    for needle in needles:
        if not needle:
            continue
        for n, line in enumerate(lines, start=1):
            if needle in line:
                return n
    return 1


def to_sarif(inv: Inventory, found: list[Finding], base: str | None = None) -> str:
    used = sorted({f.rule for f in found}, key=lambda r: RULES[r].id)
    rule_index = {name: n for n, name in enumerate(used)}
    rules = []
    for name in used:
        r = RULES[name]
        top = max((f.score for f in found if f.rule == name), default=0)
        rules.append(
            {
                "id": r.id,
                "name": "".join(p.capitalize() for p in r.name.split("-")),
                "shortDescription": {"text": r.title},
                "fullDescription": {"text": r.help},
                "help": {"text": r.help, "markdown": r.help},
                "helpUri": "https://github.com/basitalisandhu/agent-off-switch/blob/main/docs/scoring.md",
                "defaultConfiguration": {"level": level_for(top)},
                "properties": {"tags": ["security", "identity", "ai-agents"], "security-severity": f"{top / 10:.1f}"},
            }
        )
    by_id = {i.id: i for i in inv.identities}
    results = []
    for f in found:
        ident = by_id[f.identity]
        results.append(
            {
                "ruleId": f.rule_id,
                "ruleIndex": rule_index[f.rule],
                "level": f.level,
                "message": {"text": f"{f.message} Fix: {f.fix}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _artifact_uri(inv.folder, f.source, base)},
                            "region": {"startLine": _line_of(inv.folder, f.source, ident)},
                        },
                        "logicalLocations": [{"name": f.identity, "kind": "member"}],
                    }
                ],
                "partialFingerprints": {"aosFinding/v1": f.fingerprint()},
                "properties": {"blastRadius": f.score, "identity": f.identity, "evidence": f.evidence},
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-off-switch",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/basitalisandhu/agent-off-switch",
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": "agent-off-switch/"},
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2) + "\n"
