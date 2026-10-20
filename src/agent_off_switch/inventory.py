"""Build the inventory from an export folder, flag it, and render it as Markdown, CSV or JSON."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from . import __version__
from .exports import FILES, REGISTER_NAMES, read_aws, read_entra, read_github, read_register
from .model import Identity
from .scoring import score_identity
from .util import InputError, cell, days_between, load_json, parse_dt

FLAG_TEXT = {
    "no-owner": "no owner in any export or the register",
    "unused": "not used within the unused window",
    "never-used": "activity is recorded for its platform and it has never been used",
    "stale-credential": "an active credential is older than the maximum credential age",
    "expired-credential": "a credential has passed its end date and is still attached",
    "disabled": "switched off (informational)",
}


@dataclass
class Inventory:
    as_of: str
    unused_days: int
    max_credential_age: int
    sources: list[str]
    identities: list[Identity]
    notes: list[str] = field(default_factory=list)
    folder: str = ""

    def get(self, ident_id: str) -> Identity | None:
        return next((i for i in self.identities if i.id == ident_id), None)

    def summary(self) -> dict:
        by_platform: dict[str, int] = {}
        for i in self.identities:
            by_platform[i.platform] = by_platform.get(i.platform, 0) + 1
        return {
            "identities": len(self.identities),
            "agents": sum(1 for i in self.identities if i.agent),
            "no_owner": sum(1 for i in self.identities if "no-owner" in i.flags),
            "agents_no_owner": sum(1 for i in self.identities if i.agent and "no-owner" in i.flags),
            "unused": sum(1 for i in self.identities if {"unused", "never-used"} & set(i.flags)),
            "stale_credentials": sum(1 for i in self.identities if "stale-credential" in i.flags),
            "by_platform": by_platform,
        }

    def to_dict(self) -> dict:
        return {
            "tool": "agent-off-switch",
            "version": __version__,
            "as_of": self.as_of,
            "unused_days": self.unused_days,
            "max_credential_age": self.max_credential_age,
            "sources": self.sources,
            "summary": self.summary(),
            "identities": [i.to_dict() for i in self.identities],
            "notes": self.notes,
        }


def evaluate(ident: Identity, as_of: datetime, unused_days: int, max_age: int) -> None:
    flags: list[str] = []
    for c in ident.credentials:
        c.age_days = days_between(c.created, as_of)
        end = parse_dt(c.expires)
        c.expired = bool(end and end < as_of)
    if not ident.owners:
        flags.append("no-owner")
    last = parse_dt(ident.last_used)
    created = parse_dt(ident.created)
    ident.days_since_use = (as_of - last).days if last else None
    if last and (as_of - last).days > unused_days:
        flags.append("unused")
    elif ident.activity_recorded and not last and (not created or (as_of - created).days > unused_days):
        flags.append("never-used")
    active = [c for c in ident.credentials if c.kind != "federated" and str(c.status).lower() != "inactive"]
    if any(c.age_days is not None and c.age_days > max_age and not c.expired for c in active):
        flags.append("stale-credential")
    if any(c.expired for c in ident.credentials):
        flags.append("expired-credential")
    if not ident.enabled:
        flags.append("disabled")
    ident.flags = flags


def _read(platform: str, reader, *args) -> None:
    """Run one export reader; a record of the wrong shape becomes a clear input error instead of a traceback."""
    try:
        reader(*args)
    except (AttributeError, IndexError, KeyError, TypeError) as exc:
        raise InputError(
            f"{platform} exports: a record has an unexpected shape ({type(exc).__name__}: {exc}); "
            "re-export it with the command in docs/exports.md"
        ) from exc


def build(
    folder: Path,
    as_of: datetime,
    unused_days: int = 90,
    max_credential_age: int = 90,
    include_aws_managed_roles: bool = False,
) -> Inventory:
    if not folder.is_dir():
        raise InputError(f"{folder}: not a folder")
    if unused_days < 1 or max_credential_age < 1:
        raise InputError("--unused-days and --max-credential-age must be at least 1")
    known = sorted(p.name for p in folder.iterdir() if p.name in FILES or p.name in REGISTER_NAMES)
    if not known:
        raise InputError(f"{folder}: none of the expected export files is present (see docs/exports.md)")
    inv: dict[str, Identity] = {}
    notes: list[str] = []
    _read("Entra", read_entra, folder, inv, notes)
    _read("AWS", read_aws, folder, inv, notes, include_aws_managed_roles)
    _read("GitHub", read_github, folder, inv)
    _read("register", read_register, folder, inv)
    identities = []
    for key in sorted(inv):
        ident = score_identity(inv[key])
        evaluate(ident, as_of, unused_days, max_credential_age)
        identities.append(ident)
    if any(i.platform == "github" and i.type == "github-app" for i in identities):
        notes.append("GitHub installation exports carry no last-use date: GitHub App activity is not judged")
    return Inventory(
        as_of=as_of.date().isoformat(),
        unused_days=unused_days,
        max_credential_age=max_credential_age,
        sources=known,
        identities=identities,
        notes=notes,
        folder=str(folder),
    )


def from_json(path: Path) -> Inventory:
    data = load_json(path)
    if not isinstance(data, dict) or not isinstance(data.get("identities"), list):
        raise InputError(f"{path.name}: not an inventory written by aos inventory --format json")
    try:
        identities = [Identity.from_dict(d) for d in data["identities"] if isinstance(d, dict)]
    except TypeError as exc:
        raise InputError(f"{path.name}: an identity record has an unexpected shape: {exc}") from exc
    return Inventory(
        as_of=str(data.get("as_of") or ""),
        unused_days=int(data.get("unused_days") or 90),
        max_credential_age=int(data.get("max_credential_age") or 90),
        sources=list(data.get("sources") or []),
        identities=identities,
        notes=list(data.get("notes") or []),
        folder=str(path),
    )


def load(source: Path, as_of: datetime, **kw) -> Inventory:
    """An inventory from an export folder or from a saved inventory JSON file."""
    if source.is_dir():
        return build(source, as_of, **kw)
    if source.is_file():
        return from_json(source)
    raise InputError(f"{source}: no such folder or file")


# ---- rendering -----------------------------------------------------------------------------------------------------


def last_used_text(i: Identity) -> str:
    if i.last_used:
        return i.last_used[:10]
    return "never" if i.activity_recorded else "unknown"


def to_markdown(inv: Inventory) -> str:
    s = inv.summary()
    lines = [
        "# Agent identity inventory",
        "",
        f"As of {inv.as_of}: {s['identities']} non-human identities from {len(inv.sources)} export files, "
        f"{s['agents']} of them look like agents. No owner: {s['no_owner']}. Unused for {inv.unused_days} days "
        f"or never used: {s['unused']}. Credential older than {inv.max_credential_age} days: "
        f"{s['stale_credentials']}.",
        "",
        "| Identity | Platform | Type | Agent | Owner | Last used | Credentials (oldest, days) | Blast radius "
        "| Flags |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for i in sorted(inv.identities, key=lambda x: (-x.blast_radius, x.id)):
        lines.append(
            f"| `{cell(i.id)}` {cell(i.name)} | {i.platform} | {i.type} | {'yes' if i.agent else 'no'} "
            f"| {cell(', '.join(i.owners))} | {last_used_text(i)} | {len(i.credentials)} "
            f"({cell(i.oldest_credential_days())}) | {i.blast_radius} | {cell(', '.join(i.flags))} |"
        )
    if inv.notes:
        lines += ["", "## Notes", ""] + [f"- {n}" for n in inv.notes]
    lines += ["", "Flags: " + "; ".join(f"{k}: {v}" for k, v in FLAG_TEXT.items()) + "."]
    return "\n".join(lines) + "\n"


CSV_COLUMNS = [
    "id",
    "name",
    "platform",
    "type",
    "agent",
    "owners",
    "enabled",
    "created",
    "last_used",
    "days_since_use",
    "credential_count",
    "oldest_credential_days",
    "blast_radius",
    "top_grant",
    "flags",
    "used_by",
]


def to_csv(inv: Inventory) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, lineterminator="\n")
    w.writeheader()
    for i in inv.identities:
        top = max(i.grants, key=lambda g: g.score, default=None)
        w.writerow(
            {
                "id": i.id,
                "name": i.name,
                "platform": i.platform,
                "type": i.type,
                "agent": "yes" if i.agent else "no",
                "owners": "; ".join(i.owners),
                "enabled": "yes" if i.enabled else "no",
                "created": i.created or "",
                "last_used": last_used_text(i),
                "days_since_use": "" if i.days_since_use is None else i.days_since_use,
                "credential_count": len(i.credentials),
                "oldest_credential_days": i.oldest_credential_days() or "",
                "blast_radius": i.blast_radius,
                "top_grant": top.name if top else "",
                "flags": "; ".join(i.flags),
                "used_by": "; ".join(i.used_by),
            }
        )
    return buf.getvalue()


def to_json(inv: Inventory) -> str:
    return json.dumps(inv.to_dict(), indent=2) + "\n"
