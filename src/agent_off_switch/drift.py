"""Compare two inventories: new identities, new grants and lost ownership, for a CI gate."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from .inventory import Inventory
from .util import InputError, cell

GATING = ("new-identity", "new-grant", "owner-lost")


@dataclass
class Change:
    kind: str  # new-identity, new-grant, owner-lost, removed-identity, removed-grant, owner-changed
    identity: str
    detail: str
    key: str
    score: int = 0
    reviewed: bool = False


def load_accepted(path: Path | None) -> set[str]:
    """Reviewed changes: one key per line (an identity id, or 'identity id|change'); '#' starts a comment."""
    if path is None:
        return set()
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise InputError(f"{path.name}: cannot read: {exc}") from exc
    out = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(line)
    return out


def compare(old: Inventory, new: Inventory, accepted: set[str] | None = None) -> list[Change]:
    accepted = accepted or set()
    before = {i.id: i for i in old.identities}
    after = {i.id: i for i in new.identities}
    changes: list[Change] = []
    for ident_id in sorted(after):
        ident = after[ident_id]
        if ident_id not in before:
            owners = ", ".join(ident.owners) or "no owner"
            changes.append(
                Change(
                    "new-identity",
                    ident_id,
                    f"{ident.name} ({ident.type}, {owners}, blast radius {ident.blast_radius})",
                    ident_id,
                    ident.blast_radius,
                )
            )
            continue
        old_ident = before[ident_id]
        old_grants = {g.key() for g in old_ident.grants}
        for g in ident.grants:
            if g.key() not in old_grants:
                changes.append(
                    Change("new-grant", ident_id, f"{g.name} (score {g.score})", f"{ident_id}|{g.key()}", g.score)
                )
        new_grants = {g.key() for g in ident.grants}
        for g in old_ident.grants:
            if g.key() not in new_grants:
                changes.append(Change("removed-grant", ident_id, g.name, f"{ident_id}|removed|{g.key()}"))
        if old_ident.owners and not ident.owners:
            changes.append(
                Change(
                    "owner-lost",
                    ident_id,
                    f"was owned by {', '.join(old_ident.owners)}; now no owner",
                    f"{ident_id}|owner-lost",
                    ident.blast_radius,
                )
            )
        elif set(old_ident.owners) != set(ident.owners) and ident.owners:
            changes.append(
                Change(
                    "owner-changed",
                    ident_id,
                    f"{', '.join(old_ident.owners) or 'none'} -> {', '.join(ident.owners)}",
                    f"{ident_id}|owner-changed",
                )
            )
    for ident_id in sorted(set(before) - set(after)):
        changes.append(Change("removed-identity", ident_id, before[ident_id].name, f"{ident_id}|removed"))
    for c in changes:
        c.reviewed = c.kind not in GATING or c.key in accepted or c.identity in accepted
    return changes


def unreviewed(changes: list[Change]) -> list[Change]:
    return [c for c in changes if c.kind in GATING and not c.reviewed]


def to_markdown(old: Inventory, new: Inventory, changes: list[Change]) -> str:
    open_ = unreviewed(changes)
    lines = [
        "# Agent identity drift",
        "",
        f"From {old.as_of or 'unknown'} ({len(old.identities)} identities) to {new.as_of or 'unknown'} "
        f"({len(new.identities)} identities): {len(changes)} changes, {len(open_)} not reviewed.",
        "",
        "| Change | Identity | Detail | Reviewed |",
        "|---|---|---|---|",
    ]
    order = {k: n for n, k in enumerate((*GATING, "owner-changed", "removed-grant", "removed-identity"))}
    for c in sorted(changes, key=lambda c: (order.get(c.kind, 9), -c.score, c.identity)):
        mark = "yes" if c.reviewed else "**no**"
        if c.kind not in GATING:
            mark = "n/a"
        lines.append(f"| {c.kind} | `{cell(c.identity)}` | {cell(c.detail)} | {mark} |")
    if not changes:
        lines.append("| - | - | No changes. | - |")
    if open_:
        lines += [
            "",
            "To accept a change after review, add its key to the accept file (one per line):",
            "",
            "```",
            *[c.key for c in open_],
            "```",
        ]
    return "\n".join(lines) + "\n"


def to_json(old: Inventory, new: Inventory, changes: list[Change]) -> str:
    return (
        json.dumps(
            {
                "from": old.as_of,
                "to": new.as_of,
                "changes": [asdict(c) for c in changes],
                "unreviewed": len(unreviewed(changes)),
            },
            indent=2,
        )
        + "\n"
    )
