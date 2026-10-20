"""Shared helpers: reading exports, dates, masking and table cells.

The JSON page reader, date parser and masking helpers are adapted from the scripts in
https://github.com/basitalisandhu/agent-identity-governance-skills (nhi_inventory.py and
entra_agent_review.py, MIT licence, same author).
"""

from __future__ import annotations

import csv
import json
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
NO_VALUE = {"n/a", "no_information", "not_supported", "none", "null", "never"}


class InputError(Exception):
    """Bad input: the command exits with code 2."""


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise InputError(f"{path.name}: cannot read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"{path.name}: not valid JSON: {exc}") from exc


def load_csv(path: Path) -> list[dict[str, str]]:
    try:
        with path.open(encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.DictReader(fh))
    except (OSError, csv.Error, UnicodeDecodeError) as exc:
        raise InputError(f"{path.name}: cannot read: {exc}") from exc
    return [{(k or "").strip().lower(): (v or "").strip() for k, v in r.items() if k} for r in rows]


def items(data, *keys: str) -> list[dict]:
    """Rows from a Graph page ({"value": [...]}), a list of pages, a bare list, or an object holding one of keys."""
    names = ("value", *keys)
    if isinstance(data, dict):
        for k in names:
            if isinstance(data.get(k), list):
                return [x for x in data[k] if isinstance(x, dict)]
        return []
    out: list[dict] = []
    if isinstance(data, list):
        for x in data:
            if isinstance(x, list) or (
                isinstance(x, dict) and any(isinstance(x.get(k), list) for k in names)
            ):  # gh api --paginate --slurp gives a list of pages
                out += items(x, *keys)
            elif isinstance(x, dict):
                out.append(x)
    return out


def parse_dt(value) -> datetime | None:
    """ISO 8601 text (Z, offset or date only) or epoch seconds or milliseconds, as an aware UTC datetime."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(value / 1000 if abs(value) > 10**11 else value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):  # out of range or NaN: treat as no date
            return None
    text = str(value).strip()
    if text.lower() in NO_VALUE:
        return None
    text = re.sub(r"(\.\d{6})\d+", r"\1", text.replace("Z", "+00:00").replace("z", "+00:00"))
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        try:
            dt = datetime.combine(date.fromisoformat(text[:10]), datetime.min.time())
        except ValueError:
            return None
    try:
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    except OverflowError:  # an offset that moves the date outside years 1 to 9999
        return None


def iso(dt: datetime | None) -> str | None:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def as_of(value: str | None) -> datetime:
    """The end of the given day (UTC), or the end of today."""
    try:
        day = date.fromisoformat(value) if value else datetime.now(timezone.utc).date()
    except ValueError as exc:
        raise InputError(f"--as-of {value!r} is not YYYY-MM-DD") from exc
    return datetime.combine(day, datetime.max.time()).replace(microsecond=0, tzinfo=timezone.utc)


def days_between(earlier: str | None, later: datetime) -> int | None:
    dt = parse_dt(earlier)
    return (later - dt).days if dt else None


def mask(value) -> str:
    """Show only the last four characters of a key id."""
    text = str(value or "").strip()
    return "****" + text[-4:] if text else "****"


def cell(value) -> str:
    """A Markdown table cell: pipes escaped, line breaks removed, '-' for nothing."""
    text = str(value if value not in (None, "", []) else "-")
    return text.replace("|", "\\|").replace("\r\n", " ").replace("\n", " ").replace("\r", " ")


def tag_owner(tags) -> str:
    """An owner from AWS tags ([{"Key": "owner", ...}]) or Entra tags (["owner:team@example.com"])."""
    for t in tags or []:
        if isinstance(t, dict) and str(t.get("Key", "")).lower() in {"owner", "owner-email", "owneremail"}:
            return str(t.get("Value", "")).strip()
        if isinstance(t, str):
            m = re.match(r"(?i)^owner\s*[:=]\s*(.+)$", t)
            if m:
                return m.group(1).strip()
    return ""


def tag_values(tags) -> list[str]:
    out = []
    for t in tags or []:
        if isinstance(t, dict):
            out.append(f"{t.get('Key', '')}={t.get('Value', '')}")
        elif isinstance(t, str):
            out.append(t)
    return out


def write_text(text: str, out: str | None) -> None:
    if out:
        Path(out).write_text(text, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text)
