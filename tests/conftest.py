"""Shared helpers. Inputs are built inside each test; the only fixture files on disk are examples/."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_off_switch import inventory
from agent_off_switch.util import as_of

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "demo-tenant"
AS_OF = "2026-10-09"
GRAPH = "dddddddd-0000-4000-8000-000000000001"


def write_json(folder: Path, name: str, data) -> Path:
    path = folder / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def write_text(folder: Path, name: str, text: str) -> Path:
    path = folder / name
    path.write_text(text, encoding="utf-8")
    return path


def build(folder: Path, day: str = AS_OF, **kw) -> inventory.Inventory:
    return inventory.build(folder, as_of(day), **kw)


def guid(n: int, prefix: str = "aaaaaaaa") -> str:
    return f"{prefix}-0000-4000-8000-{n:012d}"


def entra_app(n: int, name: str, owners=(), secrets=(), tags=()) -> dict:
    return {
        "id": guid(n, "bbbbbbbb"),
        "appId": guid(n),
        "displayName": name,
        "createdDateTime": "2026-01-01T00:00:00Z",
        "owners": [{"userPrincipalName": o} for o in owners],
        "tags": list(tags),
        "passwordCredentials": [
            {"keyId": guid(100 + i, "ffffffff"), "startDateTime": start, "endDateTime": end}
            for i, (start, end) in enumerate(secrets)
        ],
        "keyCredentials": [],
    }


def entra_sp(n: int, name: str, sp_type: str = "Application", **extra) -> dict:
    return {
        "id": guid(n, "cccccccc"),
        "appId": guid(n),
        "displayName": name,
        "servicePrincipalType": sp_type,
        "accountEnabled": True,
        "appOwnerOrganizationId": "00000000-0000-4000-8000-000000000000",
        "owners": [],
        **extra,
    }


@pytest.fixture
def demo() -> Path:
    return DEMO


@pytest.fixture
def demo_inv() -> inventory.Inventory:
    return build(DEMO)
