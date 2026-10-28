"""Scaling test: review, inventory and off on the demo tenant copied 10 and 100 times.

Each copy gets new ids and names (GUIDs and name fields rewritten the same way in every file, so the cross
references between files still hold). The 100x tenant must not take much more than 10 times the 10x one; a
quadratic loop shows up as roughly 100 times.
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import shutil
import time
import uuid
from pathlib import Path

from agent_off_switch import cli

DEMO = Path(__file__).resolve().parent.parent / "examples" / "demo-tenant"
GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
NAME_KEYS = {
    "displayName",
    "appDisplayName",
    "principalDisplayName",
    "RoleName",
    "UserName",
    "GroupName",
    "PolicyName",
    "RoleId",
    "UserId",
    "Arn",
    "AccessKeyId",
    "slug",
    "app_slug",
    "name",
    "title",
    "login",
    "key",
}


def _rename(node, copy: int, key: str | None = None):
    if isinstance(node, dict):
        return {k: _rename(v, copy, k) for k, v in node.items()}
    if isinstance(node, list):
        return [_rename(v, copy, key) for v in node]
    if isinstance(node, str):
        if GUID.match(node):
            return str(uuid.uuid5(uuid.NAMESPACE_OID, f"{node}/{copy}"))
        if key in NAME_KEYS and node:
            return f"{node}-c{copy}"
        if key in {"id", "app_id", "installation_id"} and node:
            return f"{node}-c{copy}"
    if isinstance(node, int) and not isinstance(node, bool) and key in {"id", "app_id"}:
        return node * 100_000 + copy
    return node


def _concat(copies: list):
    first = copies[0]
    if isinstance(first, list):
        return [row for c in copies for row in c]
    out = {}
    for k, v in first.items():
        if isinstance(v, list):
            out[k] = [row for c in copies for row in c[k]]
        else:
            out[k] = v
    return out


def make_tenant(dest: Path, times: int) -> Path:
    dest.mkdir(parents=True)
    for path in DEMO.iterdir():
        if path.suffix != ".json":
            shutil.copy(path, dest / path.name)
            continue
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
        copies = [doc] + [_rename(doc, k) for k in range(1, times)]
        (dest / path.name).write_text(json.dumps(_concat(copies)), encoding="utf-8")
    return dest


def _run(folder: Path) -> float:
    start = time.perf_counter()
    for argv in (
        ["review", str(folder), "--as-of", "2026-10-09", "--fail-on", "none"],
        ["inventory", str(folder), "--format", "json"],
        ["off", str(folder), "aws-role:coding-agent-runner"],
    ):
        sink = io.StringIO()
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            assert cli.main(argv) in (0, 1), sink.getvalue()[-500:]
    return time.perf_counter() - start


def test_identity_count_scales(tmp_path):
    folder = make_tenant(tmp_path / "x10", 10)
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink):
        assert cli.main(["inventory", str(folder), "--format", "json"]) == 0
    assert (
        len(json.loads(sink.getvalue())["identities"]) > 100
    )  # 13 in the demo; a few GitHub records share ids across copies


def test_runtime_grows_linearly(tmp_path):
    small = _run(make_tenant(tmp_path / "x10", 10))
    big = _run(make_tenant(tmp_path / "x100", 100))
    # Linear growth gives about 10x; allow generous noise for shared CI runners.
    assert big < max(small, 0.05) * 30, f"10x copies: {small:.2f}s, 100x copies: {big:.2f}s"
