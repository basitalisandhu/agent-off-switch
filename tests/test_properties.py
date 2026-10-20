"""Property tests: the parsers and the whole pipeline on malformed exports.

Every command must end with exit code 0, 1 or 2 on any input, never with a traceback. Exit code 2 is the clear
"bad input" error. The pipeline test copies examples/demo-tenant, swaps a few values for values of the wrong type,
and runs review, inventory and off.
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from agent_off_switch import cli  # noqa: E402
from agent_off_switch.util import cell, iso, items, mask, parse_dt, tag_owner, tag_values  # noqa: E402

DEMO = Path(__file__).resolve().parent.parent / "examples" / "demo-tenant"
JSON_FILES = sorted(p.name for p in DEMO.glob("*.json"))

json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats() | st.text(max_size=20),
    lambda inner: st.lists(inner, max_size=4) | st.dictionaries(st.text(max_size=8), inner, max_size=4),
    max_leaves=20,
)
wrong_values = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-(10**20), max_value=10**20)
    | st.floats()
    | st.text(max_size=12)
    | st.builds(list)
    | st.builds(dict)
)


@settings(max_examples=300)
@given(st.one_of(st.text(), st.integers(), st.floats(), st.none(), st.booleans()))
def test_parse_dt_never_raises_and_is_utc(value):
    dt = parse_dt(value)
    assert dt is None or dt.utcoffset().total_seconds() == 0


@settings(max_examples=200)
@given(st.datetimes(timezones=st.just(timezone.utc)))
def test_iso_round_trips(dt: datetime):
    text = iso(dt)
    assert iso(parse_dt(text)) == text


@settings(max_examples=200)
@given(json_values)
def test_items_returns_only_records(data):
    assert all(isinstance(row, dict) for row in items(data, "roles"))


@settings(max_examples=200)
@given(st.text())
def test_mask_shows_at_most_four_characters(value):
    out = mask(value)
    assert out.startswith("****") and len(out) <= 8
    assert out[4:] == value.strip()[-4:]


@settings(max_examples=200)
@given(json_values)
def test_cell_is_one_safe_table_cell(value):
    out = cell(value)
    assert "\n" not in out and "\r" not in out
    assert "|" not in out.replace("\\|", "")


@settings(max_examples=200)
@given(st.lists(json_values, max_size=5))
def test_tag_helpers_accept_any_list(tags):
    assert isinstance(tag_owner(tags), str)
    assert all(isinstance(t, str) for t in tag_values(tags))


def _paths(node, prefix=()):
    yield prefix
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _paths(value, (*prefix, key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _paths(value, (*prefix, index))


@settings(max_examples=60, deadline=None, suppress_health_check=list(HealthCheck), database=None)
@given(st.sampled_from(JSON_FILES), st.data())
def test_malformed_exports_never_crash(name, data):
    doc = json.loads((DEMO / name).read_text(encoding="utf-8-sig"))
    for _ in range(data.draw(st.integers(1, 3))):
        path = data.draw(st.sampled_from([p for p in _paths(doc) if p]))
        node = doc
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = data.draw(wrong_values)
    tmp = Path(tempfile.mkdtemp())
    try:
        folder = tmp / "tenant"
        shutil.copytree(DEMO, folder)
        (folder / name).write_text(json.dumps(doc), encoding="utf-8")
        for argv in (
            ["review", str(folder), "--as-of", "2026-10-09", "--fail-on", "none"],
            ["inventory", str(folder), "--format", "json"],
            ["off", str(folder), "mail-triage-agent"],
        ):
            sink = io.StringIO()
            with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                assert cli.main(argv) in (0, 1, 2)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
