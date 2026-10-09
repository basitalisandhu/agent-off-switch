import csv
import io
import json

import pytest
from conftest import AS_OF, build, entra_app, entra_sp, guid, write_json

from agent_off_switch import cli, inventory
from agent_off_switch.util import InputError


def test_demo_inventory_counts(demo_inv):
    s = demo_inv.summary()
    assert s["identities"] == 13
    assert s["agents_no_owner"] == 4
    assert s["by_platform"] == {"aws": 4, "entra": 5, "github": 3, "register": 1}


def test_flags_never_used_and_disabled(tmp_path):
    sp = entra_sp(1, "old")
    sp["accountEnabled"] = False
    write_json(tmp_path, "entra-service-principals.json", {"value": [sp]})
    write_json(tmp_path, "entra-sign-in-activity.json", {"value": []})
    flags = build(tmp_path).get(f"entra:{guid(1)}").flags
    assert "never-used" in flags and "disabled" in flags and "no-owner" in flags


def test_expired_credentials_are_not_stale(tmp_path):
    write_json(
        tmp_path,
        "entra-applications.json",
        {"value": [entra_app(1, "x", owners=["o@example.com"], secrets=[("2025-01-01", "2025-06-01")])]},
    )
    flags = build(tmp_path).get(f"entra:{guid(1)}").flags
    assert flags == ["expired-credential"]


def test_thresholds_are_configurable(tmp_path):
    write_json(
        tmp_path,
        "entra-applications.json",
        {"value": [entra_app(1, "x", owners=["o@example.com"], secrets=[("2026-09-01", "2027-09-01")])]},
    )
    assert build(tmp_path).get(f"entra:{guid(1)}").flags == []
    assert build(tmp_path, max_credential_age=10).get(f"entra:{guid(1)}").flags == ["stale-credential"]


def test_empty_folder_and_missing_folder_are_bad_input(tmp_path):
    with pytest.raises(InputError):
        build(tmp_path)
    with pytest.raises(InputError):
        build(tmp_path / "nope")


def test_csv_output_has_a_row_per_identity(demo_inv):
    rows = list(csv.DictReader(io.StringIO(inventory.to_csv(demo_inv))))
    assert len(rows) == 13
    assert set(rows[0]) == set(inventory.CSV_COLUMNS)


def test_json_round_trip(demo_inv, tmp_path):
    path = tmp_path / "inv.json"
    path.write_text(inventory.to_json(demo_inv), encoding="utf-8")
    again = inventory.from_json(path)
    assert [i.id for i in again.identities] == [i.id for i in demo_inv.identities]
    assert again.get("aws-role:coding-agent-runner").grants[0].score == 100


def test_from_json_rejects_other_json(tmp_path):
    path = write_json(tmp_path, "x.json", {"hello": 1})
    with pytest.raises(InputError):
        inventory.from_json(path)


def test_cli_inventory_formats_and_agents_only(demo, tmp_path, capsys):
    assert cli.main(["inventory", str(demo), "--as-of", AS_OF]) == 0
    assert "# Agent identity inventory" in capsys.readouterr().out
    out = tmp_path / "inv.json"
    assert (
        cli.main(["inventory", str(demo), "--as-of", AS_OF, "--format", "json", "--agents-only", "--out", str(out)])
        == 0
    )
    data = json.loads(out.read_text(encoding="utf-8"))
    assert all(i["agent"] for i in data["identities"]) and len(data["identities"]) == 11


def test_cli_inventory_fail_on_flags(demo):
    assert cli.main(["inventory", str(demo), "--as-of", AS_OF, "--format", "json"]) == 0
    assert cli.main(["inventory", str(demo), "--as-of", AS_OF, "--fail-on-flags", "--format", "json"]) == 1
