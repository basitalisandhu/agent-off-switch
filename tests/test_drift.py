import json

from conftest import AS_OF, ROOT, build, entra_sp, write_json

from agent_off_switch import cli, drift, inventory

BASELINE = ROOT / "examples" / "drift" / "baseline.json"
ACCEPT = ROOT / "examples" / "drift" / "accepted.txt"


def test_same_inventory_has_no_changes(demo_inv):
    changes = drift.compare(demo_inv, demo_inv)
    assert changes == [] and drift.unreviewed(changes) == []


def test_example_baseline_shows_new_identity_grant_and_owner_lost(demo_inv):
    old = inventory.from_json(BASELINE)
    changes = drift.compare(old, demo_inv, drift.load_accepted(ACCEPT))
    kinds = {(c.kind, c.identity) for c in drift.unreviewed(changes)}
    assert kinds == {
        ("new-identity", "github-app:repo-autopilot"),
        ("new-grant", "aws-role:coding-agent-runner"),
        ("owner-lost", "entra:aaaaaaaa-0000-4000-8000-000000000001"),
    }
    assert any(c.identity == "github-app:docs-preview-bot" and c.reviewed for c in changes)


def test_accepting_every_key_clears_the_gate(demo_inv, tmp_path):
    old = inventory.from_json(BASELINE)
    keys = [c.key for c in drift.compare(old, demo_inv)]
    accept = tmp_path / "ok.txt"
    accept.write_text("# reviewed\n" + "\n".join(keys) + "\n", encoding="utf-8")
    assert drift.unreviewed(drift.compare(old, demo_inv, drift.load_accepted(accept))) == []


def test_removals_and_owner_changes_do_not_gate(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    write_json(
        a,
        "entra-service-principals.json",
        {"value": [entra_sp(1, "x", tags=["owner:one@example.com"]), entra_sp(2, "y")]},
    )
    write_json(b, "entra-service-principals.json", {"value": [entra_sp(1, "x", tags=["owner:two@example.com"])]})
    changes = drift.compare(build(a), build(b))
    assert {c.kind for c in changes} == {"owner-changed", "removed-identity"}
    assert drift.unreviewed(changes) == []


def test_owner_lost_gates(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    write_json(a, "entra-service-principals.json", {"value": [entra_sp(1, "x", tags=["owner:one@example.com"])]})
    write_json(b, "entra-service-principals.json", {"value": [entra_sp(1, "x")]})
    assert [c.kind for c in drift.unreviewed(drift.compare(build(a), build(b)))] == ["owner-lost"]


def test_cli_drift_exit_codes(demo, tmp_path, capsys):
    assert cli.main(["drift", str(BASELINE), str(demo), "--as-of", AS_OF, "--accept", str(ACCEPT)]) == 1
    out = capsys.readouterr().out
    assert "3 not reviewed" in out and "github-app:repo-autopilot" in out
    same = tmp_path / "same.json"
    cli.main(["inventory", str(demo), "--as-of", AS_OF, "--format", "json", "--out", str(same)])
    assert cli.main(["drift", str(same), str(demo), "--as-of", AS_OF]) == 0


def test_cli_drift_json_and_bad_input(demo, tmp_path, capsys):
    assert cli.main(["drift", str(BASELINE), str(demo), "--as-of", AS_OF, "--format", "json"]) == 1
    assert json.loads(capsys.readouterr().out)["unreviewed"] == 4
    assert cli.main(["drift", str(tmp_path / "missing.json"), str(demo)]) == 2
    assert cli.main(["drift", str(BASELINE), str(demo), "--accept", str(tmp_path / "nope.txt")]) == 2
