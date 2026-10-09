import json
import ntpath
import posixpath

from conftest import AS_OF

from agent_off_switch import cli, review

LEVELS = {"none", "note", "warning", "error"}


def sarif_for(demo_inv):
    return json.loads(review.to_sarif(demo_inv, review.review(demo_inv)))


def test_sarif_top_level_structure(demo_inv):
    doc = sarif_for(demo_inv)
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    assert len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "agent-off-switch" and driver["rules"]


def test_sarif_results_reference_rules_consistently(demo_inv):
    run = sarif_for(demo_inv)["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids))
    for res in run["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["level"] in LEVELS
        assert res["message"]["text"]
        loc = res["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] >= 1
        assert "\\" not in loc["artifactLocation"]["uri"]


def test_sarif_rules_carry_security_severity(demo_inv):
    for rule in sarif_for(demo_inv)["runs"][0]["tool"]["driver"]["rules"]:
        sev = float(rule["properties"]["security-severity"])
        assert 0 <= sev <= 10
        assert rule["shortDescription"]["text"] and rule["help"]["text"]


def test_sarif_points_at_the_line_holding_the_identity(demo_inv, demo):
    run = sarif_for(demo_inv)["runs"][0]
    res = next(r for r in run["results"] if r["properties"]["identity"] == "aws-role:coding-agent-runner")
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"].endswith("aws-authorization-details.json")
    lines = (demo / "aws-authorization-details.json").read_text(encoding="utf-8").splitlines()
    assert "coding-agent-runner" in lines[loc["region"]["startLine"] - 1]


def test_windows_paths_become_relative_forward_slash_uris():
    uri = review._artifact_uri(r"C:\work\repo\exports", "entra-applications.json", r"C:\work\repo", pathmod=ntpath)
    assert uri == "exports/entra-applications.json"
    other = review._artifact_uri(r"D:\exports", "a.json", r"C:\work", pathmod=ntpath)
    assert other == "file:///D:/exports/a.json"
    assert review._artifact_uri("/w/repo/x", "a.json", "/w/repo", pathmod=posixpath) == "x/a.json"


def test_cli_writes_parseable_sarif(demo, tmp_path):
    out = tmp_path / "aos.sarif"
    assert cli.main(["review", str(demo), "--as-of", AS_OF, "--format", "sarif", "--out", str(out)]) == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["runs"][0]["results"]


def test_empty_review_is_valid_sarif(tmp_path):
    (tmp_path / "agents.csv").write_text("id,name,owner\nx,x,o@example.com\n", encoding="utf-8")
    out = tmp_path / "s.sarif"
    assert cli.main(["review", str(tmp_path), "--format", "sarif", "--out", str(out)]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["runs"][0]["results"] == [] and doc["runs"][0]["tool"]["driver"]["rules"] == []
