import json

from conftest import AS_OF, build, write_json

from agent_off_switch import cli, review


def test_demo_tells_the_four_orphans_story(demo_inv):
    found = review.review(demo_inv)
    text = review.to_markdown(demo_inv, found, "examples/demo-tenant")
    assert "## 4 agent identities nobody owns" in text
    orphans = {f.identity for f in found if f.rule == "no-owner"}
    assert orphans == {
        "aws-role:coding-agent-runner",
        "github-app:repo-autopilot",
        "entra:aaaaaaaa-0000-4000-8000-000000000001",
        "aws-user:support-bot",
    }


def test_findings_ranked_by_score(demo_inv):
    found = review.review(demo_inv)
    scores = [f.score for f in found]
    assert scores == sorted(scores, reverse=True)
    assert found[0].identity == "aws-role:coding-agent-runner" and found[0].rule == "wildcard-iam"


def test_demo_has_each_headline_finding(demo_inv):
    rules = {(f.rule, f.identity) for f in review.review(demo_inv)}
    assert ("tenant-wide-application-permission", "entra:aaaaaaaa-0000-4000-8000-000000000001") in rules
    assert ("broad-github-app", "github-app:repo-autopilot") in rules
    assert ("admin-role", "entra:aaaaaaaa-0000-4000-8000-000000000005") in rules


def test_every_finding_has_a_fix(demo_inv):
    assert all(f.fix for f in review.review(demo_inv))


def test_grant_findings_are_grouped_per_identity(demo_inv):
    found = [f for f in review.review(demo_inv) if f.rule == "broad-github-app"]
    assert len(found) == 1 and "Also:" in found[0].message


def test_open_trust_is_found(tmp_path):
    write_json(
        tmp_path,
        "aws-authorization-details.json",
        {
            "RoleDetailList": [
                {
                    "RoleName": "r",
                    "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}}]},
                }
            ]
        },
    )
    found = review.review(build(tmp_path))
    assert any(f.rule == "open-role-trust" and f.score == 90 for f in found)


def test_disabled_identities_are_not_reviewed(tmp_path):
    write_json(
        tmp_path,
        "github-installations.json",
        [
            {
                "id": 1,
                "app_slug": "x",
                "suspended_at": "2026-01-01T00:00:00Z",
                "permissions": {"administration": "write"},
                "repository_selection": "all",
            }
        ],
    )
    assert review.review(build(tmp_path)) == []


def test_exit_code_levels(demo_inv):
    found = review.review(demo_inv)
    assert review.exit_code(found, "error") == 1
    assert review.exit_code(found, "none") == 0
    assert review.exit_code([f for f in found if f.level == "note"], "warning") == 0
    assert review.exit_code([], "note") == 0


def test_cli_review_json(demo, capsys):
    assert cli.main(["review", str(demo), "--as-of", AS_OF, "--format", "json", "--fail-on", "none"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["agents_no_owner"] == 4
    assert all(len(f["fingerprint"]) == 32 for f in data["findings"])


def test_cli_review_accepts_saved_inventory(demo, tmp_path):
    inv = tmp_path / "inv.json"
    assert cli.main(["inventory", str(demo), "--as-of", AS_OF, "--format", "json", "--out", str(inv)]) == 0
    assert cli.main(["review", str(inv), "--fail-on", "error", "--out", str(tmp_path / "r.md")]) == 1
    assert "nobody owns" in (tmp_path / "r.md").read_text(encoding="utf-8")
