import json
import os
import subprocess

import pytest
from conftest import AS_OF

from agent_off_switch import cli, runbook
from agent_off_switch.runbook import PHASES

MAIL = "entra:aaaaaaaa-0000-4000-8000-000000000001"


def steps_for(demo_inv, ident_id):
    return runbook.runbook(demo_inv.get(ident_id))


def test_every_demo_identity_is_fully_covered(demo_inv):
    for ident in demo_inv.identities:
        rb = runbook.runbook(ident)
        assert rb.not_covered == [], ident.id


def test_phases_are_in_order(demo_inv):
    for ident in demo_inv.identities:
        order = [PHASES.index(s.phase) for s in runbook.runbook(ident).steps]
        assert order == sorted(order), ident.id
        assert runbook.runbook(ident).steps[-1].phase == PHASES[4]


def test_entra_runbook_disables_removes_permission_and_secret(demo_inv):
    rb = steps_for(demo_inv, MAIL)
    text = runbook.to_markdown(rb, AS_OF)
    assert '"accountEnabled": false' in text
    assert "appRoleAssignments/asg-demo-0001" in text
    assert "az ad app credential delete --id aaaaaaaa-0000-4000-8000-000000000001 --key-id <key id ending 0001>" in text
    assert "auditLogs/signIns" in text


def test_odata_dollar_signs_are_escaped_for_the_shell(demo_inv):
    for s in steps_for(demo_inv, MAIL).steps:
        assert "?$" not in s.change + s.verify


def test_directory_role_and_federated_credential(demo_inv):
    text = runbook.to_markdown(steps_for(demo_inv, "entra:aaaaaaaa-0000-4000-8000-000000000005"), AS_OF)
    assert "roleManagement/directory/roleAssignments/roleasg-demo-0001" in text
    assert "federated-credential delete" in text


def test_managed_identity_is_detached_not_disabled(demo_inv):
    rb = steps_for(demo_inv, "entra:aaaaaaaa-0000-4000-8000-000000000003")
    assert "Detach the managed identity" in rb.steps[0].title
    assert "func-summariser" in rb.steps[0].change


def test_aws_role_runbook(demo_inv):
    rb = steps_for(demo_inv, "aws-role:coding-agent-runner")
    joined = "\n".join(s.change for s in rb.steps)
    assert "update-assume-role-policy --role-name coding-agent-runner" in joined
    assert "AWSRevokeOlderSessions" in joined
    assert "delete-role-policy --role-name coding-agent-runner --policy-name agent-all" in joined
    assert "cloudtrail lookup-events" in rb.steps[-1].verify


def test_aws_user_runbook_never_prints_the_full_key(demo_inv):
    rb = steps_for(demo_inv, "aws-user:support-bot")
    text = runbook.to_markdown(rb, AS_OF)
    assert "AWSDenyAll" in text and "<key id ending MPLE>" in text
    assert "AKIAIOSFODNN7EXAMPLE" not in text
    assert "detach-user-policy --user-name support-bot" in text


def test_github_app_and_deploy_key(demo_inv):
    app = runbook.to_markdown(steps_for(demo_inv, "github-app:repo-autopilot"), AS_OF)
    assert "Suspend" in app and "installations/50000001" in app
    key = runbook.to_markdown(steps_for(demo_inv, "github-deploy-key:example-org/website#1001"), AS_OF)
    assert "gh api -X DELETE repos/example-org/website/keys/1001" in key


def test_register_connector_uses_gateway(demo_inv):
    rb = steps_for(demo_inv, "register:crm-mcp-connector")
    assert "mcp-gateway.example.com" in rb.steps[0].change
    assert rb.not_covered == []


def test_coverage_reports_unhandled_grants(demo_inv):
    ident = demo_inv.get("aws-role:coding-agent-runner")
    rb = runbook.Runbook(ident, [], runbook.coverage(ident, []))
    assert rb.not_covered == ["grant inline-policy:agent-all"]
    assert "Not covered" in runbook.to_markdown(rb, AS_OF)


def test_cli_off_by_name_and_json(demo, capsys):
    assert cli.main(["off", str(demo), "mail-triage-agent", "--as-of", AS_OF, "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["identity"] == MAIL and data["not_covered"] == []
    assert data["steps"][0]["phase"] == PHASES[0]


def test_cli_off_unknown_identity_suggests(demo, capsys):
    assert cli.main(["off", str(demo), "mail-triage-agnet"]) == 2
    assert "did you mean" in capsys.readouterr().err


def test_off_runs_nothing(demo, monkeypatch, capsys):
    def boom(*a, **k):
        raise AssertionError("aos must not start a process")

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(os, "system", boom)
    for ident in ("aws-role:coding-agent-runner", "github-app:repo-autopilot", MAIL):
        assert cli.main(["off", str(demo), ident, "--as-of", AS_OF]) == 0
    assert "ran none of them" in capsys.readouterr().out


@pytest.mark.parametrize("value", ["aaaaaaaa-0000-4000-8000-000000000001", "cccccccc-0000-4000-8000-000000000001"])
def test_off_finds_identity_by_app_or_object_id(demo, value, capsys):
    assert cli.main(["off", str(demo), value, "--as-of", AS_OF]) == 0
    assert "mail-triage-agent" in capsys.readouterr().out
