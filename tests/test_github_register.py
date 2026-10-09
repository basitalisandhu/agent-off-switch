import pytest
from conftest import build, guid, write_json, write_text

from agent_off_switch.util import InputError

HEAD = "id,name,type,owner,purpose,platform,identity,permissions,last_used,credential_kind,credential_id,credential_created,credential_expires,gateway\n"


def installs(tmp_path, selection="all", suspended=None):
    write_json(
        tmp_path,
        "github-installations.json",
        {
            "installations": [
                {
                    "id": 7,
                    "app_slug": "fixer",
                    "account": {"login": "example-org"},
                    "repository_selection": selection,
                    "suspended_at": suspended,
                    "permissions": {"administration": "write", "metadata": "read"},
                }
            ]
        },
    )


def test_installation_with_admin_on_all_repositories(tmp_path):
    installs(tmp_path)
    ident = build(tmp_path).get("github-app:fixer")
    assert ident.blast_radius == 95
    assert ident.refs["repository_selection"] == "all"
    assert {g.scope for g in ident.grants} == {"all repositories"}


def test_installation_on_selected_repositories_scores_lower(tmp_path):
    installs(tmp_path, selection="selected")
    assert build(tmp_path).get("github-app:fixer").blast_radius == 70


def test_suspended_installation_is_disabled(tmp_path):
    installs(tmp_path, suspended="2026-10-01T00:00:00Z")
    assert "disabled" in build(tmp_path).get("github-app:fixer").flags


def test_deploy_keys_list_and_mapping_shapes(tmp_path):
    write_json(
        tmp_path,
        "github-deploy-keys.json",
        {"example-org/site": [{"id": 5, "title": "push", "read_only": False, "created_at": "2026-01-01T00:00:00Z"}]},
    )
    ident = build(tmp_path).get("github-deploy-key:example-org/site#5")
    assert ident.blast_radius == 50
    assert ident.grants[0].name == "example-org/site (read-write)"


def test_register_row_links_to_identity_by_app_id(tmp_path):
    write_json(tmp_path, "entra-applications.json", {"value": [{"appId": guid(1), "displayName": "svc"}]})
    write_text(
        tmp_path, "agents.csv", HEAD + f"triage,triage,agent,team@example.com,Sorts mail,m365,{guid(1)},,,,,,,\n"
    )
    ident = build(tmp_path).get(f"entra:{guid(1)}")
    assert ident.owners == ["team@example.com"]
    assert ident.used_by == ["triage"] and ident.agent
    assert ident.purpose == "Sorts mail"


def test_register_row_pointing_nowhere_is_bad_input(tmp_path):
    write_text(tmp_path, "agents.csv", HEAD + "x,x,agent,,,,aws-role:missing,,,,,,,\n")
    with pytest.raises(InputError, match="no export holds"):
        build(tmp_path)


def test_register_only_connector_with_credential_and_permissions(tmp_path):
    write_text(
        tmp_path,
        "agents.csv",
        HEAD
        + "crm,crm,mcp-connector,ops@example.com,,CRM,,contacts:read;admin:*,2026-10-01,api-key,key-1234,2026-01-01,,gw\n",
    )
    ident = build(tmp_path).get("register:crm")
    assert ident.type == "mcp-connector"
    assert ident.credentials[0].key_id == "****1234"
    assert ident.blast_radius == 80
    assert ident.refs["gateway"] == "gw"


def test_register_needs_id_or_name(tmp_path):
    write_text(tmp_path, "agents.csv", "owner,purpose\nx,y\n")
    with pytest.raises(InputError):
        build(tmp_path)


def test_legacy_register_csv_name_is_read(tmp_path):
    write_text(tmp_path, "register.csv", "id,name,owner\nbot1,bot1,a@example.com\n")
    assert build(tmp_path).get("register:bot1").owners == ["a@example.com"]
