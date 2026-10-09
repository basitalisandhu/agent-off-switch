import json

import pytest
from conftest import GRAPH, build, entra_app, entra_sp, guid, write_json

from agent_off_switch.util import InputError


def graph_resource(folder):
    write_json(
        folder,
        "entra-resource-sps.json",
        {
            "value": [
                {"id": GRAPH, "displayName": "Microsoft Graph", "appRoles": [{"id": "r1", "value": "Mail.ReadWrite"}]}
            ]
        },
    )


def test_app_registration_credentials_and_owners(tmp_path):
    write_json(
        tmp_path,
        "entra-applications.json",
        {"value": [entra_app(1, "mail-agent", owners=["team@example.com"], secrets=[("2026-01-01", "2027-01-01")])]},
    )
    inv = build(tmp_path)
    ident = inv.get(f"entra:{guid(1)}")
    assert ident.owners == ["team@example.com"]
    assert ident.credentials[0].kind == "client-secret"
    assert ident.credentials[0].key_id == "****0100"
    assert ident.agent and "name" in ident.agent_signals


def test_managed_identity_and_agent_identity_types(tmp_path):
    write_json(
        tmp_path,
        "entra-service-principals.json",
        {
            "value": [
                entra_sp(1, "func-x", "ManagedIdentity", alternativeNames=["isExplicit=False", "/subscriptions/s/x"]),
                entra_sp(2, "helper", **{"@odata.type": "#microsoft.graph.agentIdentity"}),
            ]
        },
    )
    inv = build(tmp_path)
    assert inv.get(f"entra:{guid(1)}").type == "entra-managed-identity"
    assert inv.get(f"entra:{guid(1)}").refs["managed_identity_resource"] == "/subscriptions/s/x"
    agent = inv.get(f"entra:{guid(2)}")
    assert agent.type == "entra-agent-identity"
    assert "Entra agent identity" in agent.agent_signals


def test_microsoft_first_party_service_principals_are_skipped(tmp_path):
    sp = entra_sp(1, "Microsoft Graph")
    sp["appOwnerOrganizationId"] = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
    write_json(tmp_path, "entra-service-principals.json", {"value": [sp]})
    assert build(tmp_path).identities == []


def test_sponsors_and_tags_count_as_owners(tmp_path):
    write_json(
        tmp_path,
        "entra-service-principals.json",
        {
            "value": [
                entra_sp(1, "a", sponsors=[{"mail": "sponsor@example.com"}]),
                entra_sp(2, "b", tags=["owner:tag@example.com"]),
            ]
        },
    )
    inv = build(tmp_path)
    assert inv.get(f"entra:{guid(1)}").owners == ["sponsor@example.com"]
    assert inv.get(f"entra:{guid(2)}").owners == ["tag@example.com"]


def test_sign_in_activity_sets_last_used(tmp_path):
    write_json(tmp_path, "entra-service-principals.json", {"value": [entra_sp(1, "a"), entra_sp(2, "b")]})
    write_json(
        tmp_path,
        "entra-sign-in-activity.json",
        {"value": [{"appId": guid(1), "lastSignInActivity": {"lastSignInDateTime": "2026-10-01T00:00:00Z"}}]},
    )
    inv = build(tmp_path)
    assert inv.get(f"entra:{guid(1)}").last_used == "2026-10-01T00:00:00Z"
    assert inv.get(f"entra:{guid(2)}").activity_recorded and inv.get(f"entra:{guid(2)}").last_used is None


def test_missing_sign_in_activity_is_noted(tmp_path):
    write_json(tmp_path, "entra-service-principals.json", {"value": [entra_sp(1, "a")]})
    assert any("sign-in-activity" in n for n in build(tmp_path).notes)


def test_application_permission_names_resolve(tmp_path):
    write_json(tmp_path, "entra-service-principals.json", {"value": [entra_sp(1, "a")]})
    graph_resource(tmp_path)
    write_json(
        tmp_path,
        "entra-app-role-assignments.json",
        {"value": [{"id": "x1", "principalId": guid(1, "cccccccc"), "resourceId": GRAPH, "appRoleId": "r1"}]},
    )
    g = build(tmp_path).get(f"entra:{guid(1)}").grants[0]
    assert g.name == "Microsoft Graph: Mail.ReadWrite"
    assert g.scope == "tenant" and g.score == 90 and g.ref == "x1"


def test_delegated_grants_split_scopes_and_consent_type(tmp_path):
    write_json(tmp_path, "entra-service-principals.json", {"value": [entra_sp(1, "a")]})
    graph_resource(tmp_path)
    write_json(
        tmp_path,
        "entra-oauth2-grants.json",
        {
            "value": [
                {
                    "id": "g1",
                    "clientId": guid(1, "cccccccc"),
                    "consentType": "AllPrincipals",
                    "resourceId": GRAPH,
                    "scope": "User.Read Mail.Read",
                },
                {
                    "id": "g2",
                    "clientId": guid(1, "cccccccc"),
                    "consentType": "Principal",
                    "resourceId": GRAPH,
                    "scope": "Files.Read.All",
                },
            ]
        },
    )
    grants = build(tmp_path).get(f"entra:{guid(1)}").grants
    assert len(grants) == 3
    assert {g.scope for g in grants} == {"all users", "one user"}


def test_directory_roles_attach_to_service_principal(tmp_path):
    write_json(tmp_path, "entra-service-principals.json", {"value": [entra_sp(1, "a")]})
    write_json(
        tmp_path,
        "entra-directory-roles.json",
        {
            "value": [
                {
                    "id": "ra1",
                    "principalId": guid(1, "cccccccc"),
                    "directoryScopeId": "/",
                    "roleDefinition": {"displayName": "Global Administrator"},
                }
            ]
        },
    )
    g = build(tmp_path).get(f"entra:{guid(1)}").grants[0]
    assert (g.kind, g.name, g.score, g.scope) == ("directory-role", "Global Administrator", 100, "tenant")


def test_bad_json_is_input_error(tmp_path):
    (tmp_path / "entra-applications.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(InputError):
        build(tmp_path)


def test_bom_and_crlf_exports_are_read(tmp_path):
    text = json.dumps({"value": [{"appId": guid(1), "displayName": "x"}]})
    (tmp_path / "entra-applications.json").write_bytes(b"\xef\xbb\xbf" + text.replace(",", ",\r\n").encode())
    assert build(tmp_path).get(f"entra:{guid(1)}") is not None
