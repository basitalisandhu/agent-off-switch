import json
from urllib.parse import quote

import pytest
from conftest import build, write_json, write_text

from agent_off_switch.exports import trust_principals
from agent_off_switch.util import InputError

ACCOUNT = "111122223333"
STAR = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


def role(name, path="/", tags=(), inline=None, managed=(), trust=None, last=None):
    return {
        "Path": path,
        "RoleName": name,
        "Arn": f"arn:aws:iam::{ACCOUNT}:role/{name}",
        "CreateDate": "2026-01-01T00:00:00Z",
        "AssumeRolePolicyDocument": trust
        or {"Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}}]},
        "Tags": list(tags),
        "RoleLastUsed": {"LastUsedDate": last} if last else {},
        "AttachedManagedPolicies": [{"PolicyName": n, "PolicyArn": a} for n, a in managed],
        "RolePolicyList": [{"PolicyName": "inline", "PolicyDocument": inline}] if inline else [],
    }


def test_roles_with_wildcard_inline_policy_score_100(tmp_path):
    write_json(tmp_path, "aws-authorization-details.json", {"RoleDetailList": [role("agent-x", inline=STAR)]})
    ident = build(tmp_path).get("aws-role:agent-x")
    assert ident.blast_radius == 100 and ident.agent
    assert ident.grants[0].reason == "Action * on Resource *"


def test_service_linked_roles_skipped_unless_asked(tmp_path):
    write_json(
        tmp_path,
        "aws-authorization-details.json",
        {"RoleDetailList": [role("AWSServiceRoleForX", path="/aws-service-role/x.amazonaws.com/")]},
    )
    assert build(tmp_path).identities == []
    assert len(build(tmp_path, include_aws_managed_roles=True).identities) == 1


def test_owner_tag_and_last_used(tmp_path):
    write_json(
        tmp_path,
        "aws-authorization-details.json",
        {
            "RoleDetailList": [
                role("r", tags=[{"Key": "owner", "Value": "team@example.com"}], last="2026-10-01T00:00:00Z")
            ]
        },
    )
    ident = build(tmp_path).get("aws-role:r")
    assert ident.owners == ["team@example.com"] and ident.last_used.startswith("2026-10-01")


def test_customer_managed_policy_document_is_scored(tmp_path):
    arn = f"arn:aws:iam::{ACCOUNT}:policy/p"
    doc = {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]}
    write_json(
        tmp_path,
        "aws-authorization-details.json",
        {
            "RoleDetailList": [role("r", managed=[("p", arn)])],
            "Policies": [{"Arn": arn, "PolicyVersionList": [{"IsDefaultVersion": True, "Document": doc}]}],
        },
    )
    assert build(tmp_path).get("aws-role:r").blast_radius == 90


def test_aws_managed_administrator_access(tmp_path):
    write_json(
        tmp_path,
        "aws-authorization-details.json",
        {
            "RoleDetailList": [
                role("r", managed=[("AdministratorAccess", "arn:aws:iam::aws:policy/AdministratorAccess")])
            ]
        },
    )
    assert build(tmp_path).get("aws-role:r").blast_radius == 100


def test_users_with_keys_and_last_used(tmp_path):
    write_json(
        tmp_path,
        "aws-access-keys.json",
        [
            {
                "AccessKeyMetadata": [
                    {
                        "UserName": "bot",
                        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                        "Status": "Active",
                        "CreateDate": "2026-01-01T00:00:00Z",
                    }
                ]
            }
        ],
    )
    write_json(
        tmp_path,
        "aws-access-key-last-used.json",
        [{"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "AccessKeyLastUsed": {"LastUsedDate": "2026-05-01T00:00:00Z"}}],
    )
    ident = build(tmp_path).get("aws-user:bot")
    assert ident.credentials[0].key_id == "****MPLE"
    assert ident.credentials[0].last_used == "2026-05-01T00:00:00Z"
    assert "unused" in ident.flags and "stale-credential" in ident.flags
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(ident.to_dict())


def test_missing_last_used_is_noted(tmp_path):
    write_json(
        tmp_path,
        "aws-access-keys.json",
        {"AccessKeyMetadata": [{"UserName": "u", "AccessKeyId": "AKIAIOSFODNN7EXAMPLE"}]},
    )
    assert any("last use is unknown" in n for n in build(tmp_path).notes)


def test_credential_report_fallback(tmp_path):
    write_text(
        tmp_path,
        "aws-credential-report.csv",
        "user,arn,user_creation_time,password_enabled,access_key_1_active,access_key_1_last_rotated,"
        "access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date\n"
        "<root_account>,x,2020-01-01,true,false,N/A,N/A,false,N/A,N/A\n"
        "svc,arn:aws:iam::111122223333:user/svc,2025-01-01,false,true,2025-01-01,2026-10-01,false,N/A,N/A\n",
    )
    inv = build(tmp_path)
    assert [i.id for i in inv.identities] == ["aws-user:svc"]
    assert inv.get("aws-user:svc").credentials[0].key_id == "slot 1"


def test_credential_report_without_user_column_is_bad_input(tmp_path):
    write_text(tmp_path, "aws-credential-report.csv", "name,arn\nx,y\n")
    with pytest.raises(InputError):
        build(tmp_path)


def test_group_policies_resolve_for_users(tmp_path):
    write_json(
        tmp_path,
        "aws-access-keys.json",
        {"AccessKeyMetadata": [{"UserName": "u", "AccessKeyId": "AKIAIOSFODNN7EXAMPLE"}]},
    )
    write_json(
        tmp_path,
        "aws-authorization-details.json",
        {
            "UserDetailList": [{"UserName": "u", "GroupList": ["admins"]}],
            "GroupDetailList": [
                {"GroupName": "admins", "GroupPolicyList": [{"PolicyName": "all", "PolicyDocument": STAR}]}
            ],
        },
    )
    g = build(tmp_path).get("aws-user:u").grants[0]
    assert g.kind == "group" and g.score == 100 and "through group admins" in g.reason


def test_trust_principals_accepts_url_encoded_text():
    doc = quote(json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}}]}))
    assert trust_principals(doc) == ["AWS: *"]
    assert trust_principals({"Statement": {"Effect": "Allow", "Principal": "*"}}) == ["AWS: *"]


def test_details_must_be_an_object(tmp_path):
    write_json(tmp_path, "aws-authorization-details.json", [1, 2])
    with pytest.raises(InputError):
        build(tmp_path)
