import pytest

from agent_off_switch.model import Grant
from agent_off_switch.scoring import (
    aws_document_score,
    aws_policy_score,
    declared_score,
    delegated_score,
    directory_role_score,
    github_permission_score,
    graph_application_score,
    score_grant,
)


@pytest.mark.parametrize(
    ("perm", "score"),
    [
        ("RoleManagement.ReadWrite.Directory", 95),
        ("Mail.ReadWrite", 90),
        ("Files.Read.All", 75),
        ("Tasks.ReadWrite.All", 60),
        ("Sites.Selected", 40),
    ],
)
def test_graph_application_tiers(perm, score):
    assert graph_application_score(perm)[0] == score


def test_delegated_scores_depend_on_consent_and_risk():
    assert delegated_score("Mail.Read", True)[0] == 50
    assert delegated_score("User.Read", True)[0] == 20
    assert delegated_score("Mail.Read", False)[0] == 25
    assert delegated_score("User.Read", False)[0] == 10


def test_directory_roles_score_highest_for_tenant_takeover():
    assert directory_role_score("Global Administrator")[0] == 100
    assert directory_role_score("Cloud Application Administrator")[0] == 95
    assert directory_role_score("Helpdesk Administrator")[0] == 85
    assert directory_role_score("Directory Readers")[0] == 40


@pytest.mark.parametrize(
    ("statement", "score"),
    [
        ({"Effect": "Allow", "Action": "*", "Resource": "*"}, 100),
        ({"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b/*"}, 90),
        ({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}, 95),
        ({"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"}, 90),
        ({"Effect": "Allow", "Action": "s3:*", "Resource": "*"}, 75),
        ({"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::b"}, 55),
        ({"Effect": "Allow", "Action": "ses:SendEmail", "Resource": "*"}, 45),
        ({"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "*"}, 30),
        ({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}, 20),
        ({"Effect": "Deny", "Action": "*", "Resource": "*"}, 0),
    ],
)
def test_aws_document_scores(statement, score):
    assert aws_document_score({"Statement": [statement]})[0] == score


def test_aws_document_as_json_text():
    assert aws_document_score('{"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}')[0] == 100


def test_aws_managed_policies_by_name():
    assert aws_policy_score("AdministratorAccess", "arn:aws:iam::aws:policy/AdministratorAccess", [])[0] == 100
    assert aws_policy_score("AmazonS3FullAccess", "arn:aws:iam::aws:policy/AmazonS3FullAccess", [])[0] == 75
    assert aws_policy_score("AWSDenyAll", "arn:aws:iam::aws:policy/AWSDenyAll", [])[0] == 0
    assert aws_policy_score("custom", "arn:aws:iam::111122223333:policy/custom", [])[0] == 35


def test_github_permissions():
    assert github_permission_score("organization_administration", "write", False)[0] == 100
    assert github_permission_score("administration", "write", True)[0] == 95
    assert github_permission_score("workflows", "write", True)[0] == 80
    assert github_permission_score("issues", "write", False)[0] == 40
    assert github_permission_score("metadata", "read", True)[0] == 30


def test_declared_permissions():
    assert declared_score("admin:*")[0] == 80
    assert declared_score("deals:write")[0] == 50
    assert declared_score("contacts:read")[0] == 20


def test_score_grant_sets_scope():
    g = score_grant(Grant(kind="app-permission", name="contents:write", detail={"repository_selection": "all"}))
    assert (g.score, g.scope) == (80, "all repositories")
    g = score_grant(Grant(kind="something-new", name="x"))
    assert g.score == 20
