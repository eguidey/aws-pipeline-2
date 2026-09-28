"""Tests for the preventive guardrails (policy/check.py)."""

import copy
import json

import pytest

from policy import check

RULES = check.load_rules()
REPO = "123456789012.dkr.ecr.us-east-1.amazonaws.com/appsec-api"
DIGEST = "sha256:" + "a" * 64


def container(**overrides):
    c = {
        "name": "api",
        "image": f"{REPO}@{DIGEST}",
        "readonlyRootFilesystem": True,
        "linuxParameters": {"initProcessEnabled": True, "capabilities": {"drop": ["ALL"]}},
    }
    c.update(overrides)
    return c


def taskdef(**overrides):
    td = {
        "family": "appsec-api",
        "cpu": "256",
        "memory": "512",
        "networkMode": "awsvpc",
        "requiresCompatibilities": ["FARGATE"],
        "containerDefinitions": [container()],
    }
    td.update(overrides)
    return td


def plan_with(*resource_changes, region="us-east-1"):
    return {"variables": {"region": {"value": region}}, "resource_changes": list(resource_changes)}


def rc(rtype, after, actions=("create",), after_unknown=None, name="this"):
    return {
        "address": f"module.x.{rtype}.{name}",
        "type": rtype,
        "change": {"actions": list(actions), "after": after, "after_unknown": after_unknown or {}},
    }


GOOD_ECR = {
    "image_tag_mutability": "IMMUTABLE",
    "image_scanning_configuration": [{"scan_on_push": True}],
    "encryption_configuration": [{"encryption_type": "KMS", "kms_key": "arn:aws:kms:..."}],
}
GOOD_TD = {
    "cpu": "256",
    "memory": "512",
    "network_mode": "awsvpc",
    "requires_compatibilities": ["FARGATE"],
    "container_definitions": json.dumps([container(image=f"{REPO}:bootstrap")]),
}


# ------------------------------------------------------------------ deploy-time gate
def test_compliant_task_definition_passes():
    assert check.check_task_definition(taskdef(), RULES, REPO) == []


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"readonlyRootFilesystem": False}, "readonlyRootFilesystem"),
        ({"privileged": True}, "privileged"),
        ({"user": "root"}, "root"),
        ({"user": "0:0"}, "root"),
        ({"linuxParameters": {}}, "drop ALL"),
        ({"linuxParameters": {"capabilities": {"drop": ["ALL"], "add": ["NET_ADMIN"]}}}, "adding Linux capabilities"),
        ({"image": f"{REPO}:latest"}, "pinned by digest"),
        ({"image": f"docker.io/evil/api@{DIGEST}"}, "pinned by digest"),
    ],
)
def test_task_definition_hardening_is_enforced(overrides, expected):
    td = taskdef(containerDefinitions=[container(**overrides)])
    violations = check.check_task_definition(td, RULES, REPO)
    assert any(expected in v for v in violations), violations


@pytest.mark.parametrize(
    ("cpu", "memory", "expected"),
    [
        ("256", "4096", "not valid with cpu 256"),  # Fargate rejects this pair
        ("2048", "4096", "exceeds the policy maximum"),  # valid for Fargate, but over the cost cap
        ("300", "512", "not a valid Fargate size"),
        ("abc", "512", "whole numbers"),
    ],
)
def test_fargate_sizing_is_enforced(cpu, memory, expected):
    violations = check.check_task_definition(taskdef(cpu=cpu, memory=memory), RULES, REPO)
    assert any(expected in v for v in violations), violations


def test_non_fargate_task_definition_is_blocked():
    violations = check.check_task_definition(taskdef(requiresCompatibilities=["EC2"], networkMode="bridge"), RULES, REPO)
    assert len(violations) == 2


# ------------------------------------------------------------------ plan-time gate
def test_compliant_plan_passes():
    plan = plan_with(
        rc("aws_ecr_repository", GOOD_ECR),
        rc("aws_ecs_task_definition", GOOD_TD),
        rc("aws_cloudwatch_log_group", {"kms_key_id": None}, after_unknown={"kms_key_id": True}),
        rc("aws_security_group", {"ingress": [{"from_port": 8000, "to_port": 8000, "cidr_blocks": ["0.0.0.0/0"]}]}),
    )
    assert check.check_plan(plan, RULES) == []


def test_disallowed_region_is_blocked():
    violations = check.check_plan(plan_with(region="eu-west-1"), RULES)
    assert any("region 'eu-west-1' is not allowed" in v for v in violations)


def test_stripping_ecr_controls_is_blocked():
    weak = {"image_tag_mutability": "MUTABLE", "image_scanning_configuration": [{"scan_on_push": False}],
            "encryption_configuration": [{"encryption_type": "AES256"}]}
    violations = check.check_plan(plan_with(rc("aws_ecr_repository", weak)), RULES)
    assert len(violations) == 3


def test_stripping_container_hardening_in_terraform_is_blocked():
    td = dict(GOOD_TD, container_definitions=json.dumps([container(readonlyRootFilesystem=False)]))
    violations = check.check_plan(plan_with(rc("aws_ecs_task_definition", td)), RULES)
    assert any("readonlyRootFilesystem" in v for v in violations)


def test_unknown_container_definitions_are_skipped_not_crashed():
    td = dict(GOOD_TD, container_definitions=None)
    plan = plan_with(rc("aws_ecs_task_definition", td, after_unknown={"container_definitions": True}))
    assert check.check_plan(plan, RULES) == []


def test_unencrypted_log_group_is_blocked():
    violations = check.check_plan(plan_with(rc("aws_cloudwatch_log_group", {"kms_key_id": None})), RULES)
    assert any("KMS" in v for v in violations)


@pytest.mark.parametrize(
    ("resource", "after"),
    [
        ("aws_security_group", {"ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]}),
        ("aws_security_group", {"ingress": [{"from_port": 0, "to_port": 0, "protocol": "-1", "ipv6_cidr_blocks": ["::/0"]}]}),
        ("aws_vpc_security_group_ingress_rule", {"from_port": 3389, "to_port": 3389, "cidr_ipv4": "0.0.0.0/0"}),
        ("aws_security_group_rule", {"type": "ingress", "from_port": 1, "to_port": 1024, "cidr_blocks": ["0.0.0.0/0"]}),
    ],
)
def test_admin_ports_open_to_internet_are_blocked(resource, after):
    violations = check.check_plan(plan_with(rc(resource, after)), RULES)
    assert any("must not be open to the internet" in v for v in violations), violations


def test_admin_port_from_private_cidr_is_allowed():
    after = {"ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["10.0.0.0/8"]}]}
    assert check.check_plan(plan_with(rc("aws_security_group", after)), RULES) == []


def test_public_access_block_must_be_complete():
    after = {"block_public_acls": True, "block_public_policy": False, "ignore_public_acls": True, "restrict_public_buckets": True}
    violations = check.check_plan(plan_with(rc("aws_s3_bucket_public_access_block", after)), RULES)
    assert violations == ["module.x.aws_s3_bucket_public_access_block.this: block_public_policy must be true"]


@pytest.mark.parametrize("rtype", ["aws_iam_user", "aws_iam_access_key"])
def test_long_lived_credentials_are_blocked(rtype):
    violations = check.check_plan(plan_with(rc(rtype, {"name": "x"})), RULES)
    assert any("not allowed" in v for v in violations)


def test_deletes_and_no_ops_are_not_evaluated():
    weak = copy.deepcopy(GOOD_ECR) | {"image_tag_mutability": "MUTABLE"}
    plan = plan_with(rc("aws_ecr_repository", weak, actions=("delete",)), rc("aws_iam_user", {}, actions=("no-op",)))
    assert check.check_plan(plan, RULES) == []


# ------------------------------------------------------------------ CLI
def test_cli_exit_codes_and_step_summary(tmp_path, monkeypatch):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    good, bad = tmp_path / "good.json", tmp_path / "bad.json"
    good.write_text(json.dumps(taskdef()))
    bad.write_text(json.dumps(taskdef(cpu="4096", memory="8192")))

    assert check.main(["taskdef", str(good), "--expected-repository", REPO]) == 0
    assert check.main(["taskdef", str(bad), "--expected-repository", REPO]) == 1
    assert "FAILED" in summary.read_text()


def test_rules_file_matches_fargate_platform_limits():
    # Guard against typos in rules.json: every size must be a documented Fargate combination.
    sizes = RULES["fargate"]["valid_sizes"]
    assert sizes["256"] == [512, 1024, 2048]
    assert sizes["512"] == list(range(1024, 4097, 1024))
    assert sizes["1024"] == list(range(2048, 8193, 1024))
    assert sizes["2048"] == list(range(4096, 16385, 1024))
    assert set(RULES["allowed_regions"]) == {"us-east-1", "us-east-2"}
