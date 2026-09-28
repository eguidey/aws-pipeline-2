"""Preventive guardrails - the AWS counterpart of Azure Policy's "deny" effect.

AWS Config (infra/modules/guardrails) *detects* drift after the fact. This module *blocks*
non-compliant changes before they reach AWS, at two points:

  plan     - run on `terraform show -json tfplan` before `terraform apply` (infra.yml)
  taskdef  - run on the task definition the pipeline is about to register (pipeline.yml)

Rules live in policy/rules.json, the same file Terraform reads for input validation, so there
is one source of truth. Usage:

  python -m policy.check plan plan.json
  python -m policy.check taskdef new.json --expected-repository 123.dkr.ecr.us-east-1.amazonaws.com/appsec-api
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

RULES_PATH = Path(__file__).with_name("rules.json")
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
MUTATING_ACTIONS = {"create", "update"}


def load_rules(path: Path = RULES_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


# ------------------------------------------------------------------ shared rules
def check_fargate_size(cpu: Any, memory: Any, rules: dict[str, Any], where: str) -> list[str]:
    """Fargate only accepts specific CPU/memory pairs; we also cap CPU to control cost."""
    try:
        cpu_i, mem_i = int(str(cpu)), int(str(memory))
    except (TypeError, ValueError):
        return [f"{where}: cpu/memory must be whole numbers (got cpu={cpu!r}, memory={memory!r})"]
    fargate = rules["fargate"]
    violations = []
    if cpu_i > fargate["max_cpu"]:
        violations.append(f"{where}: cpu {cpu_i} exceeds the policy maximum of {fargate['max_cpu']}")
    allowed = fargate["valid_sizes"].get(str(cpu_i))
    if allowed is None:
        violations.append(f"{where}: cpu {cpu_i} is not a valid Fargate size ({', '.join(fargate['valid_sizes'])})")
    elif mem_i not in allowed:
        violations.append(f"{where}: memory {mem_i} is not valid with cpu {cpu_i} (allowed: {allowed})")
    return violations


def check_containers(containers: list[dict[str, Any]], where: str, expected_repository: str | None = None) -> list[str]:
    """Runtime hardening every container must keep - stripping it from the module is blocked."""
    violations = []
    for c in containers:
        name = f"{where} container '{c.get('name', '?')}'"
        if c.get("readonlyRootFilesystem") is not True:
            violations.append(f"{name}: readonlyRootFilesystem must be true")
        if c.get("privileged") is True:
            violations.append(f"{name}: privileged containers are not allowed")
        user = str(c.get("user", "")).split(":")[0]
        if user in {"root", "0"}:
            violations.append(f"{name}: must not run as root")
        drops = ((c.get("linuxParameters") or {}).get("capabilities") or {}).get("drop") or []
        if "ALL" not in drops:
            violations.append(f"{name}: must drop ALL Linux capabilities")
        adds = ((c.get("linuxParameters") or {}).get("capabilities") or {}).get("add") or []
        if adds:
            violations.append(f"{name}: adding Linux capabilities is not allowed ({adds})")
        if expected_repository is not None:
            image = str(c.get("image", ""))
            if not image.startswith(f"{expected_repository}@sha256:"):
                violations.append(f"{name}: image must come from {expected_repository} and be pinned by digest (got {image!r})")
    return violations


# ------------------------------------------------------------------ deploy-time gate
def check_task_definition(taskdef: dict[str, Any], rules: dict[str, Any], expected_repository: str | None) -> list[str]:
    where = f"task definition '{taskdef.get('family', '?')}'"
    violations = check_fargate_size(taskdef.get("cpu"), taskdef.get("memory"), rules, where)
    if "FARGATE" not in (taskdef.get("requiresCompatibilities") or []):
        violations.append(f"{where}: must require FARGATE")
    if taskdef.get("networkMode") != "awsvpc":
        violations.append(f"{where}: networkMode must be awsvpc")
    violations += check_containers(taskdef.get("containerDefinitions") or [], where, expected_repository)
    return violations


# ------------------------------------------------------------------ plan-time gate
def _first(block: Any) -> dict[str, Any]:
    if isinstance(block, list) and block:
        return block[0] or {}
    return block if isinstance(block, dict) else {}


def _check_plan_resource(rc: dict[str, Any], rules: dict[str, Any]) -> list[str]:
    rtype, addr = rc.get("type", ""), rc.get("address", "?")
    change = rc.get("change") or {}
    after = change.get("after") or {}
    unknown = change.get("after_unknown") or {}
    v: list[str] = []

    if rtype in rules["forbidden_resource_types"]:
        return [f"{addr}: {rtype} is not allowed - humans and CI use roles and OIDC, never long-lived IAM users or keys"]

    if rtype == "aws_ecr_repository":
        if after.get("image_tag_mutability") != "IMMUTABLE":
            v.append(f"{addr}: image tags must be IMMUTABLE")
        if _first(after.get("image_scanning_configuration")).get("scan_on_push") is not True:
            v.append(f"{addr}: scan_on_push must be enabled")
        if _first(after.get("encryption_configuration")).get("encryption_type") != "KMS":
            v.append(f"{addr}: must be encrypted with KMS")

    elif rtype == "aws_ecs_task_definition":
        v += check_fargate_size(after.get("cpu"), after.get("memory"), rules, addr)
        if "FARGATE" not in (after.get("requires_compatibilities") or []):
            v.append(f"{addr}: must require FARGATE")
        if after.get("network_mode") != "awsvpc":
            v.append(f"{addr}: network_mode must be awsvpc")
        if not unknown.get("container_definitions") and after.get("container_definitions"):
            v += check_containers(json.loads(after["container_definitions"]), addr)

    elif rtype == "aws_cloudwatch_log_group":
        if not after.get("kms_key_id") and not unknown.get("kms_key_id"):
            v.append(f"{addr}: log groups must be encrypted with a KMS key")

    elif rtype == "aws_s3_bucket_public_access_block":
        for flag in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"):
            if after.get(flag) is not True:
                v.append(f"{addr}: {flag} must be true")

    elif rtype == "aws_security_group":
        for rule in after.get("ingress") or []:
            v += _check_ingress(addr, rule.get("protocol"), rule.get("from_port"), rule.get("to_port"),
                                (rule.get("cidr_blocks") or []) + (rule.get("ipv6_cidr_blocks") or []), rules)

    elif rtype == "aws_vpc_security_group_ingress_rule":
        v += _check_ingress(addr, after.get("ip_protocol"), after.get("from_port"), after.get("to_port"),
                            [c for c in (after.get("cidr_ipv4"), after.get("cidr_ipv6")) if c], rules)

    elif rtype == "aws_security_group_rule" and after.get("type") == "ingress":
        v += _check_ingress(addr, after.get("protocol"), after.get("from_port"), after.get("to_port"),
                            (after.get("cidr_blocks") or []) + (after.get("ipv6_cidr_blocks") or []), rules)
    return v


def _check_ingress(addr: str, protocol: Any, from_port: Any, to_port: Any, cidrs: list[str],
                   rules: dict[str, Any]) -> list[str]:
    if not OPEN_CIDRS.intersection(cidrs):
        return []
    if str(protocol).lower() in {"-1", "all"} or from_port is None or to_port is None:
        lo, hi = 0, 65535  # "all traffic" rules ignore the port fields (AWS stores them as 0 or -1)
    else:
        lo, hi = int(from_port), int(to_port)
        if lo == -1 or hi == -1:
            lo, hi = 0, 65535
    return [f"{addr}: port {p} must not be open to the internet"
            for p in rules["blocked_admin_ports"] if lo <= p <= hi]


def check_plan(plan: dict[str, Any], rules: dict[str, Any]) -> list[str]:
    violations = []
    region = ((plan.get("variables") or {}).get("region") or {}).get("value")
    if region not in rules["allowed_regions"]:
        violations.append(f"region {region!r} is not allowed (allowed: {rules['allowed_regions']})")
    for rc in plan.get("resource_changes") or []:
        actions = set((rc.get("change") or {}).get("actions") or [])
        if actions & MUTATING_ACTIONS:
            violations += _check_plan_resource(rc, rules)
    return violations


# ------------------------------------------------------------------ CLI
def _report(kind: str, violations: list[str]) -> int:
    lines = [f"### Policy gate ({kind}): " + ("FAILED" if violations else "passed")]
    lines += [f"- {v}" for v in violations] or ["All preventive guardrails satisfied."]
    text = "\n".join(lines)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    for v in violations:
        print(f"::error title=Policy violation::{v}")
    return 1 if violations else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="kind", required=True)
    p_plan = sub.add_parser("plan", help="check a `terraform show -json` plan")
    p_plan.add_argument("file")
    p_td = sub.add_parser("taskdef", help="check an ECS task definition before it is registered")
    p_td.add_argument("file")
    p_td.add_argument("--expected-repository", help="ECR repository URI the image must come from (pinned by digest)")
    parser.add_argument("--rules", default=str(RULES_PATH))
    args = parser.parse_args(argv)

    rules = load_rules(Path(args.rules))
    data = json.loads(Path(args.file).read_text(encoding="utf-8"))
    if args.kind == "plan":
        return _report("terraform plan", check_plan(data, rules))
    return _report("task definition", check_task_definition(data, rules, args.expected_repository))


if __name__ == "__main__":
    sys.exit(main())
