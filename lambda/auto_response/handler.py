"""Automated incident response for the AppSec API.

Triggered two ways:
  1. EventBridge "CloudWatch Alarm State Change" (alarm -> ALARM): find the source IPs
     behind the alert with a Logs Insights query, block them with a network ACL deny
     rule, record the block, and email a summary with the evidence.
  2. EventBridge schedule ({"action": "expire"}): remove blocks whose time is up.

Network ACLs are used (rather than security groups) because they support explicit DENY
rules that are evaluated before the allow-all rule at number 100.
"""

from __future__ import annotations

import ipaddress
import json
import os
import time
from datetime import UTC, datetime

import boto3
from botocore.exceptions import ClientError

RULE_MIN, RULE_MAX = 1, 90  # deny rules live below the allow-all rule (100)

# Which runtime event type identifies the offender for each alarm.
DEFAULT_ALARM_EVENT_TYPES = {
    "brute_force": "brute_force_suspected",
    "injection_attempt": "suspicious_input",
}


class Config:
    """Settings from environment variables (set by Terraform)."""

    def __init__(self, env: dict | None = None):
        env = env if env is not None else os.environ
        self.log_group = env["APP_LOG_GROUP"]
        self.nacl_id = env["NACL_ID"]
        self.table = env["BLOCKLIST_TABLE"]
        self.topic_arn = env["ALERT_TOPIC_ARN"]
        self.mode = env.get("RESPONSE_MODE", "block").lower()  # "block" or "notify"
        self.block_minutes = int(env.get("BLOCK_MINUTES", "60"))
        self.lookback_minutes = int(env.get("LOOKBACK_MINUTES", "15"))
        self.max_blocks = int(env.get("MAX_BLOCKS_PER_ALARM", "5"))
        self.never_block = [ipaddress.ip_network(c, strict=False) for c in json.loads(env.get("NEVER_BLOCK_CIDRS", "[]"))]
        self.alarm_event_types = json.loads(env.get("ALARM_EVENT_TYPES", json.dumps(DEFAULT_ALARM_EVENT_TYPES)))


def log(action: str, **fields) -> None:
    """Structured JSON audit trail of every response action."""
    print(json.dumps({"timestamp": datetime.now(UTC).isoformat(), "component": "auto-response",
                      "action": action, **fields}, default=str))


# --------------------------------------------------------------------------- evidence
def event_type_for_alarm(alarm_name: str, mapping: dict) -> str | None:
    for suffix, event_type in mapping.items():
        if alarm_name.endswith(suffix):
            return event_type
    return None


def find_offenders(logs_client, cfg: Config, event_type: str, now: float | None = None,
                   poll_seconds: float = 1.0, timeout_seconds: float = 40) -> list[dict]:
    """Run a Logs Insights query and return [{"ip": ..., "events": n}] sorted by volume."""
    now = time.time() if now is None else now
    query = (
        f'filter event_type = "{event_type}" '
        "| stats count(*) as events by src_ip "
        "| sort events desc | limit 20"
    )
    query_id = logs_client.start_query(
        logGroupName=cfg.log_group,
        startTime=int(now - cfg.lookback_minutes * 60),
        endTime=int(now),
        queryString=query,
    )["queryId"]

    deadline = time.monotonic() + timeout_seconds
    while True:
        result = logs_client.get_query_results(queryId=query_id)
        if result["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
            break
        if time.monotonic() > deadline:
            log("query_timeout", query_id=query_id)
            return []
        time.sleep(poll_seconds)

    offenders = []
    for row in result.get("results", []):
        fields = {f["field"]: f["value"] for f in row}
        if fields.get("src_ip"):
            offenders.append({"ip": fields["src_ip"], "events": int(float(fields.get("events", 0)))})
    return offenders


def blockable(ip: str, cfg: Config) -> tuple[bool, str]:
    """Only block public IPv4 addresses that aren't on the never-block list."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, "not a valid IP address"
    if addr.version != 4:
        return False, "IPv6 not supported by this rule set"
    if not addr.is_global:
        return False, "private or reserved address"
    if any(addr in net for net in cfg.never_block):
        return False, "on the never-block list"
    return True, "ok"


# --------------------------------------------------------------------------- containment
def existing_denies(ec2_client, nacl_id: str) -> dict[str, int]:
    """Map of CIDR -> rule number for deny rules we manage."""
    acl = ec2_client.describe_network_acls(NetworkAclIds=[nacl_id])["NetworkAcls"][0]
    return {
        e["CidrBlock"]: e["RuleNumber"]
        for e in acl["Entries"]
        if not e["Egress"] and e["RuleAction"] == "deny" and RULE_MIN <= e["RuleNumber"] <= RULE_MAX and "CidrBlock" in e
    }


def block_ip(ec2_client, table, cfg: Config, ip: str, reason: str, now: float | None = None) -> dict:
    """Add a NACL deny rule for ip/32 and record it. Idempotent."""
    now = time.time() if now is None else now
    cidr = f"{ip}/32"
    current = existing_denies(ec2_client, cfg.nacl_id)
    if cidr in current:
        return {"ip": ip, "status": "already_blocked", "rule_number": current[cidr]}

    used = set(current.values())
    free = next((n for n in range(RULE_MIN, RULE_MAX + 1) if n not in used), None)
    if free is None:
        return {"ip": ip, "status": "failed", "error": "no free NACL rule numbers"}

    ec2_client.create_network_acl_entry(
        NetworkAclId=cfg.nacl_id, RuleNumber=free, Protocol="-1",
        RuleAction="deny", Egress=False, CidrBlock=cidr,
    )
    expires_at = int(now + cfg.block_minutes * 60)
    table.put_item(Item={
        "ip": ip, "rule_number": free, "reason": reason,
        "blocked_at": int(now), "expires_at": expires_at,
    })
    return {"ip": ip, "status": "blocked", "rule_number": free,
            "expires_at": datetime.fromtimestamp(expires_at, UTC).isoformat()}


def expire_blocks(ec2_client, table, cfg: Config, now: float | None = None) -> list[dict]:
    """Remove blocks whose time has run out."""
    now = time.time() if now is None else now
    released = []
    items = table.scan().get("Items", [])
    for item in items:
        if int(item["expires_at"]) > now:
            continue
        try:
            ec2_client.delete_network_acl_entry(NetworkAclId=cfg.nacl_id, RuleNumber=int(item["rule_number"]), Egress=False)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidNetworkAclEntry.NotFound":
                raise
        table.delete_item(Key={"ip": item["ip"]})
        released.append({"ip": item["ip"], "rule_number": int(item["rule_number"])})
        log("unblocked", ip=item["ip"], rule_number=int(item["rule_number"]))
    return released


# --------------------------------------------------------------------------- reporting
def build_summary(alarm_name: str, event_type: str, offenders: list[dict], actions: list[dict], cfg: Config) -> str:
    lines = [
        f"Automated response for alarm: {alarm_name}",
        f"Time (UTC): {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')}",
        f"Mode: {cfg.mode.upper()}   Evidence window: last {cfg.lookback_minutes} min of '{event_type}' events",
        "",
        "Top sources:",
    ]
    lines += [f"  {o['ip']:<18} {o['events']} event(s)" for o in offenders[:10]] or ["  (none found)"]
    lines += ["", "Actions taken:"]
    lines += [f"  {a['ip']:<18} {a['status']}" + (f" (NACL rule {a['rule_number']})" if a.get("rule_number") else "")
              + (f" - {a['reason']}" if a.get("reason") else "") for a in actions] or ["  none"]
    if any(a["status"] == "blocked" for a in actions):
        lines += ["", f"Blocks expire automatically after {cfg.block_minutes} minutes.",
                  f"Unblock early: aws ec2 delete-network-acl-entry --network-acl-id {cfg.nacl_id} --ingress --rule-number <N>"]
    lines += ["", "Investigate: CloudWatch > Logs Insights > saved queries 'top_source_ips' and 'deployment_timeline'."]
    return "\n".join(lines)


# --------------------------------------------------------------------------- entry point
def handle(event: dict, cfg: Config, logs_client, ec2_client, table, sns_client) -> dict:
    if event.get("action") == "expire":
        released = expire_blocks(ec2_client, table, cfg)
        return {"expired": released}

    detail = event.get("detail", {})
    alarm_name = detail.get("alarmName", "")
    state = detail.get("state", {}).get("value")
    if state != "ALARM":
        return {"skipped": f"state is {state}"}

    event_type = event_type_for_alarm(alarm_name, cfg.alarm_event_types)
    if not event_type:
        return {"skipped": f"no response configured for {alarm_name}"}

    offenders = find_offenders(logs_client, cfg, event_type)
    actions = []
    for offender in offenders[: cfg.max_blocks]:
        ok, why = blockable(offender["ip"], cfg)
        if not ok:
            actions.append({"ip": offender["ip"], "status": "skipped", "reason": why})
        elif cfg.mode != "block":
            actions.append({"ip": offender["ip"], "status": "would_block", "reason": "notify-only mode"})
        else:
            actions.append(block_ip(ec2_client, table, cfg, offender["ip"], reason=alarm_name))

    for action in actions:
        log("response", alarm=alarm_name, **action)

    sns_client.publish(
        TopicArn=cfg.topic_arn,
        Subject=f"[AUTO-RESPONSE] {alarm_name}: {sum(a['status'] == 'blocked' for a in actions)} IP(s) blocked"[:100],
        Message=build_summary(alarm_name, event_type, offenders, actions, cfg),
    )
    return {"alarm": alarm_name, "offenders": offenders, "actions": actions}


def lambda_handler(event, context):  # pragma: no cover - thin AWS wiring
    cfg = Config()
    return handle(
        event, cfg,
        logs_client=boto3.client("logs"),
        ec2_client=boto3.client("ec2"),
        table=boto3.resource("dynamodb").Table(cfg.table),
        sns_client=boto3.client("sns"),
    )
