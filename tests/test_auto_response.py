"""Tests for the automated response Lambda using in-memory fakes (no AWS needed)."""

import json
import sys
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lambda" / "auto_response"))
import handler as ar  # noqa: E402

NACL = "acl-123"


class FakeLogs:
    def __init__(self, rows):
        self.rows = rows
        self.queries = []

    def start_query(self, **kwargs):
        self.queries.append(kwargs)
        return {"queryId": "q-1"}

    def get_query_results(self, queryId):
        return {"status": "Complete", "results": [
            [{"field": "src_ip", "value": ip}, {"field": "events", "value": str(n)}] for ip, n in self.rows
        ]}


class FakeEc2:
    def __init__(self, entries=None):
        self.entries = entries or [
            {"RuleNumber": 100, "Egress": False, "RuleAction": "allow", "CidrBlock": "0.0.0.0/0"},
            {"RuleNumber": 32767, "Egress": False, "RuleAction": "deny", "CidrBlock": "0.0.0.0/0"},
        ]

    def describe_network_acls(self, NetworkAclIds):
        return {"NetworkAcls": [{"Entries": list(self.entries)}]}

    def create_network_acl_entry(self, NetworkAclId, RuleNumber, Protocol, RuleAction, Egress, CidrBlock):
        assert NetworkAclId == NACL and RuleAction == "deny" and not Egress
        self.entries.append({"RuleNumber": RuleNumber, "Egress": Egress, "RuleAction": RuleAction, "CidrBlock": CidrBlock})

    def delete_network_acl_entry(self, NetworkAclId, RuleNumber, Egress):
        before = len(self.entries)
        self.entries = [e for e in self.entries if not (e["RuleNumber"] == RuleNumber and e["Egress"] == Egress)]
        if len(self.entries) == before:
            raise ClientError({"Error": {"Code": "InvalidNetworkAclEntry.NotFound"}}, "DeleteNetworkAclEntry")

    def denies(self):
        return {e["CidrBlock"]: e["RuleNumber"] for e in self.entries if e["RuleAction"] == "deny" and e["RuleNumber"] < 100}


class FakeTable:
    def __init__(self):
        self.items = {}

    def put_item(self, Item):
        self.items[Item["ip"]] = Item

    def scan(self):
        return {"Items": list(self.items.values())}

    def delete_item(self, Key):
        self.items.pop(Key["ip"], None)


class FakeSns:
    def __init__(self):
        self.messages = []

    def publish(self, **kwargs):
        self.messages.append(kwargs)


def make_cfg(**overrides):
    env = {
        "APP_LOG_GROUP": "/ecs/appsec-api", "NACL_ID": NACL, "BLOCKLIST_TABLE": "t",
        "ALERT_TOPIC_ARN": "arn:aws:sns:us-east-1:1:alerts", "RESPONSE_MODE": "block",
        "BLOCK_MINUTES": "60", "NEVER_BLOCK_CIDRS": json.dumps(["93.184.100.0/24"]),
    }
    env.update(overrides)
    return ar.Config(env)


def alarm_event(name="appsec-api-brute_force", state="ALARM"):
    return {"detail-type": "CloudWatch Alarm State Change",
            "detail": {"alarmName": name, "state": {"value": state}}}


@pytest.fixture
def aws():
    return {"ec2": FakeEc2(), "table": FakeTable(), "sns": FakeSns()}


def run(event, cfg, aws, rows=()):
    logs = FakeLogs(rows)
    result = ar.handle(event, cfg, logs, aws["ec2"], aws["table"], aws["sns"])
    return result, logs


def test_brute_force_alarm_blocks_top_public_ip(aws):
    result, logs = run(alarm_event(), make_cfg(), aws, rows=[("44.201.113.9", 7)])
    assert aws["ec2"].denies() == {"44.201.113.9/32": 1}
    assert aws["table"].items["44.201.113.9"]["rule_number"] == 1
    assert result["actions"][0]["status"] == "blocked"
    assert 'event_type = "brute_force_suspected"' in logs.queries[0]["queryString"]
    msg = aws["sns"].messages[0]
    assert "1 IP(s) blocked" in msg["Subject"] and "44.201.113.9" in msg["Message"]


def test_injection_alarm_queries_suspicious_input(aws):
    _, logs = run(alarm_event("appsec-api-injection_attempt"), make_cfg(), aws, rows=[("44.201.113.5", 3)])
    assert 'event_type = "suspicious_input"' in logs.queries[0]["queryString"]


def test_private_and_allowlisted_ips_are_never_blocked(aws):
    rows = [("10.0.0.5", 50), ("93.184.100.7", 40), ("not-an-ip", 1)]
    result, _ = run(alarm_event(), make_cfg(), aws, rows=rows)
    assert aws["ec2"].denies() == {}
    reasons = {a["ip"]: a["reason"] for a in result["actions"]}
    assert reasons["10.0.0.5"] == "private or reserved address"
    assert reasons["93.184.100.7"] == "on the never-block list"
    assert reasons["not-an-ip"] == "not a valid IP address"


def test_notify_mode_does_not_block(aws):
    result, _ = run(alarm_event(), make_cfg(RESPONSE_MODE="notify"), aws, rows=[("44.201.113.9", 7)])
    assert aws["ec2"].denies() == {}
    assert result["actions"][0]["status"] == "would_block"
    assert "0 IP(s) blocked" in aws["sns"].messages[0]["Subject"]


def test_blocking_is_idempotent(aws):
    run(alarm_event(), make_cfg(), aws, rows=[("44.201.113.9", 7)])
    result, _ = run(alarm_event(), make_cfg(), aws, rows=[("44.201.113.9", 9)])
    assert result["actions"][0]["status"] == "already_blocked"
    assert len(aws["ec2"].denies()) == 1


def test_uses_next_free_rule_number(aws):
    aws["ec2"].entries.append({"RuleNumber": 1, "Egress": False, "RuleAction": "deny", "CidrBlock": "192.0.2.1/32"})
    run(alarm_event(), make_cfg(), aws, rows=[("44.201.113.9", 7)])
    assert aws["ec2"].denies()["44.201.113.9/32"] == 2


def test_max_blocks_per_alarm(aws):
    rows = [(f"44.201.113.{i}", 10 - i) for i in range(1, 9)]
    result, _ = run(alarm_event(), make_cfg(MAX_BLOCKS_PER_ALARM="3"), aws, rows=rows)
    assert len(result["actions"]) == 3 and len(aws["ec2"].denies()) == 3


def test_ok_state_and_unknown_alarms_are_ignored(aws):
    assert "skipped" in run(alarm_event(state="OK"), make_cfg(), aws)[0]
    assert "skipped" in run(alarm_event("appsec-api-server_errors"), make_cfg(), aws)[0]
    assert aws["sns"].messages == []


def test_expired_blocks_are_removed(aws):
    cfg = make_cfg()
    ar.block_ip(aws["ec2"], aws["table"], cfg, "44.201.113.9", "test", now=1_000)
    ar.block_ip(aws["ec2"], aws["table"], cfg, "44.201.113.10", "test", now=10_000)
    released = ar.expire_blocks(aws["ec2"], aws["table"], cfg, now=1_000 + 3600 + 1)
    assert [r["ip"] for r in released] == ["44.201.113.9"]
    assert list(aws["ec2"].denies()) == ["44.201.113.10/32"]
    assert list(aws["table"].items) == ["44.201.113.10"]


def test_expire_tolerates_rule_already_removed(aws):
    cfg = make_cfg()
    ar.block_ip(aws["ec2"], aws["table"], cfg, "44.201.113.9", "test", now=0)
    aws["ec2"].entries = [e for e in aws["ec2"].entries if e["RuleNumber"] != 1]  # someone unblocked manually
    released = ar.expire_blocks(aws["ec2"], aws["table"], cfg, now=10_000)
    assert released and aws["table"].items == {}


def test_expire_action_via_handler(aws):
    cfg = make_cfg(BLOCK_MINUTES="0")
    run(alarm_event(), cfg, aws, rows=[("44.201.113.9", 7)])
    result, _ = run({"action": "expire"}, cfg, aws)
    assert result["expired"][0]["ip"] == "44.201.113.9"


def test_documentation_ranges_are_treated_as_reserved(aws):
    # 203.0.113.0/24 is reserved for documentation - it can never be a real attacker.
    result, _ = run(alarm_event(), make_cfg(), aws, rows=[("203.0.113.9", 7)])
    assert result["actions"][0]["reason"] == "private or reserved address"
    assert aws["ec2"].denies() == {}
