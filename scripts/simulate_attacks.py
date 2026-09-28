"""Generate attack-like traffic against YOUR OWN deployment to test the detections.

Usage:
    python scripts/simulate_attacks.py http://<task-public-ip>:8000

Only run this against infrastructure you own. The payloads are harmless probes -
the API never executes them - but they look malicious to the detection rules,
which is exactly what we want to verify.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PROBES = {
    "SQL injection": "/api/items?search=" + urllib.parse.quote("' OR '1'='1"),
    "SQL injection (UNION)": "/api/items?id=" + urllib.parse.quote("1 UNION SELECT username, password FROM users"),
    "Cross-site scripting": "/api/items?q=" + urllib.parse.quote("<script>alert(document.cookie)</script>"),
    "Path traversal": "/api/items?file=" + urllib.parse.quote("../../../../etc/passwd"),
    "Command injection": "/api/items?host=" + urllib.parse.quote("127.0.0.1; cat /etc/passwd"),
}


def request(base: str, path: str, method: str = "GET", body: dict | None = None) -> int:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method,
                                 headers={"Content-Type": "application/json", "User-Agent": "appsec-attack-simulator/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1].startswith(("http://", "https://")):
        print(__doc__)
        return 2
    base = sys.argv[1].rstrip("/")

    print(f"Target: {base}\n")
    print(f"[health] {request(base, '/health')}")

    print("\n1) Injection probes -> expect 'injection_attempt' alarm")
    for name, path in PROBES.items():
        print(f"   {name:<24} HTTP {request(base, path)}")

    print("\n2) Brute-force login (12 bad passwords) -> expect 'brute_force' and 'auth_failure_spike' alarms")
    for i in range(12):
        code = request(base, "/api/login", "POST", {"username": "analyst", "password": f"Winter2026!{i}"})
        print(f"   attempt {i + 1:>2}: HTTP {code}")
        time.sleep(0.2)

    print("\n3) Request flood (150 requests) -> expect 'rate_limited' alarm")
    codes: dict[int, int] = {}
    for _ in range(150):
        code = request(base, "/api/items")
        codes[code] = codes.get(code, 0) + 1
    print(f"   status codes: {codes}")

    print("\nDone. Alarms evaluate over 5-minute windows - check your email and the CloudWatch")
    print("Alarms console in ~5 minutes, then investigate with the saved Logs Insights queries.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
