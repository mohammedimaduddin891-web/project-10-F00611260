#!/usr/bin/env python3
"""triage_logins.py — a tiny, dumb, deterministic detector for auth.log.

Week 10, Chapter 10 (Security Operations). This is NOT an ML model and not an
AIOps agent. It is the *baseline you build by hand first* so that when an AI
SOC assistant flags the same chain, you can check its homework. Run:

    python3 triage_logins.py auth.log

Phase-2 rule: build this rule engine by hand BEFORE you ask an agent to write
one. Then compare. The human owns the verdict.
"""
import sys
from collections import defaultdict
from datetime import datetime

# Rules are intentionally simple and explainable. Each returns (matched, why).
HOME_GEO = "US-IL"          # the ministry's normal geography
OFFHOURS = range(0, 6)      # 00:00-05:59 UTC is suspicious for this org


def parse(path):
    rows = []
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 7)
        if len(parts) < 7:
            continue
        ts, host, svc, user, srcip, geo, result = parts[:7]
        note = parts[7] if len(parts) > 7 else ""
        rows.append(dict(ts=ts, host=host, svc=svc, user=user,
                         srcip=srcip, geo=geo, result=result, note=note))
    return rows


def detect(rows):
    findings = []
    fails = defaultdict(int)
    for r in rows:
        when = datetime.fromisoformat(r["ts"].replace("Z", "+00:00"))
        # Rule 1: failed auth bursts (spray / brute force)
        if r["result"] == "deny":
            fails[r["user"]] += 1
            if fails[r["user"]] >= 3:
                findings.append((r, "burst of denied auths (spray/brute force)"))
        # Rule 2: success from outside home geography
        if r["result"] == "ok" and r["geo"] not in (HOME_GEO, "INT"):
            findings.append((r, f"successful login from non-home geo {r['geo']}"))
        # Rule 3: off-hours privileged action
        if r["svc"] == "sudo" and when.hour in OFFHOURS:
            findings.append((r, "off-hours privilege escalation"))
        # Rule 4: privilege escalation with no change ticket
        if r["svc"] == "sudo" and "NO change ticket" in r["note"]:
            findings.append((r, "sudo without a change ticket"))
        # Rule 5: outbound to an external IP we just saw attacking us (exfil)
        if "exfil" in r["note"] or "egress to 203.0.113" in r["note"]:
            findings.append((r, "possible data exfiltration to attacker IP"))
    return findings


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "auth.log"
    hits = detect(parse(path))
    if not hits:
        print("No findings. (Did you point at the right file?)")
    for r, why in hits:
        print(f"[FLAG] {r['ts']} {r['user']}@{r['host']} <{r['srcip']}> -- {why}")
    print(f"\n{len(hits)} finding(s). Now: which are TRUE positives? You decide.")
