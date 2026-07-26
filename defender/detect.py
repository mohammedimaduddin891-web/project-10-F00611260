#!/usr/bin/env python3
"""detect.py — extended deterministic detector for auth.log (Project 10).

Builds on the Chapter 10 baseline (triage_logins.py). Keeps all five baseline
rules and adds four new ones that catch stages the baseline missed or only
caught by accident (mislabeled as a geo violation).

    python3 detect.py auth.log

New vs. the baseline:
  Rule 6  impossible travel        (names the stolen-account delivery step)
  Rule 7  MFA fatigue / push-bomb  (baseline caught this only as "non-home geo")
  Rule 8  bulk data read           (the collection step — MISSED by the baseline)
  Rule 9  lateral movement         (internal SSH pivot after external compromise)
"""
import sys
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta

HOME_GEO = "US-IL"
INTERNAL_GEO = "INT"
OFFHOURS = range(0, 6)
SPRAY_WINDOW_S = 300
SPRAY_THRESHOLD = 3
BULK_ROW_THRESHOLD = 1000
SVC_ALLOWLIST = {"svc_bkp"}


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


def _rows_parsed(rows):
    m = re.search(r"\(?\s*([\d.]+)\s*([kKmM]?)\s*rows?\b", rows["note"])
    if not m:
        return None
    val = float(m.group(1))
    mult = {"k": 1_000, "m": 1_000_000}.get(m.group(2).lower(), 1)
    return int(val * mult)


def detect(rows):
    findings = []
    deny_times = defaultdict(deque)
    sprayed = set()
    compromised_ips = set()

    for r in rows:
        when = datetime.fromisoformat(r["ts"].replace("Z", "+00:00"))
        note = r["note"]

        # Rule 1 (baseline, now WINDOWED): failed-auth burst
        if r["result"] == "deny" and r["user"] not in SVC_ALLOWLIST:
            dq = deny_times[r["user"]]
            dq.append(when)
            while dq and (when - dq[0]) > timedelta(seconds=SPRAY_WINDOW_S):
                dq.popleft()
            if len(dq) >= SPRAY_THRESHOLD and r["user"] not in sprayed:
                sprayed.add(r["user"])
                compromised_ips.add(r["srcip"])
                findings.append((r, f"burst of {len(dq)} denied auths in "
                                    f"{SPRAY_WINDOW_S}s (password spray / brute force)"))

        # Rule 2 (baseline): success from outside home geography
        if r["result"] == "ok" and r["geo"] not in (HOME_GEO, INTERNAL_GEO):
            compromised_ips.add(r["srcip"])
            findings.append((r, f"successful login from non-home geo {r['geo']}"))

        # Rule 3 (baseline): off-hours privileged action
        if r["svc"] == "sudo" and when.hour in OFFHOURS:
            findings.append((r, "off-hours privilege escalation"))

        # Rule 4 (baseline): privilege escalation, no change ticket
        if r["svc"] == "sudo" and "NO change ticket" in note:
            findings.append((r, "sudo privilege escalation without a change ticket"))

        # Rule 5 (baseline): egress to a hostile IP (exfil)
        if "exfil" in note or "egress to 203.0.113" in note:
            findings.append((r, "possible data exfiltration to attacker IP"))

        # NEW RULE 6: impossible travel (ATT&CK T1078)
        if "impossible travel" in note.lower():
            compromised_ips.add(r["srcip"])
            findings.append((r, "impossible-travel login (stolen valid account, T1078)"))

        # NEW RULE 7: MFA fatigue / push bombing
        if r["result"] == "ok" and re.search(r"mfa fatigue|push bomb|\d+(st|nd|rd|th)\s+push",
                                              note, re.IGNORECASE):
            findings.append((r, "MFA-fatigue success (push bombing defeated plain-push MFA)"))

        # NEW RULE 8: bulk data read (COLLECTION, ATT&CK T1005) — baseline missed this
        n = _rows_parsed(r)
        if r["result"] == "ok" and n is not None and n >= BULK_ROW_THRESHOLD:
            findings.append((r, f"bulk data read: {n:,} rows in one query "
                                f"(collection / staging for exfil, T1005)"))

        # NEW RULE 9: lateral movement (ATT&CK T1021)
        if (r["svc"] == "sshd" and r["result"] == "ok"
                and (r["srcip"] in compromised_ips or "lateral move" in note.lower())):
            findings.append((r, "lateral movement over internal network (T1021)"))

    return findings


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "auth.log"
    hits = detect(parse(path))
    if not hits:
        print("No findings. (Did you point at the right file?)")
        return
    for r, why in hits:
        print(f"[FLAG] {r['ts']} {r['user']:>8}@{r['host']:<4} <{r['srcip']}> -- {why}")
    print(f"\n{len(hits)} finding(s) across the chain. "
          f"Now: which are TRUE positives? You decide.")


if __name__ == "__main__":
    main()
