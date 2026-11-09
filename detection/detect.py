import argparse
import json
import re
import sys
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

import yaml

AUTH_LINE = re.compile(
    r"^(?P<ts>\S+) (?P<host>\S+) sshd\[\d+\]: "
    r"(?P<result>Accepted|Failed) password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port \d+"
)


def to_dt(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


# ---------- Loading ----------

def parse_auth_line(line):
    m = AUTH_LINE.match(line.strip())
    if not m:
        return None
    return {
        "time": to_dt(m["ts"]),
        "user": m["user"],
        "ip": m["ip"],
        "outcome": "success" if m["result"] == "Accepted" else "failure",
    }


def load_events(path):
    events, skipped = [], 0
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = parse_auth_line(line)
        if event:
            events.append(event)
        else:
            skipped += 1
    events.sort(key=lambda e: e["time"])
    return events, skipped


def parse_cloud_event(raw):
    try:
        return {
            "time": to_dt(raw["eventTime"]),
            "name": raw["eventName"],
            "user": raw.get("userIdentity", {}).get("userName", "unknown"),
            "ip": raw["sourceIPAddress"],
            "params": raw.get("requestParameters", {}),
        }
    except (KeyError, ValueError, AttributeError):
        return None


def load_cloud_events(path):
    events, skipped = [], 0
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            event = parse_cloud_event(json.loads(line))
        except json.JSONDecodeError:
            event = None
        if event:
            events.append(event)
        else:
            skipped += 1
    events.sort(key=lambda e: e["time"])
    return events, skipped


def load_rules(folder):
    return [yaml.safe_load(p.read_text(encoding="utf-8"))
            for p in sorted(Path(folder).glob("*.yml"))]


# ---------- Detectors ----------

def make_alert(rule, time, source, detail):
    return {
        "rule_id": rule["id"],
        "title": rule["title"],
        "severity": rule["severity"],
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": source,
        "detail": detail,
    }


def detect_threshold(events, rule):
    window = timedelta(seconds=rule["window_seconds"])
    recent = defaultdict(deque)
    alerted = set()
    alerts = []
    for e in events:
        if e["outcome"] != "failure":
            continue
        q = recent[e["ip"]]
        q.append(e["time"])
        while q and e["time"] - q[0] > window:
            q.popleft()
        if len(q) >= rule["threshold"] and e["ip"] not in alerted:
            alerted.add(e["ip"])
            detail = f"{len(q)} failed logins in {rule['window_seconds']}s"
            alerts.append(make_alert(rule, e["time"], e["ip"], detail))
    return alerts


def detect_success_after_failures(events, rule):
    window = timedelta(seconds=rule["window_seconds"])
    recent = defaultdict(deque)
    alerts = []
    for e in events:
        q = recent[e["ip"]]
        while q and e["time"] - q[0] > window:
            q.popleft()
        if e["outcome"] == "failure":
            q.append(e["time"])
        elif len(q) >= rule["failures"]:
            detail = f"successful login for '{e['user']}' after {len(q)} recent failures"
            alerts.append(make_alert(rule, e["time"], e["ip"], detail))
    return alerts


def detect_cloud_event(cloud_events, rule):
    alerts = []
    for e in cloud_events:
        if e["name"] in rule["event_names"]:
            resource = e["params"].get("bucketName") or e["params"].get("name") or "-"
            detail = f"{e['name']} by {e['user']} on {resource}"
            alerts.append(make_alert(rule, e["time"], e["ip"], detail))
    return alerts


def detect_correlation(base_alerts, rule):
    window = rule["window_seconds"]
    cloud_alerts = [a for a in base_alerts if a["rule_id"].startswith("cloud-")]
    alerts = []
    for first in (a for a in base_alerts if a["rule_id"] == rule["first_alert"]):
        start = to_dt(first["time"])
        hits = [
            c for c in cloud_alerts
            if c["source"] == first["source"]
            and 0 <= (to_dt(c["time"]) - start).total_seconds() <= window
        ]
        if hits:
            names = ", ".join(c["rule_id"] for c in hits)
            detail = f"{len(hits)} cloud change(s) within {window}s of the login: {names}"
            alerts.append(make_alert(rule, to_dt(hits[0]["time"]), first["source"], detail))
    return alerts


AUTH_DETECTORS = {
    "threshold": detect_threshold,
    "success_after_failures": detect_success_after_failures,
}


def run_detection(auth_events, rules, cloud_events=None):
    cloud_events = cloud_events or []
    alerts = []
    for rule in rules:
        kind = rule["type"]
        if kind in AUTH_DETECTORS:
            alerts.extend(AUTH_DETECTORS[kind](auth_events, rule))
        elif kind == "cloud_event":
            alerts.extend(detect_cloud_event(cloud_events, rule))
        elif kind == "correlation":
            continue  # handled after the base alerts exist
        else:
            raise ValueError(f"Unknown rule type '{kind}' in rule '{rule['id']}'")

    base = list(alerts)
    for rule in rules:
        if rule["type"] == "correlation":
            alerts.extend(detect_correlation(base, rule))

    alerts.sort(key=lambda a: a["time"])
    return alerts


# ---------- Command line ----------

def main():
    parser = argparse.ArgumentParser(description="Run detection rules against logs")
    parser.add_argument("--auth", required=True, help="Path to auth.log")
    parser.add_argument("--cloud", help="Path to cloudtrail.jsonl (optional)")
    parser.add_argument("--rules", default="detection/rules", help="Folder of rule files")
    args = parser.parse_args()

    auth, auth_skipped = load_events(args.auth)
    cloud, cloud_skipped = ([], 0)
    if args.cloud:
        cloud, cloud_skipped = load_cloud_events(args.cloud)
    rules = load_rules(args.rules)
    alerts = run_detection(auth, rules, cloud)

    print(f"Parsed {len(auth)} auth lines (skipped {auth_skipped}), "
          f"{len(cloud)} cloud events (skipped {cloud_skipped}), {len(rules)} rules loaded")
    for a in alerts:
        print(f"{a['severity']:<9} {a['time']} {a['source']:<15} {a['title']} - {a['detail']}")
    print(f"\n{len(alerts)} alerts")
    sys.exit(1 if alerts else 0)


if __name__ == "__main__":
    main()