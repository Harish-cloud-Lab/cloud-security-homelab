import argparse
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


def parse_auth_line(line):
    m = AUTH_LINE.match(line.strip())
    if not m:
        return None
    return {
        "time": datetime.fromisoformat(m["ts"].replace("Z", "+00:00")),
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


def load_rules(folder):
    rules = []
    for path in sorted(Path(folder).glob("*.yml")):
        rules.append(yaml.safe_load(path.read_text(encoding="utf-8")))
    return rules


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


DETECTORS = {
    "threshold": detect_threshold,
    "success_after_failures": detect_success_after_failures,
}


def run_detection(events, rules):
    alerts = []
    for rule in rules:
        alerts.extend(DETECTORS[rule["type"]](events, rule))
    alerts.sort(key=lambda a: a["time"])
    return alerts


def main():
    parser = argparse.ArgumentParser(description="Run detection rules against logs")
    parser.add_argument("--auth", required=True, help="Path to auth.log")
    parser.add_argument("--rules", default="detection/rules", help="Folder of rule files")
    args = parser.parse_args()

    events, skipped = load_events(args.auth)
    rules = load_rules(args.rules)
    alerts = run_detection(events, rules)

    print(f"Parsed {len(events)} lines, skipped {skipped}, {len(rules)} rules loaded")
    for a in alerts:
        print(f"{a['severity']:<9} {a['time']} {a['source']:<15} {a['title']} - {a['detail']}")
    print(f"\n{len(alerts)} alerts")
    sys.exit(1 if alerts else 0)


if __name__ == "__main__":
    main()