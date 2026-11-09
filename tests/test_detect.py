import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import detect
import generate_logs

RULES = detect.load_rules(Path(__file__).resolve().parent.parent / "detection" / "rules")
T0 = datetime(2026, 1, 15, 14, 0, 0, tzinfo=timezone.utc)
ATTACKER = "203.0.113.50"


def auth_events(lines):
    parsed = [detect.parse_auth_line(line) for line in lines]
    assert None not in parsed
    return sorted(parsed, key=lambda e: e["time"])


def cloud_events(raws):
    parsed = [detect.parse_cloud_event(raw) for raw in raws]
    assert None not in parsed
    return parsed


def run(attack):
    lines, raws = generate_logs.generate(attack, 1)
    return detect.run_detection(auth_events(lines), RULES, cloud_events(raws))


def ids(alerts):
    return [a["rule_id"] for a in alerts]


def failures(ip, count, gap_seconds):
    rng = random.Random(0)
    return [
        generate_logs.ssh_line(rng, T0 + timedelta(seconds=i * gap_seconds), False, "alice", ip)
        for i in range(count)
    ]


def success(ip, offset_seconds):
    rng = random.Random(0)
    return generate_logs.ssh_line(rng, T0 + timedelta(seconds=offset_seconds), True, "deploy", ip)


def stop_logging(ip):
    return generate_logs.cloud_event(
        T0 + timedelta(minutes=2), "StopLogging", "deploy", ip, {"name": "main-trail"}
    )


# ---------- The main known-good and known-bad checks ----------

def test_clean_day_has_no_alerts():
    assert run(False) == []


def test_attack_day_triggers_every_expected_rule():
    assert set(ids(run(True))) == {
        "ssh-bruteforce",
        "ssh-success-after-failures",
        "cloud-public-access-block-removed",
        "cloud-bucket-policy-changed",
        "cloud-logging-disabled",
        "correlation-ssh-then-cloud",
    }


def test_all_attack_alerts_come_from_the_attacker_address():
    assert {a["source"] for a in run(True)} == {ATTACKER}


def test_generated_logs_are_fully_parseable():
    lines, raws = generate_logs.generate(True, 1)
    auth_events(lines)
    cloud_events(raws)


# ---------- Brute force rule ----------

def test_fast_bruteforce_is_detected():
    alerts = detect.run_detection(auth_events(failures("203.0.113.77", 6, 5)), RULES)
    assert "ssh-bruteforce" in ids(alerts)


def test_threshold_alerts_once_per_address():
    alerts = detect.run_detection(auth_events(failures("203.0.113.77", 30, 2)), RULES)
    assert ids(alerts).count("ssh-bruteforce") == 1


def test_two_attackers_are_alerted_separately():
    lines = failures("203.0.113.77", 6, 2) + failures("203.0.113.78", 6, 2)
    alerts = detect.run_detection(auth_events(lines), RULES)
    assert {a["source"] for a in alerts if a["rule_id"] == "ssh-bruteforce"} == {
        "203.0.113.77",
        "203.0.113.78",
    }


def test_slow_bruteforce_evades_the_threshold():
    # Documents a known limitation: one attempt a minute never reaches 5 in 120 s.
    alerts = detect.run_detection(auth_events(failures("203.0.113.77", 20, 60)), RULES)
    assert alerts == []


# ---------- Success-after-failures rule ----------

def test_few_failures_before_success_is_not_flagged():
    lines = failures("198.51.100.10", 2, 5) + [success("198.51.100.10", 30)]
    assert detect.run_detection(auth_events(lines), RULES) == []


# ---------- Correlation rule ----------

def test_correlation_fires_for_the_same_address():
    lines = failures(ATTACKER, 6, 3) + [success(ATTACKER, 40)]
    alerts = detect.run_detection(auth_events(lines), RULES, cloud_events([stop_logging(ATTACKER)]))
    assert "correlation-ssh-then-cloud" in ids(alerts)


def test_correlation_ignores_a_different_address():
    lines = failures(ATTACKER, 6, 3) + [success(ATTACKER, 40)]
    alerts = detect.run_detection(
        auth_events(lines), RULES, cloud_events([stop_logging("198.51.100.99")])
    )
    assert "cloud-logging-disabled" in ids(alerts)
    assert "correlation-ssh-then-cloud" not in ids(alerts)


# ---------- Parsing and safety ----------

def test_invalid_user_line_is_parsed():
    line = ("2026-01-15T14:00:00Z web01 sshd[1234]: "
            "Failed password for invalid user admin from 203.0.113.50 port 40000 ssh2")
    event = detect.parse_auth_line(line)
    assert event["user"] == "admin"
    assert event["outcome"] == "failure"
    assert event["ip"] == "203.0.113.50"


def test_unparseable_auth_lines_are_counted(tmp_path):
    good = generate_logs.ssh_line(random.Random(0), T0, True, "alice", "198.51.100.10")
    path = tmp_path / "auth.log"
    path.write_text("garbage line\n" + good + "\n", encoding="utf-8")
    events, skipped = detect.load_events(path)
    assert len(events) == 1
    assert skipped == 1


def test_malformed_cloud_lines_are_counted(tmp_path):
    path = tmp_path / "cloudtrail.jsonl"
    path.write_text('{"not": "an event"}\nnot json\n', encoding="utf-8")
    events, skipped = detect.load_cloud_events(path)
    assert events == []
    assert skipped == 2


def test_unknown_rule_type_raises_an_error():
    with pytest.raises(ValueError):
        detect.run_detection([], [{"id": "typo-rule", "type": "treshold"}])