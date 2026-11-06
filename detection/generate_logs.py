import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

USERS = ["alice", "bob", "carol", "deploy"]
NORMAL_IPS = ["198.51.100.10", "198.51.100.11", "198.51.100.12"]
ATTACKER_IP = "203.0.113.50"
START = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)


def stamp(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def ssh_line(rng, ts, ok, user, ip, invalid=False):
    pid = rng.randint(1000, 9999)
    port = rng.randint(30000, 60000)
    if ok:
        msg = f"Accepted password for {user} from {ip} port {port} ssh2"
    elif invalid:
        msg = f"Failed password for invalid user {user} from {ip} port {port} ssh2"
    else:
        msg = f"Failed password for {user} from {ip} port {port} ssh2"
    return f"{stamp(ts)} web01 sshd[{pid}]: {msg}"


def cloud_event(ts, name, user, ip, params=None):
    return {
        "eventTime": stamp(ts),
        "eventName": name,
        "userIdentity": {"userName": user},
        "sourceIPAddress": ip,
        "requestParameters": params or {},
    }


def generate(attack, seed):
    rng = random.Random(seed)
    ssh, cloud = [], []

    # Normal day: logins with the occasional single typo
    for _ in range(40):
        ts = START + timedelta(minutes=rng.randint(0, 480), seconds=rng.randint(0, 59))
        user, ip = rng.choice(USERS), rng.choice(NORMAL_IPS)
        if rng.random() < 0.1:
            ssh.append((ts, ssh_line(rng, ts, False, user, ip)))
            ts = ts + timedelta(seconds=rng.randint(5, 20))
        ssh.append((ts, ssh_line(rng, ts, True, user, ip)))

    # Normal cloud activity
    for _ in range(15):
        ts = START + timedelta(minutes=rng.randint(0, 480), seconds=rng.randint(0, 59))
        name = rng.choice(["ListBuckets", "GetObject", "DescribeInstances"])
        cloud.append((ts, cloud_event(ts, name, rng.choice(USERS), rng.choice(NORMAL_IPS))))

    if attack:
        t0 = START + timedelta(hours=5)
        # Brute force: 12 failures in about 35 seconds, then a success
        for n in range(12):
            ts = t0 + timedelta(seconds=n * 3)
            user = rng.choice(["root", "admin", "test", "oracle"])
            ssh.append((ts, ssh_line(rng, ts, False, user, ATTACKER_IP, invalid=True)))
        ts = t0 + timedelta(seconds=45)
        ssh.append((ts, ssh_line(rng, ts, True, "deploy", ATTACKER_IP)))

        # Risky cloud changes by the same account and address (used on Day 18)
        steps = [
            (2, "DeleteBucketPublicAccessBlock", {"bucketName": "my-homelab-logs-bucket"}),
            (3, "PutBucketPolicy", {"bucketName": "my-homelab-logs-bucket"}),
            (4, "StopLogging", {"name": "main-trail"}),
        ]
        for minutes, name, params in steps:
            ts = t0 + timedelta(minutes=minutes)
            cloud.append((ts, cloud_event(ts, name, "deploy", ATTACKER_IP, params)))

    ssh.sort(key=lambda pair: pair[0])
    cloud.sort(key=lambda pair: pair[0])
    return [line for _, line in ssh], [event for _, event in cloud]


def main():
    parser = argparse.ArgumentParser(description="Generate fake logs for detection practice")
    parser.add_argument("--attack", action="store_true", help="Inject the attack scenario")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--out", required=True, help="Output folder")
    args = parser.parse_args()

    ssh, cloud = generate(args.attack, args.seed)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "auth.log").write_text("\n".join(ssh) + "\n", encoding="utf-8")
    with open(out / "cloudtrail.jsonl", "w", encoding="utf-8") as f:
        for event in cloud:
            f.write(json.dumps(event) + "\n")
    print(f"Wrote {len(ssh)} SSH lines and {len(cloud)} cloud events to {out}")


if __name__ == "__main__":
    main()