import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

DEFAULT_ENDPOINT = "http://localhost:4566"
PUBLIC_ACL_GROUPS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "SQL Server",
    27017: "MongoDB",
    6379: "Redis",
}
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def finding(resource, check, severity, message):
    return {"resource": resource, "check": check, "severity": severity, "message": message}


def as_list(value):
    return [value] if isinstance(value, str) else list(value)


# ---------- S3 checks ----------

def check_public_access_block(s3, name):
    try:
        cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return [finding(name, "public-access-block", "HIGH", "No public access block configured")]
        raise
    if not (len(cfg) == 4 and all(cfg.values())):
        return [finding(name, "public-access-block", "HIGH", "Public access block is incomplete")]
    return []


def check_encryption(s3, name):
    try:
        s3.get_bucket_encryption(Bucket=name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            return [finding(name, "encryption", "MEDIUM", "No default encryption configured")]
        raise
    return []


def check_versioning(s3, name):
    if s3.get_bucket_versioning(Bucket=name).get("Status") != "Enabled":
        return [finding(name, "versioning", "LOW", "Versioning is not enabled")]
    return []


def check_bucket_policy(s3, name):
    try:
        raw = s3.get_bucket_policy(Bucket=name)["Policy"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            return []
        raise
    results = []
    for stmt in json.loads(raw).get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        if isinstance(principal, dict):
            everyone = "*" in as_list(principal.get("AWS", []))
        else:
            everyone = principal == "*"
        if everyone and "Condition" not in stmt:
            sid = stmt.get("Sid", "unnamed")
            results.append(
                finding(name, "bucket-policy", "HIGH", f"Policy statement '{sid}' allows everyone")
            )
    return results


def check_bucket_acl(s3, name):
    results = []
    for grant in s3.get_bucket_acl(Bucket=name)["Grants"]:
        uri = grant.get("Grantee", {}).get("URI")
        if uri in PUBLIC_ACL_GROUPS:
            who = uri.rsplit("/", 1)[-1]
            results.append(
                finding(name, "bucket-acl", "HIGH", f"ACL grants {grant['Permission']} to {who}")
            )
    return results


BUCKET_CHECKS = [
    check_public_access_block,
    check_encryption,
    check_versioning,
    check_bucket_policy,
    check_bucket_acl,
]


# ---------- Security group checks ----------

def open_to_world(rule):
    v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))
    v6 = any(r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", []))
    return v4 or v6


def check_security_groups(ec2):
    results = []
    for sg in ec2.describe_security_groups()["SecurityGroups"]:
        name = sg["GroupName"]
        for rule in sg.get("IpPermissions", []):
            if not open_to_world(rule):
                continue
            if rule.get("IpProtocol") == "-1":
                results.append(
                    finding(name, "sg-open-ingress", "HIGH", "All traffic open to the internet")
                )
                continue
            low, high = rule.get("FromPort"), rule.get("ToPort")
            if low is None or high is None:
                continue
            for port, label in SENSITIVE_PORTS.items():
                if low <= port <= high:
                    results.append(
                        finding(name, "sg-open-ingress", "HIGH",
                                f"{label} (port {port}) open to the internet")
                    )
    return results


# ---------- Run and report ----------

def run_audit(s3, ec2):
    buckets = [b["Name"] for b in s3.list_buckets()["Buckets"]]
    findings = []
    for name in buckets:
        for check in BUCKET_CHECKS:
            findings.extend(check(s3, name))
    findings.extend(check_security_groups(ec2))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["resource"]))
    return buckets, findings


def summarize(findings):
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] += 1
    return counts


def write_reports(buckets, findings, counts, outdir):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    data = {
        "generated": stamp,
        "buckets_checked": len(buckets),
        "summary": counts,
        "findings": findings,
    }
    (outdir / "audit-report.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

    lines = [
        "# Cloud security audit report",
        "",
        f"Generated: {stamp}",
        "",
        f"Buckets checked: {len(buckets)}",
        "",
        f"Summary: {counts['HIGH']} high, {counts['MEDIUM']} medium, {counts['LOW']} low",
        "",
    ]
    if findings:
        lines += ["| Severity | Resource | Check | Finding |", "|---|---|---|---|"]
        for f in findings:
            lines.append(f"| {f['severity']} | {f['resource']} | {f['check']} | {f['message']} |")
    else:
        lines.append("No findings.")
    (outdir / "audit-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Read-only audit of S3 buckets and security groups")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT,
                        help="Endpoint of the fake AWS server (default: local Moto)")
    parser.add_argument("--real-aws", action="store_true",
                        help="Use real AWS instead of the local fake server")
    parser.add_argument("--report-dir", default="reports", help="Where to write the reports")
    args = parser.parse_args()

    endpoint = None if args.real_aws else args.endpoint
    s3 = boto3.client("s3", endpoint_url=endpoint)
    ec2 = boto3.client("ec2", endpoint_url=endpoint)

    buckets, findings = run_audit(s3, ec2)
    counts = summarize(findings)

    for f in findings:
        print(f"{f['severity']:<7} {f['resource']:<18} {f['check']:<20} {f['message']}")
    print(f"\nChecked {len(buckets)} buckets and the security groups: "
          f"{counts['HIGH']} high, {counts['MEDIUM']} medium, {counts['LOW']} low")

    write_reports(buckets, findings, counts, args.report_dir)
    print(f"Reports written to {args.report_dir}/")

    sys.exit(1 if counts["HIGH"] else 0)


if __name__ == "__main__":
    main()