import json
import sys

import boto3
from botocore.exceptions import ClientError

ENDPOINT = "http://localhost:4566"
s3 = boto3.client("s3", endpoint_url=ENDPOINT)
ec2 = boto3.client("ec2", endpoint_url=ENDPOINT)

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

def check_public_access_block(name):
    try:
        cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return [finding(name, "public-access-block", "HIGH", "No public access block configured")]
        raise
    if not (len(cfg) == 4 and all(cfg.values())):
        return [finding(name, "public-access-block", "HIGH", "Public access block is incomplete")]
    return []


def check_encryption(name):
    try:
        s3.get_bucket_encryption(Bucket=name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            return [finding(name, "encryption", "MEDIUM", "No default encryption configured")]
        raise
    return []


def check_versioning(name):
    if s3.get_bucket_versioning(Bucket=name).get("Status") != "Enabled":
        return [finding(name, "versioning", "LOW", "Versioning is not enabled")]
    return []


def check_bucket_policy(name):
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


def check_bucket_acl(name):
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


def check_security_groups():
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


# ---------- Run ----------

def main():
    buckets = [b["Name"] for b in s3.list_buckets()["Buckets"]]
    findings = []
    for name in buckets:
        for check in BUCKET_CHECKS:
            findings.extend(check(name))
    findings.extend(check_security_groups())

    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["resource"]))
    for f in findings:
        print(f"{f['severity']:<7} {f['resource']:<18} {f['check']:<20} {f['message']}")

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] += 1
    print(f"\nChecked {len(buckets)} buckets and the security groups: "
          f"{counts['HIGH']} high, {counts['MEDIUM']} medium, {counts['LOW']} low")

    sys.exit(1 if counts["HIGH"] else 0)


if __name__ == "__main__":
    main()