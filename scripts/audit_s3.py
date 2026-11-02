import sys

import boto3
from botocore.exceptions import ClientError

ENDPOINT = "http://localhost:4566"
s3 = boto3.client("s3", endpoint_url=ENDPOINT)


def finding(resource, check, severity, message):
    return {"resource": resource, "check": check, "severity": severity, "message": message}


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
    status = s3.get_bucket_versioning(Bucket=name).get("Status")
    if status != "Enabled":
        return [finding(name, "versioning", "LOW", "Versioning is not enabled")]
    return []


CHECKS = [check_public_access_block, check_encryption, check_versioning]


def main():
    buckets = [b["Name"] for b in s3.list_buckets()["Buckets"]]
    findings = []
    for name in buckets:
        for check in CHECKS:
            findings.extend(check(name))

    for f in findings:
        print(f"{f['severity']:<7} {f['resource']:<16} {f['check']:<20} {f['message']}")

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] += 1
    print(f"\nChecked {len(buckets)} buckets: "
          f"{counts['HIGH']} high, {counts['MEDIUM']} medium, {counts['LOW']} low")

    sys.exit(1 if counts["HIGH"] else 0)


if __name__ == "__main__":
    main()