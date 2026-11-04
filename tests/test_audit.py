import json

import boto3
from moto import mock_aws

import audit

FULL_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}
ENCRYPTION = {
    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
}


def clients():
    return (
        boto3.client("s3", region_name="us-east-1"),
        boto3.client("ec2", region_name="us-east-1"),
    )


def make_good_bucket(s3, name="good-bucket"):
    s3.create_bucket(Bucket=name)
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=FULL_BLOCK)
    s3.put_bucket_encryption(Bucket=name, ServerSideEncryptionConfiguration=ENCRYPTION)
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})


def checks_for(findings, resource):
    return {f["check"] for f in findings if f["resource"] == resource}


def make_group(ec2, name, permissions):
    vpc_id = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    group_id = ec2.create_security_group(
        GroupName=name, Description=name, VpcId=vpc_id
    )["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=permissions)
    return group_id


def tcp(port, cidr):
    return {"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
            "IpRanges": [{"CidrIp": cidr}]}


@mock_aws
def test_good_bucket_has_no_findings():
    s3, ec2 = clients()
    make_good_bucket(s3)
    _, findings = audit.run_audit(s3, ec2)
    assert checks_for(findings, "good-bucket") == set()


@mock_aws
def test_missing_public_access_block_is_high():
    s3, ec2 = clients()
    s3.create_bucket(Bucket="weak-bucket")
    _, findings = audit.run_audit(s3, ec2)
    match = [f for f in findings
             if f["resource"] == "weak-bucket" and f["check"] == "public-access-block"]
    assert len(match) == 1
    assert match[0]["severity"] == "HIGH"


@mock_aws
def test_incomplete_public_access_block_is_flagged():
    s3, ec2 = clients()
    s3.create_bucket(Bucket="partial-bucket")
    s3.put_public_access_block(
        Bucket="partial-bucket",
        PublicAccessBlockConfiguration={**FULL_BLOCK, "BlockPublicPolicy": False},
    )
    _, findings = audit.run_audit(s3, ec2)
    assert "public-access-block" in checks_for(findings, "partial-bucket")


@mock_aws
def test_missing_versioning_is_low():
    s3, ec2 = clients()
    s3.create_bucket(Bucket="no-versioning")
    _, findings = audit.run_audit(s3, ec2)
    match = [f for f in findings
             if f["resource"] == "no-versioning" and f["check"] == "versioning"]
    assert len(match) == 1
    assert match[0]["severity"] == "LOW"


@mock_aws
def test_open_bucket_policy_is_flagged():
    s3, ec2 = clients()
    make_good_bucket(s3, "open-policy-bucket")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "PublicRead",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::open-policy-bucket/*",
        }],
    }
    s3.put_bucket_policy(Bucket="open-policy-bucket", Policy=json.dumps(policy))
    _, findings = audit.run_audit(s3, ec2)
    assert "bucket-policy" in checks_for(findings, "open-policy-bucket")


@mock_aws
def test_policy_with_condition_is_not_flagged():
    # Documents a known limitation: statements with a Condition are skipped.
    s3, ec2 = clients()
    make_good_bucket(s3, "conditional-bucket")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::conditional-bucket/*",
            "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
        }],
    }
    s3.put_bucket_policy(Bucket="conditional-bucket", Policy=json.dumps(policy))
    _, findings = audit.run_audit(s3, ec2)
    assert "bucket-policy" not in checks_for(findings, "conditional-bucket")


@mock_aws
def test_public_acl_is_flagged():
    s3, ec2 = clients()
    s3.create_bucket(Bucket="public-acl-bucket")
    s3.put_bucket_acl(Bucket="public-acl-bucket", ACL="public-read")
    _, findings = audit.run_audit(s3, ec2)
    assert "bucket-acl" in checks_for(findings, "public-acl-bucket")


@mock_aws
def test_risky_security_group_flags_ssh_and_mysql():
    s3, ec2 = clients()
    make_group(ec2, "risky-sg", [tcp(22, "0.0.0.0/0"), tcp(3306, "0.0.0.0/0")])
    _, findings = audit.run_audit(s3, ec2)
    messages = [f["message"] for f in findings if f["resource"] == "risky-sg"]
    assert len(messages) == 2
    assert any("SSH" in m for m in messages)
    assert any("MySQL" in m for m in messages)


@mock_aws
def test_web_security_group_with_https_is_quiet():
    s3, ec2 = clients()
    make_group(ec2, "web-sg", [tcp(443, "0.0.0.0/0"), tcp(22, "203.0.113.25/32")])
    _, findings = audit.run_audit(s3, ec2)
    assert checks_for(findings, "web-sg") == set()


@mock_aws
def test_security_group_drift_is_detected():
    s3, ec2 = clients()
    group_id = make_group(ec2, "web-sg", [tcp(443, "0.0.0.0/0")])
    _, before = audit.run_audit(s3, ec2)
    assert checks_for(before, "web-sg") == set()

    ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=[tcp(22, "0.0.0.0/0")])
    _, after = audit.run_audit(s3, ec2)
    assert "sg-open-ingress" in checks_for(after, "web-sg")


def test_summarize_counts_by_severity():
    findings = [
        audit.finding("a", "x", "HIGH", "m"),
        audit.finding("b", "y", "HIGH", "m"),
        audit.finding("c", "z", "LOW", "m"),
    ]
    assert audit.summarize(findings) == {"HIGH": 2, "MEDIUM": 0, "LOW": 1}