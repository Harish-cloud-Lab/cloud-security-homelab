import json

import boto3

ENDPOINT = "http://localhost:4566"
s3 = boto3.client("s3", endpoint_url=ENDPOINT)
ec2 = boto3.client("ec2", endpoint_url=ENDPOINT)

# Bucket whose policy lets everyone read it
s3.create_bucket(Bucket="open-policy-bucket")
policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PublicRead",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::open-policy-bucket/*",
        }
    ],
}
s3.put_bucket_policy(Bucket="open-policy-bucket", Policy=json.dumps(policy))

# Bucket with a public-read ACL
s3.create_bucket(Bucket="public-acl-bucket")
s3.put_bucket_acl(Bucket="public-acl-bucket", ACL="public-read")

# Security groups: one risky, one acceptable
vpc_id = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]

risky = ec2.create_security_group(
    GroupName="risky-sg", Description="SSH and MySQL open to the world", VpcId=vpc_id
)["GroupId"]
ec2.authorize_security_group_ingress(
    GroupId=risky,
    IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
         "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306,
         "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
    ],
)

ok = ec2.create_security_group(
    GroupName="web-sg", Description="HTTPS public, SSH from one IP", VpcId=vpc_id
)["GroupId"]
ec2.authorize_security_group_ingress(
    GroupId=ok,
    IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
         "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
         "IpRanges": [{"CidrIp": "203.0.113.25/32"}]},
    ],
)

print("Created open-policy-bucket, public-acl-bucket, risky-sg and web-sg")