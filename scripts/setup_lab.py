import boto3

s3 = boto3.client("s3", endpoint_url="http://localhost:4566")

FULL_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}
ENCRYPTION = {
    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
}
VERSIONING = {"Status": "Enabled"}

# 1. Well configured: should have no findings
s3.create_bucket(Bucket="good-bucket")
s3.put_public_access_block(Bucket="good-bucket", PublicAccessBlockConfiguration=FULL_BLOCK)
s3.put_bucket_encryption(Bucket="good-bucket", ServerSideEncryptionConfiguration=ENCRYPTION)
s3.put_bucket_versioning(Bucket="good-bucket", VersioningConfiguration=VERSIONING)

# 2. Weak: nothing configured, should have 3 findings
s3.create_bucket(Bucket="weak-bucket")

# 3. Partial: one public access setting off, no encryption, versioning on
s3.create_bucket(Bucket="partial-bucket")
s3.put_public_access_block(
    Bucket="partial-bucket",
    PublicAccessBlockConfiguration={**FULL_BLOCK, "BlockPublicPolicy": False},
)
s3.put_bucket_versioning(Bucket="partial-bucket", VersioningConfiguration=VERSIONING)

print("Created good-bucket, weak-bucket, partial-bucket")