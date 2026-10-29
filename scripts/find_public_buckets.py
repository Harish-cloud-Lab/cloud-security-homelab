import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3", endpoint_url="http://localhost:4566")


def is_protected(bucket_name):
    """Return True only if all four public access block settings are on."""
    try:
        resp = s3.get_public_access_block(Bucket=bucket_name)
        config = resp["PublicAccessBlockConfiguration"]
        return all(config.values()) and len(config) == 4
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return False
        raise


def main():
    buckets = s3.list_buckets()["Buckets"]
    risky = []
    for b in buckets:
        name = b["Name"]
        if is_protected(name):
            print(f"OK     {name}")
        else:
            print(f"RISKY  {name}  (public access block missing or incomplete)")
            risky.append(name)
    print(f"\nChecked {len(buckets)} buckets, {len(risky)} risky")


if __name__ == "__main__":
    main()