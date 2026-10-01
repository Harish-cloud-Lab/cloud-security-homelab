My day 3 tasks was to fix those failed checks. So I pasted code which has "Public-access-blocks, versioning, server-side-encryption, security-group, ingress and egress traffic rules".
The code is given below.

resource "aws_s3_bucket" "logs" {
  bucket = "my-homelab-logs-bucket"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Web server access"

  ingress {
    description = "SSH from my home IP for admin access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.25/32"]
  }

  egress {
    description = "HTTPS outbound only"
    from_port   = 443resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

Then i scanned that code file with "checkov" tool where i got 17 passed checks, 5 Failed checks and 0 skipped checks.
The 5 Failed checks are about Cross Replication, Lifecycle Configuratiion, Event Notification, access logging enabling and ensuring security groups are attached to another resources.
Out of these Cross replication and Event Notification failed checks are suppressed(Putting skip comment inside bucket resource).
Lifecycle Configuration is fixed with below code:

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

And this is how i suppressed (skipped) cross replication and event notification through comment

resource "aws_s3_bucket" "logs" {
  #checkov:skip=CKV_AWS_144: Replication not needed for a lab bucket, cost outweighs benefit
  #checkov:skip=CKV2_AWS_62: No event consumers in this lab
  bucket = "my-homelab-logs-bucket"
}

After applying those updates in file the checkov scan showed 19 passed, 2 failed and 2 skipped.
Only 2 failed checks are remained which are related to "Access-logging and Security Groups".
