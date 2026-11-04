# Project 3: Cloud Security Auditor

A read-only Python tool that audits S3 buckets and security groups,
rates each finding by severity, and writes JSON and Markdown reports.

## What it checks
- S3: public access block, default encryption, versioning, bucket policy, bucket ACL
- Security groups: SSH, RDP and database ports open to the internet

## How I tested it
- Terraform built a test environment in Moto, a fake AWS on my laptop
- Setup scripts created good, weak and deliberately bad resources
- [N] automated pytest tests run in GitHub Actions on every push
- Known-good resources stay quiet, and known-bad ones are flagged

## Results
- First run: [X] high, [Y] medium, [Z] low findings
- After fixes: [your numbers]

## How to run it
1. pip install -r scripts/requirements.txt
2. Start Moto: moto_server -p 4566
3. python scripts/setup_lab.py, then setup_lab2.py
4. python scripts/audit.py

## Safety
The tool only reads configuration and never changes a resource.
It talks to the local fake server unless --real-aws is passed.

## Limitations
- Moto simulates only part of AWS, so real behaviour may differ
- Policy statements with a Condition are skipped, which can hide risk
- No IAM checks yet
- Not tested against a real account

