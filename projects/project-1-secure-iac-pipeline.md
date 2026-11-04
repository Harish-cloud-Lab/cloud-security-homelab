# Project 1: Secure Infrastructure-as-Code Pipeline

A self-directed home lab project. I wrote Terraform for AWS resources, scanned it for
misconfigurations, fixed the serious findings, and put the scans into a GitHub Actions
pipeline that runs on every push.

![Security Scan](https://github.com/YOUR-USERNAME/cloud-security-homelab/actions/workflows/security-scan.yml/badge.svg)

## The problem

Cloud breaches are most often caused by misconfiguration: public buckets, SSH open to
the whole internet, missing encryption, leaked credentials. These problems are cheapest
to fix when they are caught in code, before anything is deployed.

## What I built

- Terraform for an S3 bucket and a security group, deliberately insecure at first
- A scan-fix-rescan loop with Checkov, triaging every finding as fix, accept, or suppress
- A dedicated access-log bucket with its own protections
- A GitHub Actions pipeline with three scanners: Checkov, Trivy and Gitleaks
- A local deployment of the same Terraform to Moto (a fake AWS on my laptop), so the
  code was applied for real and not only scanned

## Architecture

```
  git push
     |
     v
  GitHub Actions (fresh Linux runner on every push)
     |-- Checkov   : Terraform, Dockerfile and Kubernetes manifests
     |-- Trivy     : container image vulnerabilities
     |-- Gitleaks  : secrets in files and full git history
     |
     v
  green = merge is fine, red = fix, accept with a reason, or suppress with a reason

  Local testing:
  terraform-local/ --(provider endpoints)--> Moto on localhost:4566
        |
        +-- module "lab" = ../terraform  (the real resource code, unchanged)
```

## Results

| Stage | Result |
|---|---|
| First Checkov scan | 10 failed checks |
| After fixing the high-risk issues | 17 passed, 5 failed (all low priority) |
| After adding access logging, lifecycle rules and documented skips | [your final Checkov numbers] |
| Pipeline | [all jobs green / your result] |

High-risk issues fixed:

- SSH open to `0.0.0.0/0` restricted to a single address (a documentation placeholder here)
- Added an S3 public access block
- Enabled default encryption
- Enabled versioning
- Added descriptions to firewall rules
- Added access logging with a dedicated log bucket

## Decisions: fix, accept, or suppress

Not every finding is worth fixing in a lab. Each skipped check carries a written reason
in the code, so a reviewer can see and challenge it.

| Finding | Decision | Reason |
|---|---|---|
| Cross-region replication | Suppressed | Needs a second bucket and IAM role, and doubles storage cost |
| Event notifications | Suppressed | No consumer exists in this lab |
| Security group not attached | Suppressed | The file is scan-only, with no instance using it |
| Access logging on the log bucket itself | Suppressed | Logging the log bucket would create an endless chain of buckets |
| Log bucket uses AES256, not KMS | Accepted | S3 server access logging only supports SSE-S3 on the target bucket |

## Skills demonstrated

- Terraform (HCL), providers, modules, `init`, `plan`, `apply`, state, and drift
- IaC security scanning with Checkov, and triage of findings
- S3 and security group hardening, and the shared responsibility model
- GitHub Actions CI, with least-privilege workflow permissions
- Secret scanning with Gitleaks, and `.gitignore` hygiene
- Git workflow: commit, push, pull, merge, and recovering deleted files with `git restore`
- Debugging: Linux versus Windows path case sensitivity, and YAML indentation

## Problems I hit and what they taught me

- **Case-sensitive paths.** The pipeline failed because I had committed `Docker/` while the
  workflow referenced `docker/`. Windows ignores case, the Linux runner does not. Lesson:
  test in the environment you deploy to.
- **YAML indentation.** A misplaced space broke the workflow. Lesson: read the exact
  error line before guessing at a cause.
- **Terraform state must never be committed.** The state file records everything Terraform
  manages and can contain sensitive values, so it is excluded by `.gitignore`.

## How to reproduce

1. Install Git, Docker, Terraform and Python.
2. Scan the code: `docker run --rm -v ${PWD}/terraform:/tf bridgecrew/checkov -d /tf`
3. Start Moto: `moto_server -p 4566`, with fake credentials set in the shell.
4. Deploy locally: in `terraform-local/`, run `terraform init`, `plan`, then `apply`.
5. Push to GitHub to run the full pipeline.

## Limitations

- Terraform was applied only to Moto, a partial simulation of AWS. A successful apply
  there does not prove real AWS accepts the same code.
- Nothing has been deployed to a real AWS account.
- Real S3 access logging also needs a bucket policy for the logging service, which Moto
  does not check.
- Suppressed checks are judgment calls and would be reviewed differently in production.

## What I would do next

- Run the same code against a real AWS account using short-term credentials
- Add policy-as-code rules (for example Conftest or custom Checkov policies)
- Add a scheduled scan so newly published issues surface weekly
