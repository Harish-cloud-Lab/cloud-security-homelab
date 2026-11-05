# Cloud Security Homelab

A self-directed home lab where I practice cloud security by running a small
environment the way a real company would: infrastructure as code, scanning,
hardening, testing, and documenting results.

![Security Scan](https://github.com/Haris-cloud-Lab/cloud-security-homelab/actions/workflows/security-scan.yml/badge.svg)

## Projects
- [Project 1: Secure IaC Pipeline](projects/project-1-secure-iac-pipeline.md)
- [Project 2: Hardened Container and Kubernetes](projects/project-2-hardened-kubernetes.md)
- [Project 3: Cloud Security Auditor](projects/project-3-cloud-security-auditor.md)

## Tools
Terraform, Checkov, Trivy, Gitleaks, Docker, Kubernetes (kind, Calico),
GitHub Actions, Python (boto3, pytest, Moto)

## Roadmap
- Detection and response (log analysis, detection rules, incident report)
- Real AWS audit with short-term, read-only credentials
- Supply chain security (SBOM, image signing)

## Notes
Everything here was tested locally or in CI. Where a result depends on a
simulated AWS (Moto), the project README says so.

## Daily logs
See the `logs/` folder.