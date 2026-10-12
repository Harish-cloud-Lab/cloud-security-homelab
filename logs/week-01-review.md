“I was new to cloud security, so I built a home lab and ran it like a small company, with a GitHub repo, a ticket board, and daily logs. In the first week, I did four things.

First, I wrote Terraform for an S3 bucket and a security group and scanned it with Checkov. The first scan showed 10 failures. I fixed the high-risk ones, like SSH open to the whole internet, no public access block, no encryption, and no versioning. For the low-value ones, like cross-region replication, I suppressed the check with a written reason.

Second, I scanned container images with Trivy. An old nginx image had 921 vulnerabilities, 266 of them HIGH or CRITICAL. I built my own image on a newer, smaller, non-root base, and the scan came back clean. I verified that it ran as the nginx user, not root.

Third, I put everything into a GitHub Actions pipeline that ran Checkov, Trivy, and Gitleaks on every push. It caught real problems, including a folder name case mismatch between Windows and the Linux runner, and a YAML indentation mistake I made myself.

The main lessons were to prioritize findings by risk instead of chasing zero, that a clean scan is only a snapshot, and that I should test in the same environment I deploy to. At that point I hadn’t deployed to a real cloud account or worked with Kubernetes yet, so that was my next step.”
