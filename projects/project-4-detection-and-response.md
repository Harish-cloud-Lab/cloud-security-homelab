# Project 4: Detection and Response

A self-directed home lab project. I built a small detection pipeline in Python: it
generates synthetic logs, applies readable detection rules, correlates separate signals,
and I wrote an incident report for a simulated attack.

![Security Scan](https://github.com/Haris-cloud-Lab/cloud-security-homelab/actions/workflows/security-scan.yml/badge.svg)

**All data in this project is synthetic.** The logs, usernames and resources are made up,
and the addresses come from ranges reserved for documentation. I did not use a real SIEM
or real production logs.

## The problem

Scanning finds weaknesses before an attack, but it cannot tell you when one is under way.
Prevention is never perfect, so teams also need detection: spotting suspicious behavior
in logs, linking related signals, and responding with a clear process.

## What I built

- A log generator that produces a normal day or an attack day, using a fixed seed so
  results are repeatable
- Detection rules written as plain YAML files, inspired by the Sigma idea
- A Python detector that parses SSH logs and cloud audit logs and applies the rules
- A correlation rule that links a suspicious login to cloud changes from the same address
- Automated tests that run in GitHub Actions on every push
- An incident report for the simulated attack: [incident-report-001](incident-report-001.md)

## Architecture

```
  detection/generate_logs.py --seed N [--attack]
        |
        v
  auth.log (SSH)        cloudtrail.jsonl (cloud audit events)
        |                         |
        +-----------+-------------+
                    v
        detection/detect.py  +  detection/rules/*.yml
                    |
        +-----------+-----------------------------+
        | threshold rule: brute force             |
        | login success after failures            |
        | cloud event rules (3)                   |
        | correlation: login, then cloud changes  |
        +-----------+-----------------------------+
                    v
        alerts sorted by time, exit code 1 if any
```

## The rules

| Rule | Severity | What it detects |
|---|---|---|
| `ssh-bruteforce` | HIGH | 5 failed logins from one address within 120 seconds |
| `ssh-success-after-failures` | CRITICAL | A successful login after 5 or more recent failures from the same address |
| `cloud-public-access-block-removed` | HIGH | A bucket's public access block was removed |
| `cloud-bucket-policy-changed` | MEDIUM | A bucket policy was changed |
| `cloud-logging-disabled` | CRITICAL | Audit logging was stopped |
| `correlation-ssh-then-cloud` | CRITICAL | Cloud changes within 30 minutes from an address that just logged in after a brute force |

Some rules reference MITRE ATT&CK techniques, such as brute force, valid accounts, and
disabling cloud logs.

## Results

| Test | Result |
|---|---|
| Clean day | 0 alerts |
| Attack day | 6 alerts, all from the attacker's address |
| Automated tests | 26 passed (11 for the Project 3 auditor, 15 for the detector) |
| Pipeline | [all jobs green / your result] |

The attack-day alerts, in time order: brute force, successful login, public access block
removed, correlation, policy changed, logging stopped.

## How I tested it

- A detector must catch the known-bad case and stay quiet on the known-good one, so the
  clean day and the attack day are both automated tests
- Each rule has its own test, including cases where it must not fire
- The correlation rule is tested twice: it fires for the same address and stays silent
  for a different one
- A test documents a known weakness: a slow brute force never reaches the threshold
- The parser counts lines it cannot read, and an unknown rule type raises an error, so a
  broken rule cannot silently stop working

## Skills demonstrated

- Python: parsing, data structures (sliding windows), command-line tools
- Detection engineering: threshold rules, sequence rules, correlation, severity
- Writing detection rules as readable configuration, mapped to MITRE ATT&CK
- Testing security code with pytest, including limitations
- Incident response: timeline, impact, root cause, containment, and fixes
- CI with GitHub Actions

## Problems I hit and what they taught me

- **Silent failure is the main danger.** A rule with a typo in its type would simply never
  run. I made the detector fail loudly and added a test for it.
- **A detector can look fine while being blind.** The clean day proves it is not noisy, and
  the attack day proves it is not blind, so I always test both.

## How to run it

1. `pip install -r scripts/requirements.txt`
2. `python detection/generate_logs.py --seed 1 --out detection/sample_logs/clean`
3. `python detection/generate_logs.py --attack --seed 1 --out detection/sample_logs/attack`
4. `python detection/detect.py --auth detection/sample_logs/attack/auth.log --cloud detection/sample_logs/attack/cloudtrail.jsonl`
5. `python -m pytest tests -q`

## Limitations

- The logs are synthetic, so real logs would be messier and noisier
- Correlation matches only on the source address, so an attacker who changes address
  between the login and the cloud actions would evade it
- Slow attacks, or attacks spread over many addresses, avoid the threshold
- The rules are Sigma-inspired, not real Sigma, and nothing was tested in a real SIEM
- No real response automation: the incident report describes the response, but the project
  does not block anything

## What I would do next

- Run the same rules against a real or replayed public log dataset and tune them
- Add per-account rules and a longer window for slow attacks
- Convert the rules to real Sigma and test them in a SIEM such as Wazuh
- Add automatic response, such as blocking an address after a critical alert