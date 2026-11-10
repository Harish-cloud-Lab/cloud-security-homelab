# Incident Report 001: Brute-force login followed by cloud configuration changes

**This is a simulated incident.** All logs, usernames, resources and addresses are
synthetic and were generated for a detection exercise. IP addresses come from ranges
reserved for documentation. No real system or account was involved.

| Field | Value |
|---|---|
| Incident ID | 001 |
| Status | Closed (simulation) |
| Severity | Critical |
| Detected by | Custom detection rules (`detection/rules/`) |
| Date of activity | 2026-01-15 (synthetic) |

## Summary

An external address brute-forced SSH on a web server, then logged in successfully as the
`deploy` account. Within four minutes of the login, the same address removed the public
access block from a storage bucket, changed the bucket's policy, and stopped audit
logging. The detector raised six alerts, including a correlation alert linking the login
to the cloud changes.

## Timeline (UTC)

| Time | Event | Detected by |
|---|---|---|
| 14:00:00 | First failed SSH login from 203.0.113.50 (invalid usernames such as root, admin, test) | |
| 14:00:12 | Fifth failure within 120 seconds | `ssh-bruteforce` (HIGH) |
| 14:00:33 | Twelfth and last failure | |
| 14:00:45 | Successful login as `deploy` from the same address | `ssh-success-after-failures` (CRITICAL) |
| 14:02:00 | `DeleteBucketPublicAccessBlock` on the logs bucket by `deploy` | `cloud-public-access-block-removed` (HIGH) |
| 14:02:00 | Cloud change within 30 minutes of the suspicious login | `correlation-ssh-then-cloud` (CRITICAL) |
| 14:03:00 | `PutBucketPolicy` on the logs bucket | `cloud-bucket-policy-changed` (MEDIUM) |
| 14:04:00 | `StopLogging` on the audit trail | `cloud-logging-disabled` (CRITICAL) |

## What happened

1. **Reconnaissance and guessing.** The attacker tried many common usernames in quick
   succession, 12 failures in about 33 seconds. That speed points to automation, not a
   person mistyping a password.
2. **Initial access.** The next attempt succeeded as `deploy`, a service-style account.
   The likely cause is a weak or reused password on an account reachable from the internet
   (MITRE ATT&CK T1110 Brute Force, T1078 Valid Accounts).
3. **Weakening the cloud account.** Using the same address, the attacker removed the
   bucket's public access block, changed its policy, and then stopped audit logging.
   Turning off logging hides every action that follows (MITRE ATT&CK T1562.008 Disable or
   Modify Cloud Logs).

## Impact

Assessed from the logs only:

- The `deploy` account should be treated as compromised.
- The bucket's protections were removed and its policy was changed, so any data in it
  should be treated as exposed until the policy is reviewed.
- Audit logging was stopped, so activity after 14:04 would not appear in that trail.
- Any other action by `deploy` from 14:00:45 onward is unknown and must be investigated.

## Root cause

- SSH was reachable from the whole internet.
- The login relied on a password with no second factor.
- There was no automatic blocking after repeated failures.
- The account had permissions to change bucket protections and stop logging, which a
  deployment account should not have.

## Response (what to do in a real incident)

**Containment**
1. Disable the `deploy` account and revoke its sessions and any keys.
2. Block 203.0.113.50 at the firewall.
3. Restart audit logging immediately.

**Eradication and recovery**
4. Restore the bucket's public access block and review the policy against the last known
   good version.
5. Rotate the credentials of any account that shared a password with `deploy`.
6. Review everything `deploy` did after 14:00:45, including activity not covered by the
   audit trail, using other logs.

## Lessons and fixes

| Gap | Fix |
|---|---|
| SSH open to the internet | Restrict by address, or remove it and use a managed session service |
| Password-only login | Use key-based login or multi-factor authentication |
| No lockout after failures | Add automatic blocking after repeated failures |
| Over-broad permissions | Apply least privilege, so the account cannot change protections or stop logging |
| Logging could be stopped | Alert on `StopLogging`, protect the trail, and send logs to a separate account |

## Detection notes

- The brute-force rule and the successful-login rule gave early warning, about two
  minutes before the cloud changes.
- The correlation rule linked the login to the cloud changes by source address.
- **Gaps:** an attacker who spread attempts over a long period, used many addresses, or
  changed address between the login and the cloud actions would evade these rules.
- The rules are Sigma-inspired and were tested only against synthetic logs.
