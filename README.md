# AWS Cloud SOC Lab
 
A personal cloud security lab where I simulated three real-world attack scenarios against a live AWS environment and investigated each one by manually analyzing CloudTrail logs.
 
Built as part of my preparation for SOC Analyst and Cloud Security roles. The goal was to get hands-on with attack detection in AWS instead of just reading about it.
 
---

## What I Did
 
Set up a basic AWS environment, created IAM users to simulate a real account structure, then ran three attacks against it, each one representing a different stage of a cloud breach. After each attack, I queried CloudTrail to find the evidence, understood what the logs were telling me, and performed remediation.
 
No GuardDuty or Security Hub were available on my account type (educational credits), so all detection was done by querying CloudTrail directly via CLI. That ended up being more instructive anyway, we learn more reading raw logs than reading automated alerts.
 
---

## Attack Scenarios
 
| # | Attack | MITRE ATT&CK | Who Executed It |
|---|--------|--------------|-----------------|
| 1 | IAM Privilege Escalation | T1098 | attacker-user (low-priv compromised account) |
| 2 | S3 Public Exposure | T1530 | Root (simulating admin misconfiguration) |
| 3 | EC2 Persistence | T1078 | Root (simulating stolen admin credentials) |
 
The three scenarios intentionally represent different threat actors:
- A compromised developer account with minimal permissions trying to escalate
- An admin who misconfigures storage — the most common cause of S3 breaches in practice
- An attacker who already has root credentials and is establishing a persistent foothold
 
---

## Environment
 
```
AWS Account — ap-south-1 (Mumbai)
│
├── CloudTrail (cloud-soc-lab-trail)
│   └── S3 bucket for log storage
│
├── IAM
│   ├── normal-user — S3 read-only (legitimate employee baseline)
│   └── attacker-user — no permissions (compromised low-priv account)
│
├── S3
│   └── cloud-soc-test-likhamba (target bucket)
│
└── EC2
    └── soc-lab-target — t3.micro Ubuntu
        └── Security group: soc-lab-sg
```
 
---

## Attack 1 — IAM Privilege Escalation
 
**Scenario:** attacker-user attempts to attach AdministratorAccess to themselves, then creates new access keys for persistence.
 
**What I found in CloudTrail:**
 
| Time | Event | User | Result |
|------|-------|------|--------|
| 02:11:41 | AttachUserPolicy | attacker-user | AccessDenied |
| 02:11:58 | CreateAccessKey | attacker-user | Success |
 
The 17-second gap between the two events stood out. The short time gap between failed privilege escalation and credential creation suggests possible automated or pre-planned activity, though it could also be a skilled user executing commands rapidly.

The escalation was blocked but the access key creation succeeded. The attacker now has CLI credentials they can use from anywhere, even after the original session ends.
 
See full analysis: [attack-scenarios/iam-escalation.md](attack-scenarios/iam-escalation.md)
 
---
