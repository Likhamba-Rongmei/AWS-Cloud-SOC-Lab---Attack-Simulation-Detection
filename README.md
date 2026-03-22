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
 
The 17 second gap between the two events stood out. The short time gap between failed privilege escalation and credential creation suggests possible automated or pre-planned activity, though it could also be a skilled user executing commands rapidly.

The escalation was blocked but the access key creation succeeded. The attacker now has CLI credentials they can use from anywhere, even after the original session ends.
 
See full analysis: [attack-scenarios/iam-escalation.md](attack-scenarios/iam-escalation.md)
 
---

## Attack 2 — S3 Public Exposure
 
**Scenario:** Block Public Access disabled, then a wildcard bucket policy applied — exposing all objects to the internet.
 
**Attack chain:**
1. `PutPublicAccessBlock` — disabled all four Block Public Access settings
2. `PutBucketPolicy` — applied policy with `"Principal": "*"` and `"Action": "s3:GetObject"`
3. `DeleteBucketPolicy` — analyst removed the policy (remediation)
 
**What made this detectable:**
The `"Principal": "*"` in the bucket policy is the red flag. There is almost no legitimate reason to allow anonymous public read access to an S3 bucket. Any `PutBucketPolicy` event containing a wildcard principal should trigger immediate investigation.
 
CloudTrail also captured the source IP and user agent in the event JSON.
 
See full analysis: [attack-scenarios/s3-exposure.md](attack-scenarios/s3-exposure.md)
 
---

## Attack 3 — EC2 Persistence
 
**Scenario:** Attacker with stolen root credentials launches an EC2 instance inside the account to establish a persistent foothold.
 
**What happened:**
- Created a key pair and security group with SSH open to `0.0.0.0/0`
- Launched a t3.micro Ubuntu instance
- SSH'd in and ran post-exploitation recon
 
**Recon commands run inside the instance:**
 
| Command | What It Reveals |
|---------|----------------|
| `whoami` / `id` | Username and group memberships — found ubuntu in sudo group |
| `cat /etc/passwd` | Full user list for lateral movement planning |
| `netstat -tulpn` | Open ports — SSH confirmed on port 22 |
| `cat /root/.aws/credentials` | Credential theft attempt — Permission Denied |
| `sudo cat /etc/shadow` | Privilege escalation test |
| `find / -name "*.pem"` | Hunting for private keys |
 
**CloudTrail caught:**
- `RunInstances` logged the full resource footprint: instance ID, AMI, key pair, security group, VPC, subnet, network interface
- Two `RunInstances` events visible — the failed t2.micro attempt and the successful t3.micro launch
 
A SOC analyst seeing `RunInstances` with a newly created key pair and a security group allowing `0.0.0.0/0` on port 22 would flag this immediately.
 
See full analysis: [attack-scenarios/ec2-attack.md](attack-scenarios/ec2-attack.md)
 
---

## Incident Response
 
Terminating the EC2 instance was the first action taken, but that alone is only containment. The attacker still holds valid access keys and can relaunch infrastructure immediately. Full remediation required:
 
| Step | Action | Command |
|------|--------|---------|
| 1 | Terminate EC2 instance | `aws ec2 terminate-instances` |
| 2 | Revoke attacker access keys | `aws iam delete-access-key` |
| 3 | Remove 0.0.0.0/0 SSH ingress rule | `aws ec2 revoke-security-group-ingress` |
| 4 | Delete attacker IAM user entirely | `aws iam delete-user` |
| 5 | Remove public bucket policy | `aws s3api delete-bucket-policy` |
 
Each step was verified by querying the AWS API.
 
---

## Detection Approach
 
All detection was done by querying CloudTrail directly:
 
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy \
  --region ap-south-1 \
  --max-items 5
```
 
For each event I looked at:
- `userIdentity` — who triggered it
- `sourceIPAddress` — where it came from
- `requestParameters` — exactly what they did
- `errorCode` — whether it was blocked or succeeded
- `eventTime` — when, and how it relates to surrounding events
 
The full CloudTrail analysis methodology is in [detection/cloudtrail-analysis.md](detection/cloudtrail-analysis.md).
 
---

## Screenshots

See [screenshots/README.md](screenshots/README.md)

---

## Repo Structure
```
Cloud-SOC-Lab/
├── README.md
├── architecture.png
├── attack-scenarios/
│   ├── iam-escalation.md
│   ├── s3-exposure.md
│   └── ec2-attack.md
├── detection/
│   └── cloudtrail-analysis.md
└── screenshots/
    └── README.md
```

---

## Related
 
[Wazuh SIEM Lab](https://github.com/Likhamba-Rongmei/Wazuh-SIEM-Implementation) : on-premise SOC lab covering brute force detection and malware simulation. The SSH brute force pattern from that lab and the EC2 attack here represent the same technique across on-prem and cloud environments.
