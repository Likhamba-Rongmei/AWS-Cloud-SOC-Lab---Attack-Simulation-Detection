# Screenshots

All screenshots are taken from the live AWS environment (Console and CLI) during attack simulation and detection.

**Redaction:** Account ID, access key IDs, source IPs, instance IDs, and ARNs are blurred in all screenshots. Standard practice when sharing investigation artifacts publicly.

View all screenshots in the gallery:  
👉 [Evidence Gallery](https://likhamba-rongmei.github.io/AWS-Cloud-SOC-Lab-Attack-Simulation-Detection/)

## Lab Setup

| File | Contents |
|------|----------|
| `iam-setup.png` | CLI setup — get-caller-identity, both users created, S3ReadOnly policy attached, attacker access keys generated |

## Attack 1 — IAM Privilege Escalation (T1098)

| File | Contents |
|------|----------|
| `attachuserpolicy-denied.png` | CloudTrail event history — AttachUserPolicy from attacker-user at 02:11:41 (AccessDenied) |
| `createaccesskey-caught.png` | CloudTrail event history — CreateAccessKey from attacker-user at 02:11:58 |
| `attachuserpolicy-json.png` | Full CloudTrail JSON — errorCode: AccessDenied, userIdentity, sourceIPAddress visible |

## Attack 2 — S3 Public Exposure (T1530)

| File | Contents |
|------|----------|
| `putbucketpolicy-caught.png` | CloudTrail CLI — PutBucketPolicy with Principal: * on cloud-soc-test-likhamba at 02:34:12 |
| `deletebucketpolicy-caught.png` | CloudTrail CLI — DeleteBucketPolicy remediation at 02:34:25 |
| `putpublicaccessblock-empty.png` | CloudTrail CLI — PutPublicAccessBlock query returning empty |

## Attack 3 — EC2 Persistence (T1078)

| File | Contents |
|------|----------|
| `ec2-running.png` | EC2 instance in running state with public IP |
| `ssh-whoami-id.png` | Shell access confirmed — ubuntu user in sudo group |
| `ssh-netstat.png` | Network recon — open ports mapped inside instance |
| `ssh-shadow-exfil.png` | /etc/shadow read, find *.pem key hunt executed |
| `ssh-credentials-denied.png` | cat /root/.aws/credentials — Permission Denied |
| `runinstances-successful.png` | CloudTrail CLI — successful RunInstances with full resource list |
| `runinstances-failed.png` | CloudTrail CLI — failed t2.micro attempt at 03:55:51 |

## Incident Response

| File | Contents |
|------|----------|
| `instance-terminated.png` | EC2 instance in terminated state — containment |
| `accesskey-revoked-ssh-removed.png` | AccessKeyMetadata empty + 0.0.0.0/0 SSH rule revoked — full remediation |
