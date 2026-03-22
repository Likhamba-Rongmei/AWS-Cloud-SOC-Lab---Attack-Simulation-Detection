# CloudTrail Analysis

This document covers how CloudTrail was used to detect each attack in this lab, the queries run, what the logs show, and how to read them.

---

## What CloudTrail Logs

Every API call made in an AWS account generates a CloudTrail event. Every event contains:

| Field | What It Tells You |
|-------|------------------|
| `eventName` | What action was taken (e.g. AttachUserPolicy, RunInstances) |
| `userIdentity` | Who did it — username, account ID, access key used |
| `eventTime` | When it happened |
| `sourceIPAddress` | Where the request came from |
| `userAgent` | What tool was used (console, CLI, SDK) |
| `requestParameters` | Exactly what was requested |
| `responseElements` | What AWS returned |
| `errorCode` | If it failed, why |
| `errorMessage` | Human-readable failure reason |

The combination of these fields is what lets you reconstruct exactly what an attacker did, in what order, from where.

---

## Detection Method Used in This Lab

GuardDuty and Security Hub were unavailable on this account type (educational credits). All detection was done by querying CloudTrail directly via CLI:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=[EVENT_NAME] \
  --region ap-south-1 \
  --max-items 5
```

The `lookup-events` command lets you filter by:
- `EventName` — search for a specific API call
- `Username` — search for all actions by a specific user
- `ResourceName` — search for all actions on a specific resource

The GUI Event History in the AWS Console has a 15-20 minute ingestion delay. The CLI returns results in real time.

---

## Attack 1 — IAM Escalation Detection

### Query 1 — Find privilege escalation attempts

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy \
  --region ap-south-1 \
  --max-items 5
```

**What to look for in the response:**
- `Username` is not root or an admin, a non-admin user modifying policies is immediately suspicious
- `errorCode: AccessDenied`: the attempt was blocked, but it happened
- Timestamp: note the exact time for correlation with subsequent events

### Query 2 — Find credential creation

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --region ap-south-1 \
  --max-items 5
```

**What to look for:**
- Same username as the AttachUserPolicy event
- Timestamp within seconds of the failed escalation attempt
- No `errorCode`: this one succeeded

### Reading the JSON

The full `CloudTrailEvent` JSON inside each event is where the real detail lives. Key fields for this attack:

```json
{
  "userIdentity": {
    "type": "IAMUser",
    "userName": "attacker-user",       ← who did it
    "accessKeyId": "[REDACTED]"        ← which key they used
  },
  "eventTime": "2026-03-21T20:41:41Z",
  "eventName": "AttachUserPolicy",
  "errorCode": "AccessDenied",         ← blocked
  "errorMessage": "User is not authorized to perform: iam:AttachUserPolicy"
}
```

---

## Attack 2 — S3 Exposure Detection

### Query — Find bucket policy changes

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketPolicy \
  --region ap-south-1 \
  --max-items 5
```

**What to look for in the response:**
- `ResourceName`: which bucket was affected
- Timestamp — when did it happen
- Then open the full `CloudTrailEvent` JSON and look inside `requestParameters.bucketPolicy`

### The smoking gun in the JSON

```json
"requestParameters": {
  "bucketPolicy": {
    "Statement": [{
      "Principal": "*",        ← wildcard — anyone on the internet
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::cloud-soc-test-likhamba/*"
    }]
  }
}
```

`"Principal": "*"` is the indicator. There is no legitimate reason to allow anonymous public read access to all objects in a bucket.

### Query — Confirm remediation

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteBucketPolicy \
  --region ap-south-1 \
  --max-items 5
```

Seeing `DeleteBucketPolicy` on the same bucket confirms the policy was removed. The timestamp difference between `PutBucketPolicy` and `DeleteBucketPolicy` is the exposure window.

---

## Attack 3 — EC2 Persistence Detection

### Query — Find instance launches

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances \
  --region ap-south-1 \
  --max-items 5
```

**What to look for:**
- `Username`: who launched it. Root launching instances at 03:56 AM is suspicious
- `Resources` array, a long resource list means a lot of new infrastructure was created at once
- Presence of a newly created `KeyPair`, legitimate admins reuse existing key pairs
- Presence of a new `SecurityGroup`, legitimate admins reuse existing security groups

### Correlating with security group configuration

After finding `RunInstances`, look up what security group rules were created:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress \
  --region ap-south-1 \
  --max-items 5
```

If the response shows `"CidrIpv4": "0.0.0.0/0"` on port 22, that confirms the attacker opened SSH to the entire internet, the entry point for shell access.

---

## General Detection Patterns

These are the CloudTrail events that should always trigger investigation in a real SOC environment:

| Event | Why It Matters |
|-------|---------------|
| `AttachUserPolicy` from a non-admin user | Privilege escalation attempt |
| `CreateAccessKey` from a non-admin user | Credential persistence |
| `PutBucketPolicy` with `Principal: *` | Data exposure |
| `DeleteBucketPolicy` | Could be remediation or covering tracks |
| `RunInstances` with new key pair + new security group | Attacker establishing persistence |
| `AuthorizeSecurityGroupIngress` with `0.0.0.0/0` | Open port — potential backdoor |
| `ConsoleLogin` from unexpected IP or geography | Credential compromise |
| `StopLogging` on CloudTrail | Attacker trying to disable audit trail |

---

## Limitations of This Detection Approach

**CloudTrail lookup-events only searches the last 90 days** of management events. For longer retention and more advanced querying, logs need to be shipped to S3 and queried via Athena or a SIEM.

**CloudTrail does not log SSH commands.** Once an attacker has shell access to an EC2 instance, their terminal commands are not visible in CloudTrail. Detecting post-exploitation activity on the instance requires agent-based tools (like Wazuh, as covered in the companion lab) or AWS-native tools like GuardDuty and Inspector.

**Manual querying does not scale.** In a production environment with thousands of API calls per hour, manual `lookup-events` queries are not practical. CloudWatch alarms, EventBridge rules, or a SIEM are needed for real-time alerting.

These limitations are noted here because understanding what a tool cannot do is as important as knowing what it can.
