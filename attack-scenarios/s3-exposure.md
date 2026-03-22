# Attack 2 — S3 Public Exposure

**MITRE ATT&CK:** T1530 — Data from Cloud Storage Object  
**Service:** S3  
**Executed by:** Root (simulating admin misconfiguration / insider threat)  
**Detected via:** CloudTrail — `PutBucketPolicy`, `DeleteBucketPolicy`

---

## Scenario

The root account disables S3 Block Public Access controls and applies a wildcard bucket policy, exposing all objects in the bucket to the public internet. This simulates the most common cause of S3 data breaches: an admin or developer who misconfigures a bucket, either accidentally or intentionally.

The majority of S3 breaches are not caused by sophisticated external attackers. They happen because someone with admin access made a mistake, disabled a safety control "temporarily", forgot to re-enable it, and left sensitive data exposed for days or weeks.

---

## Attack Execution

### Step 1 — Create target bucket

```bash
aws s3api create-bucket \
  --bucket cloud-soc-test-likhamba \
  --region ap-south-1 \
  --create-bucket-configuration LocationConstraint=ap-south-1
```

### Step 2 — Disable Block Public Access

By default, AWS blocks all public access to S3 buckets. The attacker disables this protection first:

```bash
aws s3api put-public-access-block \
  --bucket cloud-soc-test-likhamba \
  --public-access-block-configuration \
  "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"
```

All four Block Public Access settings are disabled simultaneously. Without this step, the next command would return `AccessDenied`.

### Step 3 — Apply public bucket policy (the attack)

```bash
aws s3api put-bucket-policy \
  --bucket cloud-soc-test-likhamba \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "PublicReadAccess",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::cloud-soc-test-likhamba/*"
    }]
  }'
```

`"Principal": "*"` means any entity: any person, any system, anywhere on the internet, can read every object in this bucket. This is the signature of an exposed bucket.

---

## CloudTrail Evidence

Queried directly via CLI:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketPolicy \
  --region ap-south-1 \
  --max-items 5
```

### Event 1 — PutBucketPolicy (attack)

```
EventName:    PutBucketPolicy
Username:     root
EventTime:    2026-03-22T02:34:12
EventSource:  s3.amazonaws.com
Bucket:       cloud-soc-test-likhamba
Principal:    *
Action:       s3:GetObject
```

### Event 2 — DeleteBucketPolicy (remediation)

```
EventName:    DeleteBucketPolicy
Username:     root
EventTime:    2026-03-22T02:34:25
EventSource:  s3.amazonaws.com
Bucket:       cloud-soc-test-likhamba
```

---

## Timeline

| Time | Event | Significance |
|------|-------|-------------|
| 02:34:12 | PutBucketPolicy — Principal: * | Bucket exposed to internet |
| 02:34:25 | DeleteBucketPolicy | Analyst removed public policy |

**13 seconds between exposure and remediation.**

---

## Key IOCs Extracted from CloudTrail JSON

| Field | Value | Significance |
|-------|-------|-------------|
| `Principal` | `*` | Wildcard — anonymous public access granted |
| `Action` | `s3:GetObject` | Any internet user can read all objects |
| `sourceIPAddress` | `[REDACTED]` | Origin of the attack |
| `userAgent` | `aws-cli/2.34.14` | Action done via CLI, not console |
| `Username` | `root` | Admin-level account — insider threat or credential theft |

The `userAgent` field is worth noting. Console actions show a browser user agent. CLI actions show `aws-cli/...`. This tells the analyst the action was scripted or automated not someone clicking around.

---

## Why "Principal": "*" Is the Red Flag

There is almost no legitimate reason to set `"Principal": "*"` on an S3 bucket policy. Legitimate use cases for public S3 access: static website hosting, public file downloads. A wildcard principal on `s3:GetObject` across all objects (`/*`) is a near-universal indicator of misconfiguration or malicious exposure.

Any `PutBucketPolicy` event containing a wildcard principal should trigger immediate investigation.

---

## Screenshots

| File | What It Shows |
|------|--------------|
| `05-putbucketpolicy-caught.png` | CloudTrail CLI — PutBucketPolicy event with bucket name and timestamp |
| `06-deletebucketpolicy-caught.png` | CloudTrail CLI — DeleteBucketPolicy remediation event |
| `07-putpublicaccessblock-empty.png` | CloudTrail CLI — PutPublicAccessBlock returning empty (handled silently by AWS) |

---

## Remediation

```bash
# Remove the public bucket policy
aws s3api delete-bucket-policy \
  --bucket cloud-soc-test-likhamba

# Re-enable Block Public Access
aws s3api put-public-access-block \
  --bucket cloud-soc-test-likhamba \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

---

## Lessons Learned

- Block Public Access should never be disabled unless there is an explicit, documented business reason
- `PutBucketPolicy` events should be reviewed whenever they occur, especially outside business hours
- In production, an SCP (Service Control Policy) can be used to prevent Block Public Access from being disabled at the organization level, removing the human error factor entirely
- The 13-second remediation time in this lab is unrealistic for a real environment, in practice, exposed buckets often go undetected for days or weeks
