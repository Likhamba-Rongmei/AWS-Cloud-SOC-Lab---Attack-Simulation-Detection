# Attack 1 — IAM Privilege Escalation

**MITRE ATT&CK:** T1098 — Account Manipulation  
**Service:** IAM  
**Executed by:** attacker-user (compromised low-privilege account)  
**Detected via:** CloudTrail — `AttachUserPolicy`, `CreateAccessKey`

---

## Scenario

A low-privilege IAM user (attacker-user) with no permissions attempts to grant themselves administrator access, then creates new access keys to establish persistent CLI access even if the original session is terminated.

This simulates the most common post-compromise action in cloud breaches: an attacker who has stolen a developer's credentials trying to escalate before they are detected.

---

## Environment Setup

Two IAM users were created to simulate a real account structure:

```bash
# Create legitimate employee account
aws iam create-user --user-name normal-user

# Assign minimal permissions — read-only S3 access
aws iam attach-user-policy \
  --user-name normal-user \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

# Create compromised attacker account
aws iam create-user --user-name attacker-user

# Generate credentials for attacker-user
aws iam create-access-key --user-name attacker-user
```

The attacker's credentials were configured as a separate CLI profile:

```bash
aws configure --profile attacker
```

This ensures all attack commands run with attacker-user's permissions, not root.

---

## Attack Execution

### Step 1 — Privilege escalation attempt

Acting as attacker-user, attempted to attach AdministratorAccess to their own account:

```bash
aws iam attach-user-policy \
  --user-name attacker-user \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
  --profile attacker
```

**Result:** `AccessDenied`

The security control worked, attacker-user does not have permission to modify IAM policies. However, the attempt itself is now permanently logged in CloudTrail.

### Step 2 — Access key creation (persistence)

Immediately after the failed escalation, attacker-user created new access keys:

```bash
aws iam create-access-key \
  --user-name attacker-user \
  --profile attacker
```

**Result:** Success

The attacker now holds CLI credentials that work from any machine, at any time, independently of the current session.

---

## CloudTrail Evidence

### Event 1 — AttachUserPolicy (AccessDenied)

```
EventName:    AttachUserPolicy
Username:     attacker-user
EventTime:    2026-03-22T02:11:41
EventSource:  iam.amazonaws.com
ErrorCode:    AccessDenied
ErrorMessage: User is not authorized to perform: iam:AttachUserPolicy
```

### Event 2 — CreateAccessKey (Success)

```
EventName:    CreateAccessKey
Username:     attacker-user
EventTime:    2026-03-22T02:11:58
EventSource:  iam.amazonaws.com
ErrorCode:    (none — succeeded)
```

---

## Timeline Analysis

| Time | Event | Result | Significance |
|------|-------|--------|-------------|
| 02:11:41 | AttachUserPolicy | AccessDenied | Escalation attempt blocked |
| 02:11:58 | CreateAccessKey | Success | Persistence established |

**17-second gap** between the two events.

A person navigating the AWS console manually would take several minutes between actions. 17 seconds indicates the attacker was running a script. This pattern: failed escalation immediately followed by credential creation, is a signature of automated post-exploitation tooling such as Pacu or custom scripts.

---

## Why CreateAccessKey Is Dangerous

Even though the privilege escalation failed, the attacker succeeded in creating access keys. This means:

- They can authenticate to this AWS account from any machine worldwide
- The keys survive session termination, password resets, and console lockouts
- They can continue attempting other attacks at any time
- If undetected, these keys remain valid indefinitely

This is why `CreateAccessKey` events from non-root users, especially low-privilege users, are one of the highest priority alerts in a cloud SOC environment.

---

## Screenshots

| File | What It Shows |
|------|--------------|
| `01-iam-setup.png` | IAM users created, policy attached, attacker access keys generated |
| `02-attachuserpolicy-denied.png` | CloudTrail event history — AttachUserPolicy from attacker-user |
| `03-createaccesskey-caught.png` | CloudTrail event history — CreateAccessKey from attacker-user |
| `04-attachuserpolicy-json.png` | Full CloudTrail JSON — errorCode: AccessDenied visible |

---

## Remediation

```bash
# Revoke attacker access keys
aws iam delete-access-key \
  --user-name attacker-user \
  --access-key-id [REDACTED]

# Verify keys are gone
aws iam list-access-keys --user-name attacker-user

# Delete the attacker account entirely
aws iam delete-user --user-name attacker-user
```

Verified by `list-access-keys` returning `"AccessKeyMetadata": []`.

---

## Lessons Learned

- A denied API call is not the end of the story, the attempt is logged and the attacker may try other vectors
- `CreateAccessKey` should be monitored on all non-admin users, there is rarely a legitimate reason for a low-privilege user to create their own access keys
- IAM users should follow least privilege strictly, if a user only needs S3 read access, they should have exactly that and nothing more
- In production, a CloudWatch alarm on `CreateAccessKey` events would have triggered an alert within seconds
