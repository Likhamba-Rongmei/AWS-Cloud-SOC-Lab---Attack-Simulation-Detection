# Attack 3 — EC2 Persistence

**MITRE ATT&CK:** T1078 — Valid Accounts  
**Service:** EC2, IAM  
**Executed by:** Root (simulating stolen admin/root credentials)  
**Detected via:** CloudTrail — `RunInstances`, SSH recon logs

---

## Scenario

An attacker who has obtained root credentials through a leaked `.env` file, a GitHub commit containing access keys, or a compromised developer machine, launches an EC2 instance inside the victim's account to establish a persistent foothold.

This is different from Attacks 1 and 2. The attacker already has full access. Their goal now is persistence: creating infrastructure inside the victim's account that survives credential rotation and gives them continued access to the cloud environment.

The victim pays for the instance. The attacker controls it.

---

## Attack Execution

### Step 1 — Create SSH key pair

```bash
aws ec2 create-key-pair \
  --key-name soc-lab-key \
  --region ap-south-1 \
  --query 'KeyMaterial' \
  --output text > soc-lab-key.pem

chmod 400 soc-lab-key.pem
```

The private key is saved locally. The public key is registered in AWS. Without this key file, no one can SSH into the instance, even knowing the IP address.

### Step 2 — Create security group with open SSH

```bash
aws ec2 create-security-group \
  --group-name soc-lab-sg \
  --description "SOC Lab Security Group" \
  --region ap-south-1
```

```bash
aws ec2 authorize-security-group-ingress \
  --group-id sg-[REDACTED] \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0 \
  --region ap-south-1
```

`0.0.0.0/0` on port 22 means SSH is open to the entire internet. This is a critical misconfiguration, in a real environment, SSH should be restricted to specific IP ranges or disabled entirely in favour of AWS Systems Manager Session Manager.

### Step 3 — Launch EC2 instance

```bash
aws ec2 run-instances \
  --image-id ami-0f58b397bc5c1f2e8 \
  --instance-type t3.micro \
  --key-name soc-lab-key \
  --security-group-ids sg-[REDACTED] \
  --region ap-south-1 \
  --count 1 \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=soc-lab-target}]'
```

Note: The first attempt used `t2.micro` and failed, educational credit accounts are restricted to free-tier eligible instance types. `t3.micro` succeeded. Both `RunInstances` events are visible in CloudTrail.

Instance launched: `i-[REDACTED]` | Public IP: `[REDACTED]` | Region: `ap-south-1`

---

## Post-Exploitation Recon

SSH access established:

```bash
ssh -i soc-lab-key.pem ubuntu@[REDACTED]
```

Commands run inside the instance:

### Identity and privilege check

```bash
whoami
# ubuntu

id
# uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),105(lxd)
```

The `ubuntu` user is in the `sudo` group. This means full root access is one `sudo` command away, the attacker can escalate to root without needing a password.

### Network reconnaissance

```bash
netstat -tulpn
```

Port 22 (SSH) confirmed listening. The attacker maps open services for potential lateral movement targets.

### Credential theft attempt

```bash
cat /root/.aws/credentials
# cat: /root/.aws/credentials: Permission Denied
```

The attacker attempted to steal AWS credentials stored on the instance. Blocked, but the attempt is logged in the instance's auth logs.

### Privilege escalation

```bash
sudo cat /etc/shadow
```

Successfully read `/etc/shadow`: the file containing hashed passwords for all system users. With these hashes, an attacker could attempt offline password cracking.

### Key hunting

```bash
find / -name "*.pem" -o -name "*.key" 2>/dev/null
```

Searching the filesystem for private keys or certificates that could enable lateral movement to other systems.

---

## CloudTrail Evidence

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances \
  --region ap-south-1 \
  --max-items 3
```

### Event 1 — RunInstances (failed attempt, t2.micro)

```
EventName:   RunInstances
Username:    root
EventTime:   2026-03-22T03:55:51
Resources:   AMI, KeyPair, SecurityGroup
```

### Event 2 — RunInstances (successful, t3.micro)

```
EventName:   RunInstances
Username:    root
EventTime:   2026-03-22T03:56:36
Resources:
  - AWS::EC2::VPC
  - AWS::EC2::Ami
  - AWS::EC2::NetworkInterface
  - AWS::EC2::Instance       ← i-[REDACTED]
  - AWS::EC2::KeyPair        ← soc-lab-key
  - AWS::EC2::SecurityGroup  ← soc-lab-sg
  - AWS::EC2::Subnet
```

The breadth of resources in a single `RunInstances` event tells a story. A SOC analyst seeing this would immediately ask: who created this key pair, why is a new security group being created, and why does it allow `0.0.0.0/0` on port 22?

---

## Why This Pattern Is Suspicious in CloudTrail

A legitimate admin launching an EC2 instance would typically:
- Use an existing key pair, not create a new one
- Use an existing security group with proper restrictions
- Launch into a known VPC/subnet

This sequence: new key pair + new permissive security group + new instance, all created within minutes of each other, is a strong indicator of an attacker establishing infrastructure rather than a legitimate admin performing routine work.

---

## Screenshots

| File | What It Shows |
|------|--------------|
| `08-ec2-running.png` | EC2 instance in running state with public IP |
| `09-ssh-whoami-id.png` | Shell access confirmed — ubuntu user in sudo group |
| `10-ssh-netstat.png` | Network reconnaissance — open ports mapped |
| `11-ssh-shadow-exfil.png` | /etc/shadow read, *.pem hunt executed |
| `12-ssh-credentials-denied.png` | AWS credential theft attempt — Permission Denied |
| `13-runinstances-successful.png` | CloudTrail — successful RunInstances with full resource list |
| `14-runinstances-failed.png` | CloudTrail — failed RunInstances (t2.micro attempt) |

---

## Remediation

### Containment (immediate)

```bash
aws ec2 terminate-instances \
  --instance-ids i-[REDACTED] \
  --region ap-south-1
```

Verified terminated state via `describe-instances`.

**Important:** Terminating the instance is containment, not full remediation. The attacker still holds the root credentials that were used to launch it. They can launch a new instance immediately.

### Full remediation

```bash
# Revoke attacker access keys
aws iam delete-access-key \
  --user-name attacker-user \
  --access-key-id [REDACTED]

# Verify keys gone
aws iam list-access-keys --user-name attacker-user
# Returns: "AccessKeyMetadata": []

# Remove open SSH rule
aws ec2 revoke-security-group-ingress \
  --group-id sg-[REDACTED] \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0 \
  --region ap-south-1
```

Confirmed by `RevokedSecurityGroupRules` response showing `CidrIpv4: 0.0.0.0/0` removed.

---

## Lessons Learned

- Terminating an EC2 instance is containment only, the credentials that launched it must be revoked before calling the incident resolved
- SSH should never be open to `0.0.0.0/0`, use specific IP allowlists or AWS Systems Manager Session Manager
- `RunInstances` events combined with new key pair and security group creation are a high-confidence indicator of attacker persistence activity
- In production, a CloudWatch alarm on `RunInstances` from unexpected IAM users or at unusual hours would catch this within minutes
- Regular audits of running EC2 instances catch unauthorized infrastructure before the monthly bill does
