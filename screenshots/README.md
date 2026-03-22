# Screenshots

All screenshots are taken from the live AWS environment (Console and CLI) during attack simulation and detection.

**Redaction:** Account ID, access key IDs, source IPs, instance IDs, and ARNs are blurred in all screenshots. Standard practice when sharing investigation artifacts publicly.

| File | Contents |
|------|----------|
| `01-cloudtrail-active.png` | CloudTrail trail active and logging |
| `02-cli-identity.png` | `get-caller-identity` confirming CLI connection |
| `03-attach-policy-denied.png` | `AttachUserPolicy` AccessDenied in CloudTrail |
| `04-create-accesskey-caught.png` | `CreateAccessKey` event — attacker-user |
| `05-putbucketpolicy-caught.png` | `PutBucketPolicy` with `Principal: *` in CloudTrail JSON |
| `06-deletebucketpolicy.png` | `DeleteBucketPolicy` — remediation logged |
| `07-ec2-running.png` | EC2 instance running with public IP |
| `08-ssh-recon.png` | Shell inside instance — recon output |
| `09-runinstances-cloudtrail.png` | `RunInstances` event with full resource list |
| `10-instance-terminated.png` | Instance in terminated state |
| `11-accesskey-revoked.png` | Empty `AccessKeyMetadata` after key deletion |
| `12-ssh-rule-removed.png` | `0.0.0.0/0` SSH rule revoked |
