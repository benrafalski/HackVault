---
title: "AWS"
aliases: []
tags: [web, w5]
domain: web
phase: "W5"
type: tech
status: draft
pair: "[[AWS Security]]"
updated: 2026-11-03
---
# AWS

> [!abstract] TL;DR
> An account is an ownership and billing boundary, IAM is an authorization system, and a VPC is a network boundary. Design all three independently. Temporary credentials reduce lifetime, not permissions.

> [!info] Agent scope
> Accounts; IAM; STS; VPCs; compute; storage; metadata services; logging; least privilege; cost-controlled sandboxes.

## Prerequisites

- HTTP, CIDR routing, JSON, and the difference between authentication and authorization.
- Required lab: Python 3.12 standard library, any OS, an empty local directory. No AWS CLI, credentials, subscription, network, or paid resources.
- [[Web Lab Setup]]; [[AWS Security]].

## Learn

```text
Teach me AWS infrastructure at expert engineering depth. Assume HTTP, JSON,
CIDR and basic authorization knowledge. Trace account/organization ownership,
regions/AZs, IAM policy evaluation, STS role assumption and credential expiry,
VPC routing/security groups/NACLs/endpoints, EC2/ECS/Lambda identities, S3 and
KMS, IMDSv2 and CloudTrail. Work through an S3 report-reader design including
bucket versus object actions, role trust versus permissions, cross-account
access, explicit deny and boundary/session/organization restrictions. Explain
resource-policy exceptions rather than claiming every policy is intersected.
Compare compute, storage and network cost/failure tradeoffs. Give concrete JSON
and network diagrams, expected evidence and negative/positive checks. Prefer
zero-cost offline fixtures; explicitly separate them from live IAM simulation
and deployed service verification. Use public AWS documentation; identify
version/service caveats. No real credentials or production targets. Teach here,
do not edit files or study status. End with worked design-review questions.
```

## Cheatsheet

### Ownership, Identity, and Evaluation

Organizations groups accounts; organizational units organize policy attachment. An SCP limits available permissions for affected member-account principals; it does not grant permissions. Management-account and service-linked-role exceptions matter. Region selection is not data-residency proof: check replication, backups, logs, and global services.

An IAM role has two different contracts: its **trust policy** controls who can assume it; its **permissions policies** control what sessions may do. STS returns expiring access-key ID, secret, and session token. SDK credential providers refresh supported sources; copying a token into configuration loses refresh behavior. Prefer IAM Identity Center for people and workload roles for compute.

For `AssumeRole`, the normal requested duration ranges from 900 seconds to the role's configured maximum (up to 12 hours); role chaining limits a session to one hour. Other STS APIs and service-managed credentials have different lifetime rules. Refresh before expiration with bounded retry and clock-skew handling; do not assume removing trust immediately recalls every already-issued session. Revocation and permission changes require documented provider procedures and service-specific validation. IAM JSON `Version: 2012-10-17` selects the policy language, not an SDK release or policy creation date.

| Policy/control | Meaning and common error |
|---|---|
| Identity policy | Allows actions on resources; an absent allow is normally implicit deny |
| Resource policy | Can grant access from the resource side; cross-account access usually requires both sides |
| Explicit deny | Overrides applicable allows; do not reduce it to statement ordering |
| Permissions boundary / session policy | Limits permissions, does not independently grant them |
| SCP / RCP | Organization guardrails where supported; coverage and principal exceptions differ |
| KMS key policy | Separate authorization boundary; S3 permission alone need not permit decryption |
| Endpoint policy | Filters API access through an endpoint; does not replace IAM or endpoint routing |

Do not implement IAM by intersecting arbitrary JSON lists. Grants to users, roles and role-session principals have different interactions with implicit denies in boundaries/session policies. Context keys, policy variables, `NotAction`, principal matching and service-specific authorization add further semantics. Use Access Analyzer validation, documented simulation limits, and authorized service tests for real decisions.

### Report-Reader Policy

Complete identity-policy example for a synthetic bucket name; not a deployment. `ListBucket` uses the bucket ARN and the requested prefix; `GetObject` uses object ARNs. The prefix condition does not filter an otherwise broad object grant.

```json
{
  "Version": "2012-10-17",
  "Statement": [
	{
	  "Sid": "ListReports",
	  "Effect": "Allow",
	  "Action": "s3:ListBucket",
	  "Resource": "arn:aws:s3:::example-w5-reports",
	  "Condition": {"StringLike": {"s3:prefix": ["reports/*"]}}
	},
	{
	  "Sid": "ReadReports",
	  "Effect": "Allow",
	  "Action": "s3:GetObject",
	  "Resource": "arn:aws:s3:::example-w5-reports/reports/*"
	}
  ]
}
```

A request listing `reports/` fits the intended prefix; listing the bucket root does not. Versioned reads can require `s3:GetObjectVersion`. SSE-KMS reads can require `kms:Decrypt` and an appropriate key policy. Denying `DeleteObject` does not prevent overwriting via `PutObject`; retention is a separate design.

### Network and Compute Decisions

| Component | Mechanism | Failure/tradeoff |
|---|---|---|
| Public subnet | Route to internet gateway; instance also needs public addressing for direct IPv4 internet connectivity | A route alone does not publish an application; an open SG alone does not create a route |
| Private subnet | No direct internet-gateway route for workload traffic | NAT can enable outbound access and incurs charges; private is not isolated |
| Security group | Stateful allow rules on supported interfaces/resources | Return traffic is tracked; no ordered deny rule |
| NACL | Stateless subnet-level ordered allow/deny rules | Both directions, including ephemeral ports, need consideration |
| VPC endpoint | Private service reachability; gateway/interface types differ | Endpoint policy, DNS, route tables and service IAM must all agree |
| EC2 | OS lifecycle, instance profile, IMDS | Patch guest OS; require IMDSv2; choose hop limit for actual network topology |
| ECS | Task role for app; execution role for platform pulls/logging | Combining roles needlessly expands app authority |
| Lambda | Execution role, event source, concurrency | VPC attachment is not an IAM boundary; private subnets do not automatically provide internet egress |

S3 is regional object storage, not a POSIX filesystem. Single-object writes are atomic; successful PUT/DELETE and listings have strong consistency, but no multi-object transaction. EBS is block storage with AZ placement constraints; EFS is a shared filesystem with its own performance and access model. Choose for semantics before latency claims.

### Metadata, Evidence, and Cost

IMDSv2 uses a session-token requirement at the instance metadata service. Set `HttpTokens=required`, minimize the instance role, and disable metadata when unused. Hop limits are topology-specific, not a universal security score. Do not fetch credentials to prove configuration.

CloudTrail management events describe control-plane API activity; S3 object reads/writes require appropriate data-event configuration and can cost money. VPC Flow Logs describe network flows, not decrypted HTTP bodies. CloudWatch application logs are yet another source. Correlate request ID, role session, resource, region, time, and decision; avoid recording secrets.

Budgets are delayed alerts, not a universal hard stop. A real sandbox needs a separate account, spending alerts, approved regions/services, resource tags, ownership and expiration, teardown inventory, and checks for retained volumes, snapshots, addresses, NAT gateways, logs and buckets. Nothing in the required lab provisions resources.

## Gotchas

- Default encryption does not prove a bucket is private. Block Public Access and Object Ownership address different concerns.
- IAM propagation can be eventually consistent. A transient denial is not proof of a correct policy; retry with bounded backoff and correlate logs.
- CLI and SDK versions change credential chains and service support. Record versions when performing optional real-provider verification; no provider results are asserted here.

## Labs

### Environment and Complete Files

Create an empty directory for this note and place the following single file there. Start/check with `python -m unittest -v test_example`; no services or dependencies are started. The lab compiles a narrowly specified access requirement into real IAM JSON and checks its structure. It **does not evaluate IAM authorization**.

### File: test_example.py

```python
import json
import unittest

BUCKET = "example-w5-reports"


def reader_policy(bucket, prefix):
	if not bucket or "/" in bucket or not prefix.endswith("/"):
		raise ValueError("a bucket name and directory-like prefix are required")
	if any(character in bucket + prefix for character in "*?"):
		raise ValueError("requirements must not contain wildcard operators")
	bucket_arn = f"arn:aws:s3:::{bucket}"
	return {
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "ListReports",
				"Effect": "Allow",
				"Action": "s3:ListBucket",
				"Resource": bucket_arn,
				"Condition": {"StringLike": {"s3:prefix": [prefix + "*"]}},
			},
			{
				"Sid": "ReadReports",
				"Effect": "Allow",
				"Action": "s3:GetObject",
				"Resource": bucket_arn + "/" + prefix + "*",
			},
		],
	}


class PolicyDesignTests(unittest.TestCase):
	def test_action_resource_domains(self):
		listing, reading = reader_policy(BUCKET, "reports/")["Statement"]
		self.assertEqual(listing["Resource"], f"arn:aws:s3:::{BUCKET}")
		self.assertEqual(reading["Resource"], f"arn:aws:s3:::{BUCKET}/reports/*")
		self.assertEqual(listing["Condition"]["StringLike"]["s3:prefix"],
						 ["reports/*"])

	def test_read_only_and_round_trip(self):
		policy = reader_policy(BUCKET, "reports/")
		self.assertEqual(json.loads(json.dumps(policy)), policy)
		self.assertEqual({statement["Action"] for statement in policy["Statement"]},
						 {"s3:ListBucket", "s3:GetObject"})

	def test_reject_ambiguous_requirements(self):
		for prefix in ("", "reports", "*/", "reports/?/"):
			with self.subTest(prefix=prefix), self.assertRaises(ValueError):
				reader_policy(BUCKET, prefix)


if __name__ == "__main__":
	print(json.dumps(reader_policy(BUCKET, "reports/"), indent=2))
	unittest.main()
```

### Objectives and Steps

1. Run `python test_example.py` to see the generated policy and execute its checks.
2. Predict why changing the listing resource to `.../reports/*` is wrong. Make that local change, rerun the same tests, then restore it.
3. Design a separate execution role for a service that writes reports. Explain why adding `PutObject` to the reader would couple unrelated authority.
4. Draw a private compute -> S3 endpoint -> bucket path. Label network reachability, endpoint policy, role policy, bucket policy and optional KMS authorization as distinct checks.

### Hints

The requested prefix is request context for `ListBucket`, not an object ARN. The tests inspect a generated document; neither a green test nor valid JSON proves access on AWS.

### Solution and Expected Results

The supplied implementation is the worked solution: three tests should pass. The deliberate resource-domain edit should fail `test_action_resource_domains`. Restore the bucket ARN for listing. The writer role needs only its actual object-writing actions on its output prefix, not reader administration, IAM, or account-level actions.

A live acceptance matrix would include: listing `reports/` and reading a known report succeed; listing root, reading another prefix, writing and deleting fail. Real verification must additionally exercise applicable bucket, KMS, organization, endpoint and session policies. No such requests are made by this lab.

### Verification, Troubleshooting, and Cleanup

Use Python 3.12 and run from the directory containing the file; `No module named test_example` means the working directory is wrong. No AWS environment variables are read. Delete the directory and its `__pycache__` to reset. Author validation is static only; commands and expected results above were not executed during this revision.

### User-Owned Milestones

The original sandbox milestones remain optional live follow-up work; the offline exercise is not evidence that they are complete.

- [ ] Local AWS exercise: In a dedicated budgeted sandbox, create a role limited to one synthetic storage resource and verify allowed/denied actions. Enable relevant logging and delete resources after the exercise.
- [ ] Boundary check: Use the sandbox role against an unapproved resource and require denial. Review the workload's metadata protection and permissions without retrieving real production credentials.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W5 Infra and Cloud|W5 Infra and Cloud]]
- [[AWS Security]]

## References

- [IAM evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [STS AssumeRole and duration constraints](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [IAM security best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [VPC security groups](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html)
- [EC2 metadata options](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html)
- [CloudTrail data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
