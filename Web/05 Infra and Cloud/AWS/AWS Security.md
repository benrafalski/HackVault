---
title: "AWS Security"
aliases: []
tags: [web, w5, security]
domain: web
phase: "W5"
type: security
status: draft
pair: "[[AWS]]"
updated: 2026-11-03
---
# AWS Security

> [!abstract] TL;DR
> Review trust, permission, exposure, and evidence independently. A hardened launch template or policy document is an intention; runtime configuration and effective authorization require separate verification.

> [!info] Agent scope
> Security of: Accounts; IAM; STS; VPCs; compute; storage; metadata services; logging; least privilege; cost-controlled sandboxes. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Role trust and session creation; workload API authority; public storage and compute exposure; metadata availability; CI deployment authority; logging and encryption administration.
- Security review must include who can change these controls, not merely what today's application role can read. Keep administrators, deployers, workloads and log readers separate.

## Learn

```text
Teach me defensive AWS security review, assuming IAM JSON, STS and VPC basics.
Explain role trust versus permission, cross-account boundaries, session and
organization restrictions, least-privilege S3/KMS access, Block Public Access,
IMDSv2 configuration, workload segregation, network exposure and CloudTrail
coverage. Give concrete baseline/fixed configurations and harmless offline
regression fixtures. Distinguish configuration linting from complete AWS policy
evaluation and actual service authorization. Explain supported defaults,
service exceptions, rollout risks, detection false positives and evidence
retention. Use only public primary sources. No exploitation, credential access,
public lab endpoints or paid resources. Teach in this conversation without file
edits; finish with worked review cases including preserved legitimate access.
```

## Cheatsheet

### Review the Four Boundaries

| Boundary | Concrete requirement | Evidence / limitation |
|---|---|---|
| Trust | Dedicated principal; federation issuer, audience and subject scoped to workload/environment | Role trust policy and federation configuration; accepting a token is not permission to access S3 |
| Permission | Exact needed actions and resource prefixes; restrict passing roles to approved role/service combinations | Identity, resource, session, boundary, SCP/RCP and KMS policies; simplistic wildcard scanning misses grants |
| Exposure | No unintended public IP/listener; account and bucket public-access controls; private service endpoints where appropriate | Route/SG/NACL/DNS review plus effective resource configuration |
| Evidence | Centralized, protected control-plane audit and selected data events | CloudTrail data events are not automatically covered by management-event history |

`Action: "s3:*", Resource: "*"` is excessive for a report reader even inside a private subnet. Replace it with separate `s3:ListBucket` on the bucket and `s3:GetObject` on the report prefix, as in [[AWS]]. Do not use blanket explicit denies without checking service integrations; denies can lock out recovery and delivery workflows.

### Concrete Hardening Fragments

Launch-template `LaunchTemplateData` fragment, not a complete template:

```json
{
  "MetadataOptions": {
	"HttpEndpoint": "enabled",
	"HttpTokens": "required",
	"HttpPutResponseHopLimit": 1,
	"InstanceMetadataTags": "disabled"
  },
  "Monitoring": {"Enabled": false}
}
```

This example's hop limit fits a direct-host metadata consumer. Some container topologies need a different hop limit; prefer a workload-specific identity architecture and test compatibility rather than disabling the token requirement. `Monitoring.Enabled=false` concerns detailed EC2 monitoring cost, not CloudTrail or application audit. Set the endpoint to `disabled` if the workload needs no metadata, after verifying dependency behavior.

S3 Public Access Block configuration object:

```json
{
  "BlockPublicAcls": true,
  "IgnorePublicAcls": true,
  "BlockPublicPolicy": true,
  "RestrictPublicBuckets": true
}
```

Account, bucket and access-point settings combine restrictively. Bucket-owner-enforced Object Ownership disables ACLs for that bucket; it is not the same setting as Block Public Access. Explicitly declare intended controls rather than relying on creation-date defaults. CORS affects browsers, not bucket authorization. Encryption at rest does not revoke a public read grant.

A bucket-policy transport guard, with a service-principal exception for service-to-service context handling; attach only after integration review:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
	"Sid": "DenyInsecureNonServiceTransport",
	"Effect": "Deny",
	"Principal": "*",
	"Action": "s3:*",
	"Resource": ["arn:aws:s3:::example-w5-reports", "arn:aws:s3:::example-w5-reports/*"],
	"Condition": {"Bool": {"aws:SecureTransport": "false", "aws:PrincipalIsAWSService": "false"}}
  }]
}
```

This deny grants nothing. Service-principal handling, absent condition keys and delegated service roles require actual policy review. Never copy a synthetic bucket ARN into production and assume coverage.

### Supply Chain and Segregation

Build in a non-deploying identity; verify the artifact digest, builder identity and source revision before deployment. An SBOM inventories contents; it is not approval. Give the deployer only its approved resources and approved role-passing targets. The runtime should not modify its own IAM role, logging destination or release policy. Use short sessions and reviewed identity federation instead of stored access keys.

## Detection and Defense

Monitor trust-policy edits, permission attachment changes, public-access configuration changes, metadata-option changes and audit-delivery failures. Correlate approved change windows, actor/session issuer, resource ARN and source event. A successful role assumption is not inherently suspicious; an unapproved trust expansion is actionable even without subsequent data access.

Use Config/Access Analyzer findings as inputs to review, not substitutes for service tests. Alert on logging stopped or destinations changed; protect log administration with a separate identity. Minimize logged request bodies and retain only necessary identifiers. Budget alarms detect cost trends but cannot guarantee zero spend; the exercise below is entirely offline.

## Labs

### Environment and Complete Files

Python 3.12 standard library only. Use an empty directory; save the single file below. All data is synthetic and embedded. `python -m unittest -v test_example` starts and checks the lab without any network, credentials or provider SDK. This is a fixed organizational **configuration-contract checker**, not an IAM evaluator or AWS compliance certification.

### File: test_example.py

```python
import copy
import unittest

BASELINE = {
	"metadata": {"HttpTokens": "optional"},
	"public_access": {"BlockPublicAcls": True, "IgnorePublicAcls": True,
					  "BlockPublicPolicy": False, "RestrictPublicBuckets": True},
	"reader_actions": ["s3:GetObject", "s3:PutObject"],
	"reader_resource": "arn:aws:s3:::example-w5-reports/reports/*",
	"data_events": False,
	"build_role": "builder",
	"runtime_role": "reader",
}


def findings(config):
	result = set()
	if config.get("metadata", {}).get("HttpTokens") != "required":
		result.add("metadata-token-required")
	controls = config.get("public_access", {})
	for name in ("BlockPublicAcls", "IgnorePublicAcls",
				 "BlockPublicPolicy", "RestrictPublicBuckets"):
		if controls.get(name) is not True:
			result.add("public-access-block")
	if set(config.get("reader_actions", [])) != {"s3:GetObject"}:
		result.add("reader-actions")
	if config.get("reader_resource") != "arn:aws:s3:::example-w5-reports/reports/*":
		result.add("reader-resource")
	if config.get("data_events") is not True:
		result.add("data-event-coverage")
	if not config.get("runtime_role") or config.get("build_role") == config.get("runtime_role"):
		result.add("role-separation")
	return result


def hardened():
	config = copy.deepcopy(BASELINE)
	config["metadata"]["HttpTokens"] = "required"
	config["public_access"]["BlockPublicPolicy"] = True
	config["reader_actions"] = ["s3:GetObject"]
	config["data_events"] = True
	return config


class HardeningTests(unittest.TestCase):
	def test_baseline_evidence(self):
		self.assertEqual(findings(BASELINE), {
			"metadata-token-required", "public-access-block",
			"reader-actions", "data-event-coverage"})

	def test_fixed_retest_and_retained_read(self):
		config = hardened()
		self.assertEqual(findings(config), set())
		self.assertEqual(config["reader_actions"], ["s3:GetObject"])
		self.assertEqual(config["reader_resource"], BASELINE["reader_resource"])

	def test_missing_control_fails_closed(self):
		config = hardened()
		del config["public_access"]["IgnorePublicAcls"]
		self.assertIn("public-access-block", findings(config))

	def test_segregation_regression(self):
		config = hardened()
		config["build_role"] = config["runtime_role"]
		self.assertIn("role-separation", findings(config))


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

1. Predict the exact four baseline finding IDs, then run the test command.
2. Locate each root cause in the baseline fixture and explain why private networking would not fix it.
3. Compare `hardened()` with the baseline. Verify permitted report-reading intent remains present.
4. Remove one public-access key or merge the build/runtime roles and rerun. Identify which regression catches it.

### Hints

Missing is not equivalent to explicitly enabled. Set equality checks authority for this exact fixture, not the AWS action namespace. `data_events=True` is a design flag, not evidence that an actual trail is delivering events.

### Solution and Fixed Retest

The supplied `hardened()` is the worked fix: require metadata tokens, enable the missing public-access control, remove writing from the reader and require data-event coverage. Four tests should pass while explicitly recognizing the baseline's four findings. Permitted read intent and resource prefix are preserved; real `GetObject` success is deliberately not claimed.

For deployment approval, additionally inspect effective launch settings, bucket/access-point/account configuration, every applicable policy, and audit delivery. Run a synthetic allowed read and denied write only in a separately authorized sandbox; no account or unwritten cloud setup is required to complete this local exercise.

### Verification, Troubleshooting, and Cleanup

Run in this note's own directory to avoid importing another note's `test_example`. No package install is needed. A failing expected finding usually means the fixture was changed without updating the intended contract. Restore the printed fixture to reset; delete its directory and `__pycache__` to clean up. Static review only in this revision; neither tests nor provider checks were executed.

### User-Owned Milestones

Original optional cloud milestones are retained without completion claims.

- [ ] Local AWS exercise: In a dedicated budgeted sandbox, create a role limited to one synthetic storage resource and verify allowed/denied actions. Enable relevant logging and delete resources after the exercise.
- [ ] Boundary check: Use the sandbox role against an unapproved resource and require denial. Review the workload's metadata protection and permissions without retrieving real production credentials.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W5 Infra and Cloud|W5 Infra and Cloud]]
- [[AWS]]

## References

- [IAM best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [S3 condition-key policy examples](https://docs.aws.amazon.com/AmazonS3/latest/userguide/amazon-s3-policy-keys.html)
- [EC2 metadata options](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html)
- [IAM Access Analyzer policy validation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html)
