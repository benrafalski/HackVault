---
title: "Object Storage (S3 and Blob) Security"
aliases: []
tags: [web, w3, security]
domain: web
phase: "W3"
type: security
status: draft
pair: "[[Object Storage]]"
updated: 2026-11-03
---
# Object Storage (S3 and Blob) Security

> [!abstract] TL;DR
> Public policies, excessive signed-URL scope, and unsafe content serving can disclose data or introduce script/parser attacks.

> [!info] Agent scope
> Security of: Buckets and containers; object keys; identity and resource policies; signed URLs; public access controls; metadata. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Public policies, excessive signed-URL scope, and unsafe content serving can disclose data or introduce script/parser attacks.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive S3/Azure Blob security assuming HTTP and cloud identities.
Trace bucket/container policies, identity grants, public-access blocks, ownership,
encryption-key permissions and signed delegation. Explain why obscure keys,
CORS and encryption at rest do not authorize callers. Compare object/action/time
scope in S3 presigning, account/service SAS and user-delegation SAS. Cover upload
size/type limits, trusted metadata, isolated serving origins, version retention
and audit costs. Build a harmless local Azurite policy fixture narrowing container
SAS to one object, with positive reads and negative metadata/write/expiry tests.
No theft or exploitation. State emulator limitations, use primary sources, and
teach without edits or invented evidence.
```

## Cheatsheet

### Independent Policy Layers

S3 identity policies grant actions to principals; bucket/access-point policies apply to resources. Applicable explicit denies win over allows. Organization policies, permissions boundaries, session policies, endpoint policies and KMS key policies can add constraints. `s3:GetObject` does not automatically grant `s3:ListBucket`, and SSE-KMS reads can require key authorization too. New bucket defaults are not evidence about an old bucket.

Use S3 Block Public Access and bucket-owner-enforced ownership unless a reviewed requirement demands otherwise. An illustrative bucket-policy transport guard for a dedicated example bucket is:

```json
{
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*",
		"Action": "s3:*",
		"Resource": ["arn:aws:s3:::example-w3-private", "arn:aws:s3:::example-w3-private/*"],
		"Condition": {"Bool": {"aws:SecureTransport": "false"}}
	}]
}
```

This denies insecure transport; it grants no access and is not a complete policy. Review AWS-service-principal interactions before attaching transport conditions to real workloads. Scope the uploader to its own prefix and exact actions; do not give it policy management, public ACLs or version deletion merely to upload a file.

Azure separates management-plane RBAC from Blob data actions. Prefer managed identity/Entra and user-delegation SAS; account keys are broad secrets. Disable anonymous Blob access at account level, avoid public containers and disable Shared Key authorization where compatible with the workload. Azurite's shared-key protocol fixture cannot verify those Entra/RBAC account controls.

### Signed Capabilities

| Control | Residual risk |
|---|---|
| Exact object + read-only + short expiry | URL bearer can reuse it until invalid; no automatic single-use guarantee. |
| Server-generated key tied to authenticated owner | Key still needs policy; unguessability alone is not authorization. |
| HTTPS-only SAS / verified TLS | Prevents cleartext transit, not leaks through logs, browser history or referrers. |
| Upload policy/size cap | Client content type is not byte validation; scan/process separately. |
| Credential rotation/revocation | May invalidate many URLs; per-URL revocation is not universally available. |

S3 presigning often happens without a network call; signing a forbidden action can still produce a URL that fails when used. SigV4 URL limits depend on credential lifetime and signing method. Azure service SAS can use a stored access policy for some revocation scenarios; user-delegation SAS and account SAS have different restrictions. Validate the resource type, permissions, protocol and expiry, not merely the presence of a signature.

### Content and Retention

Treat uploaded metadata as untrusted. Set response Content-Type and Content-Disposition through trusted code. Serve arbitrary bytes from an isolated origin without application cookies, usually as attachment; use `X-Content-Type-Options: nosniff` at the serving proxy and appropriate CSP. CORS is a browser read policy, not authentication. A MIME label does not make stored bytes safe for a parser.

Use quotas, upload byte limits, checksum verification and bounded processing. Multipart remnants, old versions, replicas and snapshots can retain data and cost money after an apparent delete. Encryption at rest does not block a permitted API read. Do not promise secure erasure from a current-version deletion alone.

## Detection and Defense

Audit bucket/account policy changes, anonymous-access settings, key rotation and delegation issuance without recording full signed URLs. S3 CloudTrail object data events require deliberate enablement/cost planning; management events are not every object read. Azure Storage resource logs also need diagnostic configuration. Alert on unexpected method/key patterns and download volume, while accounting for legitimate batch jobs and CDN behavior.

## Labs

### Environment and Complete Files

Python 3.12+, PowerShell, Docker Linux containers, Azure Blob SDK `>=12.19,<13`. Record resolved SDK/image versions; Azurite's tag is mutable. **Not executed here.** Port 11001 must be free. The emulator verifies SAS scope but not cloud RBAC, public-access account enforcement, S3 IAM or browser-origin policy. Only bootstrap code receives a synthetic account key; application tests receive a bearer SAS.

### File: requirements.txt
```text
azure-storage-blob>=12.19,<13
```

### File: admin.py
```python
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from azure.storage.blob import (
	BlobServiceClient, BlobSasPermissions, ContainerSasPermissions,
	ContentSettings, generate_blob_sas, generate_container_sas,
)

KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
ENDPOINT = "http://127.0.0.1:11001/labaccount"
fixed = "--fix" in sys.argv
service = BlobServiceClient(ENDPOINT, credential=KEY, api_version="2021-12-02")
if not fixed:
	container = service.create_container("private-lab")
	for name in ["allowed.txt", "other.txt"]:
		container.upload_blob(name, b"synthetic fixture\n", content_settings=ContentSettings(
			content_type="application/octet-stream", content_disposition='attachment; filename="fixture.txt"'))
now = datetime.now(timezone.utc)
common = dict(account_name="labaccount", container_name="private-lab", account_key=KEY,
	protocol="https,http", start=now-timedelta(minutes=1), expiry=now+timedelta(minutes=5))
if fixed:
	token = generate_blob_sas(**common, blob_name="allowed.txt", permission=BlobSasPermissions(read=True))
else:
	token = generate_container_sas(**common, permission=ContainerSasPermissions(read=True))
expired = generate_blob_sas(account_name="labaccount", container_name="private-lab",
	blob_name="allowed.txt", account_key=KEY, permission=BlobSasPermissions(read=True),
	protocol="https,http", start=now-timedelta(minutes=20), expiry=now-timedelta(minutes=10))
Path("delegation.json").write_text(json.dumps({"base": ENDPOINT + "/private-lab/", "token": token, "expired": expired}))
service.close()
print("object-scoped delegation" if fixed else "container-scoped baseline")
```

### File: test_example.py
```python
import json
import unittest
import urllib.error
import urllib.request
from pathlib import Path

CONFIG = json.loads(Path("delegation.json").read_text())

def open_blob(name, token=None, method="GET", data=None):
	url = CONFIG["base"] + name + ("?" + token if token else "")
	headers = {"x-ms-version": "2021-12-02"}
	if method == "PUT":
		headers["x-ms-blob-type"] = "BlockBlob"
	return urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers, method=method), timeout=5)

class StoragePolicy(unittest.TestCase):
	def test_allowed(self):
		with open_blob("allowed.txt", CONFIG["token"]) as response:
			self.assertEqual(response.read(), b"synthetic fixture\n")
			self.assertIn("attachment", response.headers["Content-Disposition"])
			self.assertEqual(response.headers["Content-Type"], "application/octet-stream")

	def test_wrong_object_metadata(self):
		with self.assertRaises(urllib.error.HTTPError) as denied:
			open_blob("other.txt", CONFIG["token"], method="HEAD")
		self.assertEqual(denied.exception.code, 403)

	def test_write_and_expired(self):
		with self.assertRaises(urllib.error.HTTPError) as denied:
			open_blob("allowed.txt", CONFIG["token"], method="PUT", data=b"temporary fixture")
		self.assertEqual(denied.exception.code, 403)
		with self.assertRaises(urllib.error.HTTPError) as expired:
			open_blob("allowed.txt", CONFIG["expired"])
		self.assertEqual(expired.exception.code, 403)

	def test_anonymous(self):
		with self.assertRaises(urllib.error.HTTPError) as denied:
			open_blob("allowed.txt")
		self.assertIn(denied.exception.code, (403, 404))

if __name__ == "__main__":
	unittest.main()
```

### Baseline, Hints, and Solution

```powershell
docker run --name w3-blob-sec -d -p 127.0.0.1:11001:10000 -e AZURITE_ACCOUNTS=labaccount:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY= mcr.microsoft.com/azure-storage/azurite:latest azurite-blob --blobHost 0.0.0.0 --skipApiVersionCheck
docker logs w3-blob-sec
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python admin.py
.\.venv\Scripts\python test_example.py -v
.\.venv\Scripts\python admin.py --fix
.\.venv\Scripts\python test_example.py -v
```

Wait for the Blob listening log before setup. Baseline fails exactly the wrong-object metadata test: a container read SAS permits metadata access to both synthetic objects. No other object's body is downloaded. The fix issues a blob-specific SAS and all four tests should pass; writes and expired tokens remain denied and intended reads retain safe response headers. Hint: `read` permission is narrow by action but can still be broad by resource.

### Troubleshooting and Cleanup

Run within five minutes of issuance. A generic timeout or 401 is not the expected signed-policy failure. API-version-check skipping only accommodates local emulator negotiation. These header assertions do not prove browser CSP/origin isolation, and HTTP SAS is emulator-only. Revoke/discard the generated capability file and remove only this fixture:

```powershell
docker rm -f -v w3-blob-sec
Remove-Item -LiteralPath ./delegation.json
```

Cloud deployment requires separate negative tests for anonymous access, final identity policies, encryption-key grants and public-access blocks using a dedicated authorized account; none is represented as executed here.

- [ ] Local Object Storage exercise: Use a dedicated sandbox or emulator to upload a text object privately and issue a short-lived read URL. Verify anonymous access fails and expiry removes delegated access.
- [ ] Boundary check: Try an anonymous read and a signed URL for a different synthetic object. Both must fail unless explicitly authorized; verify uploaded markup is not executed on the application origin.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W3 Data|W3 Data]]
- [[File Upload Attacks]]
- [[Broken Access Control and IDOR]]
- [[Object Storage]]

## References

- [S3 security best practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [Azure SAS guidance](https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview)
- [Prevent anonymous Blob access](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent)
