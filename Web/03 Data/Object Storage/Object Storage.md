---
title: "Object Storage (S3 and Blob)"
aliases: []
tags: [web, w3]
domain: web
phase: "W3"
type: tech
status: draft
pair: "[[Object Storage Security]]"
updated: 2026-11-03
---
# Object Storage (S3 and Blob)

> [!abstract] TL;DR
> Default private; scope signed URLs to object/action/time; separate uploads from application origins. Record versioning and cleanup costs before using a cloud sandbox.

> [!info] Agent scope
> Buckets and containers; object keys; identity and resource policies; signed URLs; public access controls; metadata.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me S3 and Azure Blob object-storage engineering assuming HTTP and identity.
Compare buckets/containers, flat keys, metadata, versions, ETags, checksums,
multipart/block uploads, conditional writes and consistency. Explain S3 identity
and resource policies, public-access blocks, Azure RBAC/anonymous controls, and
presigned URLs versus service/user-delegation SAS. Work through private upload,
bounded read delegation, wrong-object/expired-token rejection and content serving.
Use a fully specified local Azurite fixture and label cloud-only IAM differences.
Include lifecycle/retention costs, failure modes, primary sources and version
caveats. Teach here without edits, real cloud credentials or fabricated runs.
```

## Cheatsheet

### Object Model and Consistency

An object key is an identifier, not a local filesystem path. `reports/2026/item.txt` is normally a flat key with delimiter-based listing conventions. Azure hierarchical namespace accounts add filesystem-like semantics and permissions; do not assume every Blob account behaves identically. Normalize and authorize keys in application code without treating path-looking strings as trusted filesystem paths.

S3 provides strong read-after-write consistency for object writes/deletes and listings, but replication and external caches have separate lag. Azure Blob is strongly consistent in its primary region; geo-secondary reads can lag. Neither system provides general relational multi-object transactions. Model a manifest/commit marker or use a database when multiple object updates must be coordinated.

| Mechanism | S3 | Azure Blob |
|---|---|---|
| Large upload | Multipart upload + explicit completion | Stage blocks + commit block list |
| Concurrent write protection | Conditional requests such as If-Match/If-None-Match where supported | ETag conditions and leases |
| Version retention | Versioning + lifecycle, possibly Object Lock | Versions, snapshots, soft delete and immutability policies |
| Metadata | User metadata plus HTTP content headers | Metadata plus HTTP content settings; tags are separate |
| Integrity | Explicit checksum algorithms; ETag is not universally MD5 | Content hashes/checksums per API; ETag is a version token, not a content hash |

Interrupted multipart uploads and retained versions incur storage costs until lifecycle rules or explicit cleanup handle them. A delete marker is not erasure of older versions. Record retention obligations before enabling immutable storage; cleanup may be legally/technically blocked.

### Identity and Public Access

S3 authorization combines identity/resource policies and other account/organization controls; applicable explicit denies override allows. Bucket policies use object ARNs for object actions and bucket ARNs for listing. Newer S3 defaults favor Block Public Access and bucket-owner-enforced ownership with ACLs disabled; audit upgraded/existing buckets rather than assuming defaults.

Illustrative least-privilege S3 identity policy for a precreated dedicated bucket:

```json
{
	"Version": "2012-10-17",
	"Statement": [
		{"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"],
		 "Resource": "arn:aws:s3:::example-w3-private/tenant7/*"},
		{"Effect": "Allow", "Action": "s3:ListBucket",
		 "Resource": "arn:aws:s3:::example-w3-private",
		 "Condition": {"StringLike": {"s3:prefix": ["tenant7/*"]}}}
	]
}
```

The bucket name is an example, not an existing target. For a provisioned sandbox, AWS CLI v2 public-access control is:

```powershell
aws s3api put-public-access-block --bucket $env:LAB_BUCKET --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
```

Use an operator identity for that command, never the runtime uploader. Azure management-plane rights are distinct from data-plane `Storage Blob Data Reader/Contributor`. Prefer Entra identities and user-delegation SAS in production; an account key has broad authority. Azure account `allowBlobPublicAccess=false` prevents container anonymous access even if a container setting requests it. CORS controls browser access, not caller authorization.

### Delegation and Serving

Presigned URLs and SAS are bearer capabilities: anyone possessing the URL can use it within its constraints. S3 signing example for an already provisioned runtime identity and bucket (requires boto3):

```python
import boto3

s3 = boto3.client("s3")
url = s3.generate_presigned_url("get_object", Params={
		"Bucket": "example-w3-private", "Key": "tenant7/report.txt",
		"ResponseContentDisposition": 'attachment; filename="report.txt"'
}, ExpiresIn=300)
```

Signing may happen locally without a service permission check; URL generation success does not prove access. Temporary signing credentials can expire before the requested URL lifetime. SigV4 method, target, headers and time are part of the authorization contract. A delegated upload needs its own size/type/key controls; a content-type header alone does not validate bytes.

Serve untrusted uploads from a separate origin, usually as attachment with a safe content type. Separate ingest, scanning/processing and download identities. Metadata is user input unless overwritten by trusted code. Encryption at rest protects storage media but does not stop an authorized API from returning plaintext.

## Gotchas

An unguessable object key is not authorization. Encryption at rest does not prevent an overly permissive storage policy from returning plaintext.

## Labs

### Environment and Complete Files

Python 3.12+, PowerShell, Docker Linux containers and Azure Blob SDK `>=12.19,<13`. Official Azurite image uses a mutable tag; record its digest and installed SDK version. **Not executed here.** This exercises Blob/SAS protocol behavior, not Azure RBAC, Entra, S3 IAM or cloud durability. Port 11000 must be free. Account key is a public synthetic fixture; only bootstrap code uses it.

### File: requirements.txt
```text
azure-storage-blob>=12.19,<13
```

### File: setup.py
```python
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from azure.storage.blob import BlobServiceClient, BlobSasPermissions, ContentSettings, generate_blob_sas

ACCOUNT = "labaccount"
KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
ENDPOINT = "http://127.0.0.1:11000/labaccount"
service = BlobServiceClient(ENDPOINT, credential=KEY, api_version="2021-12-02")
container = service.create_container("private-lab")
for name in ["report.txt", "other.txt"]:
	container.upload_blob(name, b"synthetic report\n", metadata={"classification": "fixture"},
		content_settings=ContentSettings(content_type="text/plain", content_disposition='attachment; filename="report.txt"'))
now = datetime.now(timezone.utc)
common = dict(account_name=ACCOUNT, container_name="private-lab", blob_name="report.txt",
	account_key=KEY, permission=BlobSasPermissions(read=True), protocol="https,http")
active = generate_blob_sas(**common, start=now-timedelta(minutes=1), expiry=now+timedelta(minutes=5))
expired = generate_blob_sas(**common, start=now-timedelta(minutes=20), expiry=now-timedelta(minutes=10))
Path("delegation.json").write_text(json.dumps({"base": ENDPOINT + "/private-lab/", "active": active, "expired": expired}))
service.close()
print("Delegations created; run tests within five minutes")
```

### File: test_example.py
```python
import json
import unittest
import urllib.error
import urllib.request
from pathlib import Path

CONFIG = json.loads(Path("delegation.json").read_text())

class BlobMechanisms(unittest.TestCase):
	def test_signed_read(self):
		with urllib.request.urlopen(CONFIG["base"] + "report.txt?" + CONFIG["active"], timeout=5) as response:
			self.assertEqual(response.read(), b"synthetic report\n")
			self.assertIn("attachment", response.headers["Content-Disposition"])
			self.assertEqual(response.headers["x-ms-meta-classification"], "fixture")

	def test_scope_and_expiry(self):
		for suffix in ["report.txt", "other.txt?" + CONFIG["active"], "report.txt?" + CONFIG["expired"]]:
			with self.subTest(suffix=suffix.split("?")[0]):
				with self.assertRaises(urllib.error.HTTPError) as denied:
					urllib.request.urlopen(CONFIG["base"] + suffix, timeout=5)
				self.assertIn(denied.exception.code, (403, 404))

if __name__ == "__main__":
	unittest.main()
```

```powershell
docker run --name w3-blob-tech -d -p 127.0.0.1:11000:10000 -e AZURITE_ACCOUNTS=labaccount:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY= mcr.microsoft.com/azure-storage/azurite:latest azurite-blob --blobHost 0.0.0.0 --skipApiVersionCheck
docker logs w3-blob-tech
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python setup.py
.\.venv\Scripts\python test_example.py -v
```

### Objectives, Hints, and Solution

Wait for the log's Blob service listening message before setup. Explain the difference between bootstrap account authority and a read-only object SAS. Expected: two tests pass, signed read returns the exact bytes/metadata, anonymous read fails, changing the object invalidates delegation, and a pre-expired token is denied without sleeping. Hint: SAS generation itself is not a network permission test. Anonymous denial may be 404 to hide resource existence; signed-token failures should be inspected as authorization failures.

### Troubleshooting and Cleanup

Clock skew and five-minute token expiry can invalidate an otherwise correct fixture. Recreate the container and rerun setup for a fresh test; setup intentionally fails if the container already exists. `--skipApiVersionCheck` relaxes Azurite's API-version gate, not all semantic differences. HTTP is for this loopback emulator only. Remove the fixture and generated bearer-token file:

```powershell
docker rm -f -v w3-blob-tech
Remove-Item -LiteralPath ./delegation.json
```

Leave browser-origin/CSP enforcement, cloud policy evaluation and real-account encryption/retention checks as separate deployment gates; this protocol test does not certify them.

- [ ] Local Object Storage exercise: Use a dedicated sandbox or emulator to upload a text object privately and issue a short-lived read URL. Verify anonymous access fails and expiry removes delegated access.
- [ ] Boundary check: Try an anonymous read and a signed URL for a different synthetic object. Both must fail unless explicitly authorized; verify uploaded markup is not executed on the application origin.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W3 Data|W3 Data]]
- [[File Upload Attacks]]
- [[Broken Access Control and IDOR]]
- [[Object Storage Security]]

## References

- [S3 consistency](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html#ConsistencyModel)
- [S3 presigned URLs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html)
- [Azure SAS overview](https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview)
- [Azurite](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azurite)
