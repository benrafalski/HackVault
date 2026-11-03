---
title: "Insecure Deserialization"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# Insecure Deserialization

> [!abstract] TL;DR
> Deserializing untrusted object graphs can invoke constructors, callbacks, or type-specific behavior that the application did not intend to authorize.

> [!info] Agent scope
> Untrusted object graphs; type construction; gadget prerequisites; integrity versus safety; schema-based alternatives.

## Learn

```text
Teach insecure deserialization as delegation of object construction and behavior
to untrusted data. Assume serialization, classes, callbacks, schemas, and service
identities. Compare native object graphs, polymorphic metadata, YAML loaders,
and data-only JSON. Explain gadget prerequisites conceptually: reachable types,
library versions, invocation paths, and authority, without gadget code or chains.
Separate integrity/authenticity from safe semantics, replay, audience, and schema.
Review a bounded JSON command DTO with duplicate-field, type, range, version,
and unknown-field rejection before explicit construction. Cover .NET BinaryFormatter,
Python pickle, Java filters, and dependency updates using primary sources.
Give secure tests and review questions with answers. No object callback demos,
RCE, payloads, bypasses, theft, scanning, or chains. Do not author files or invent
test passes; explain what parsing and schema tests cannot establish.
```

## Cheatsheet

> [!important] Defensive scope
> This page uses data-only JSON and explicit construction of a harmless DTO. It contains no native object payloads, gadget implementations, or callback execution demonstrations.

### Root Cause and Variants

Some serializers reconstruct classes, references, and callbacks rather than only values. Untrusted bytes can then influence behavior before ordinary application authorization runs. A gadget requires a reachable type and an invocation path in the deployed dependency set; a library name alone does not demonstrate impact. Later method calls on deserialized objects can matter as much as the initial parse.

| Input path | Risk boundary | Safer contract |
|---|---|---|
| Native object formats | Type instantiation and restoration hooks | Data-only interchange, explicit DTO construction |
| Polymorphic JSON/XML | Caller selects runtime type | Closed discriminator map to inert data classes |
| YAML object loaders | Tags construct application objects | Safe data loader plus independent schema |
| Internal signed messages | Trusted sender may still send overpowered objects | Verify envelope, then narrow data schema and authorization |
| Cached/session objects | Stored bytes later cross a new trust boundary | Treat storage integrity and format safety separately |

Base64 and compression change representation, not trust. A valid signature authenticates bytes under a key; it does not make every represented object safe. Verify a bounded authenticated envelope before processing its payload, and enforce issuer/audience/purpose/lifetime/replay policy as appropriate. Do not deserialize merely to discover which trust policy should apply.

### Version and Parser Details

Python `pickle` explicitly warns against untrusted data. JSON avoids arbitrary Python object construction by default, but custom `object_hook` logic can reintroduce type selection. Python's JSON parser accepts duplicate names and nonstandard numeric constants by default; reject them where the schema requires unambiguous canonical values. Booleans are subclasses of integers in Python, so exact type checks matter for numeric business fields.

.NET 9's in-box BinaryFormatter implementation throws on use; compatibility packages are not a security fix. Java serialization filters can restrict classes, graph depth, references, and bytes, but are a mitigation for legacy contracts, not proof that allowed types have safe semantics. YAML safe loading prevents arbitrary object construction in supported loaders but still needs depth, size, and schema checks.

Evidence should record entry point, format, actual serializer/version/options, permitted types, callbacks, and downstream use. A parse exception does not prove a gadget executed. Resource exhaustion from large/deep graphs is a separate risk even with no powerful callback.

## Defense

Migrate to versioned data contracts, reject unknown fields, and instantiate only explicitly selected inert DTOs after validation. Keep decoding separate from mutation and authorization. Bound input before parsing, use a hardened parser for hostile high-volume inputs, and constrain worker resources. Integrity checks, least privilege, and dependency patches remain additional layers.

## Labs

### Environment and Objectives

Python 3.12 stdlib; one file, no services/packages. Review a proposed consumer that accepts arbitrary runtime type metadata. The replacement accepts a versioned stock-adjustment DTO, not a behavior-bearing object. It returns data only; no inventory is mutated. All messages are synthetic.

### File: test_example.py

```python
from dataclasses import dataclass
import json
import unittest


@dataclass(frozen=True)
class Adjustment:
	sku: str
	quantity: int


def unique_fields(pairs):
	result = {}
	for key, value in pairs:
		if key in result:
			raise ValueError("duplicate field")
		result[key] = value
	return result


def reject_constant(value):
	raise ValueError("nonstandard numeric constant")


def decode_adjustment(blob):
	if type(blob) is not bytes or len(blob) > 512:
		raise ValueError("message size")
	data = json.loads(blob, object_pairs_hook=unique_fields,
					  parse_constant=reject_constant)
	if type(data) is not dict or set(data) != {"version", "sku", "quantity"}:
		raise ValueError("message fields")
	if type(data["version"]) is not int or data["version"] != 1:
		raise ValueError("version")
	if type(data["sku"]) is not str or data["sku"] not in {"BOOK", "PEN"}:
		raise ValueError("sku")
	if type(data["quantity"]) is not int or not 1 <= data["quantity"] <= 10:
		raise ValueError("quantity")
	return Adjustment(data["sku"], data["quantity"])


class DeserializationTests(unittest.TestCase):
	def test_explicit_dto(self):
		self.assertEqual(decode_adjustment(b'{"version":1,"sku":"BOOK","quantity":2}'),
						 Adjustment("BOOK", 2))

	def test_invalid_contracts(self):
		base = {"version": 1, "sku": "BOOK", "quantity": 2}
		changes = [{"runtime_type": "Report"}, {"quantity": True},
				   {"quantity": [2]}, {"quantity": 11}, {"version": 2}]
		for change in changes:
			with self.subTest(change=change), self.assertRaises(ValueError):
				decode_adjustment(json.dumps(base | change).encode())

	def test_duplicate_and_nonstandard_number(self):
		for blob in [b'{"version":1,"version":1,"sku":"BOOK","quantity":2}',
					 b'{"version":1,"sku":"BOOK","quantity":NaN}']:
			with self.subTest(blob=blob), self.assertRaises(ValueError):
				decode_adjustment(blob)

	def test_size_bound(self):
		with self.assertRaises(ValueError):
			decode_adjustment(b" " * 513)


if __name__ == "__main__":
	unittest.main()
```

### Commands, Hints, and Separate Solution

```powershell
py -3.12 -m unittest -v test_example
```

Use `python3.12` on other systems. Hint: why is `type(quantity) is int` used instead of `isinstance(quantity, int)`? Why reject metadata instead of ignoring it?

Solution: the parser produces ordinary values, the closed schema removes type selection, and the final constructor is chosen by trusted code. Expected: four tests pass; duplicate keys, extra metadata, booleans, collections, and unsupported versions are rejected. The DTO is immutable but not automatically authorized. A consumer must authenticate the producer and validate permission before applying an adjustment.

### Verification, Troubleshooting, and Cleanup

No tests ran during authoring. Run beside the named file; do not shadow `json` or `dataclasses` with local filenames. Input is capped at 512 bytes, but this is not a comprehensive streaming parser or adversarial CPU benchmark. Remove the disposable exercise directory; no persistent state or callbacks were created.

- [ ] Local Insecure Deserialization exercise: Review the migration to an explicit data contract.
- [ ] Boundary check: Run schema, type, duplicate-field, and size regressions.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [Python pickle security warning](https://docs.python.org/3.12/library/pickle.html)
- [Python JSON compliance details](https://docs.python.org/3.12/library/json.html)
- [Microsoft BinaryFormatter security guide](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide)
- [Oracle Java serialization filtering](https://docs.oracle.com/en/java/javase/21/core/serialization-filtering1.html)
