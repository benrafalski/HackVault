---
title: "Serialization Security"
aliases: []
tags: [web, w2, security]
domain: web
phase: "W2"
type: security
status: draft
pair: "[[Serialization]]"
updated: 2026-11-03
---
# Serialization Security

> [!abstract] TL;DR
> Admit a small data language, not arbitrary objects. Reject ambiguous records before binding; disable external resolution, constrain construction, and enforce independent byte, structure, and work limits.

> [!info] Agent scope
> Security of: JSON; XML; YAML; schemas; parser options; type construction; entity resolution; resource limits; trust boundaries. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

HTTP bodies, queue messages, import files, caches, signed envelopes, and configuration each cross a trust boundary. The risky operations are not only parsing: schema retrieval, object hooks, property binding, graph traversal, and later transformations can add capabilities. All exercises here use small offline fixtures, without external references or executable type tags.

## Learn

```text
Teach defensive serialization security for JSON, XML, and YAML at expert depth.
Assume Python and schema basics. Trace raw/compressed bytes, parser options,
duplicate handling, type construction, schema validation, authorization, and
state mutation. Explain parser disagreement, nonfinite numbers, boolean/int
confusion, XML DTD/entity/schema resolution, YAML implicit types/aliases/tags,
and unsafe native object reconstruction without any executable payloads.
Compare Python 3.12 json, PyYAML 6.0.x SafeLoader, defusedxml 0.7.1, .NET
XmlReaderSettings and System.Text.Json allowlisted polymorphism conceptually.
Give an offline real-parser lab with small benign records, a last-key-wins
baseline, strict rejection, an empty DTD policy test, and a harmless unknown tag.
Include exact files, commands, expected results, limits, and positive regression
tests. Separate preparse bytes, event-time limits, postparse schema checks,
decompression limits and external worker budgets. Explain signatures versus
safety, error/log redaction, version drift and remaining assumptions. Use
primary sources; do not fabricate execution or provide exploitation, external
entity references, object gadgets, escapes, or denial-of-service recipes.
```

## Cheatsheet

### Trust Decisions

| Stage | Required invariant | Concrete approach |
|---|---|---|
| Transport | Fixed media type and bounded decoded body | Reject unsupported encodings; count decompressed bytes, not just Content-Length |
| JSON parse | One interpretation of each name and number | Duplicate-rejecting pairs hook; reject nonfinite values; bounded numeric grammar |
| XML parse | No implicit file/network capability | Forbid DTD/entities/externals; do not invoke XInclude or untrusted XSLT |
| YAML compose | No unexpected graph or type features | SafeLoader plus event policy; reject aliases/custom tags if unnecessary |
| Binding | Only writable fields and approved concrete types | Separate DTO; exact schema; explicit discriminator-to-type map |
| State change | Valid data is still authorized | Check actor/action/resource independently of parser success |

Do not pass untrusted data to `pickle`, native object streams, or a polymorphic deserializer that selects arbitrary runtime classes. A valid signature proves origin/integrity under a key policy; a trusted producer can still send an unsafe graph or an incompatible schema. A data-only wire format is the simpler contract.

### Exact Parser Configuration

Python XML fragment for a bounded body:

```python
from defusedxml.ElementTree import fromstring
root = fromstring(body, forbid_dtd=True, forbid_entities=True, forbid_external=True)
```

Equivalent .NET defensive reader fragment, with an existing input stream:

```csharp
var settings = new System.Xml.XmlReaderSettings
{
	DtdProcessing = System.Xml.DtdProcessing.Prohibit,
	XmlResolver = null,
	MaxCharactersInDocument = 65536,
	MaxCharactersFromEntities = 1024
};
using var reader = System.Xml.XmlReader.Create(input, settings);
```

These are not interchangeable with a network-only prohibition: disabling network access alone may leave local resolution enabled. A schema validator must also use fixed local schemas and an explicit import resolver. Rejecting a DTD is a policy choice; ordinary XML elements and predefined character escapes still work.

For `System.Text.Json`, use explicit DTOs and reviewed `JsonDerivedType`/`JsonPolymorphic` declarations when polymorphism is needed. A client discriminator should select from a fixed contract, never `Type.GetType` on a client string. In .NET 9+, BinaryFormatter's in-box implementation throws; that does not make legacy compatibility packages safe.

### Limits and Ambiguities

- A JSON pairs hook can detect duplicates but only after the nested value has been parsed. It is not a parser-depth limiter.
- `parse_constant` does not catch a finite-looking exponent converted to infinity. Parse as Decimal or reject all floats when the schema needs only integers.
- SafeLoader still supports aliases, timestamps, booleans, and recursive containers. Reject unused features before construction; use cycle-aware traversal if graphs are permitted.
- Postparse depth checks cannot undo allocations. Streaming/event parsers reduce intermediate allocations, but still need token-length, byte, time, and process memory limits.
- A schema allowing `additionalProperties` is not necessarily wrong. It is wrong when an overbroad binder later treats extra fields as privileged state.

## Detection and Defense

Record parser/version, content type, size, error class, schema version and correlation ID, not body contents or resolved paths. Observe egress from parsing workers: ordinary data ingestion should not initiate network access. Duplicate-key and unsupported-tag counts are useful signals but can also indicate producer bugs. Keep rejected fixtures bounded and synthetic. Compare every rejection with a valid control so that a broken parser is not mistaken for a security control.

## Labs

### Environment and Complete Files

Fresh directory; CPython 3.12; PyYAML 6.0.2; defusedxml 0.7.1; pytest 8.3.5. All fixtures are embedded, at most 513 bytes. No HTTP, external XML references, native object loading, or companion note. **Unexecuted author example.**

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install PyYAML==6.0.2 defusedxml==0.7.1 pytest==8.3.5
.venv\Scripts\python -m pytest -q
```

### File: test_example.py

```python
import json
import pytest
import yaml
from defusedxml.ElementTree import fromstring
from defusedxml.common import DTDForbidden
from yaml.events import (AliasEvent, MappingStartEvent, MappingEndEvent,
						 SequenceStartEvent, SequenceEndEvent)


def bounded(raw):
	if type(raw) is not bytes or len(raw) > 512:
		raise ValueError("size/type")
	return raw.decode("utf-8")


def pairs(values):
	result = {}
	for key, value in values:
		if type(key) is not str or key in result:
			raise ValueError("keys")
		result[key] = value
	return result


def no_number(value):
	raise ValueError("only integer numbers")


def schema(value):
	if type(value) is not dict or set(value) != {"name", "count"}:
		raise ValueError("fields")
	if type(value["name"]) is not str or not 1 <= len(value["name"]) <= 20:
		raise ValueError("name")
	if type(value["count"]) is not int or not 0 <= value["count"] <= 10:
		raise ValueError("count")
	return value


def read_json(raw):
	return schema(json.loads(bounded(raw), object_pairs_hook=pairs,
							 parse_constant=no_number, parse_float=no_number))


class StrictLoader(yaml.SafeLoader):
	pass


def construct_mapping(loader, node):
	return pairs((loader.construct_object(key, deep=True),
				  loader.construct_object(value, deep=True))
				 for key, value in node.value)


StrictLoader.add_constructor("tag:yaml.org,2002:map", construct_mapping)


def read_yaml(raw):
	text = bounded(raw)
	depth = 0
	for event in yaml.parse(text, Loader=yaml.SafeLoader):
		if isinstance(event, AliasEvent) or getattr(event, "tag", None) is not None:
			raise ValueError("aliases/explicit tags")
		if isinstance(event, (MappingStartEvent, SequenceStartEvent)):
			depth += 1
			if depth > 3:
				raise ValueError("depth")
		if isinstance(event, (MappingEndEvent, SequenceEndEvent)):
			depth -= 1
	return schema(yaml.load(text, Loader=StrictLoader))


def read_xml(raw):
	root = fromstring(bounded(raw), forbid_dtd=True, forbid_entities=True,
					  forbid_external=True)
	if root.tag != "record" or root.attrib or (root.text or "").strip():
		raise ValueError("root")
	if any(child.attrib or len(child) or (child.tail or "").strip()
		   for child in root):
		raise ValueError("elements")
	value = pairs((child.tag, child.text or "") for child in root)
	count = value.get("count", "")
	if count not in {str(number) for number in range(11)}:
		raise ValueError("count syntax")
	value["count"] = int(count)
	return schema(value)


def test_duplicate_baseline_and_fix():
	raw = b'{"name":"Ada","count":1,"count":2}'
	assert json.loads(raw)["count"] == 2
	with pytest.raises(ValueError, match="keys"):
		read_json(raw)


@pytest.mark.parametrize("reader,raw", [
	(read_json, b'{"name":"Ada","count":2}'),
	(read_yaml, b'name: Ada\ncount: 2'),
	(read_xml, b'<record><name>Ada</name><count>2</count></record>'),
])
def test_permitted_records(reader, raw):
	assert reader(raw) == {"name": "Ada", "count": 2}


@pytest.mark.parametrize("raw", [
	b'{"name":"Ada","count":true}',
	b'{"name":"Ada","count":2.0}',
	b'{"name":"Ada","count":NaN}',
	b'{"name":"Ada","count":2,"role":"reader"}',
])
def test_json_policy(raw):
	with pytest.raises(ValueError):
		read_json(raw)


@pytest.mark.parametrize("raw", [
	b'name: Ada\ncount: 1\ncount: 2',
	b'name: !label Ada\ncount: 2',
	b'name: &label Ada\ncount: *label',
	b'name: yes\ncount: 2',
	b'name: Ada\ncount: [[[[2]]]]',
])
def test_yaml_policy(raw):
	with pytest.raises(ValueError):
		read_yaml(raw)


def test_dtd_policy_without_external_resources():
	with pytest.raises(DTDForbidden):
		read_xml(b'<!DOCTYPE record><record><name>Ada</name><count>2</count></record>')


@pytest.mark.parametrize("reader", [read_json, read_yaml, read_xml])
def test_input_cap(reader):
	with pytest.raises(ValueError, match="size"):
		reader(b" " * 513)
```

### Objectives and Hints

Establish last-key-wins using the baseline assertion, then require duplicate rejection for the identical bytes. Trace why a safe YAML constructor alone does not implement the application policy. Check the empty DTD rejection without giving the parser any resource to resolve. Hint: the two YAML passes separate event policy from construction; this trades extra bounded CPU for a small, auditable lab implementation.

### Solution and Fixed Retest

The supplied readers are the fixed solution: 512-byte cap, UTF-8, duplicate checks, explicit numeric policy, constrained YAML events, forbidden XML DTD processing, and one shared domain schema. Seventeen test cases are expected. Successful controls must still return Ada/count 2. This does not certify a general-purpose hostile-file service: JSON/XML tree allocation is bounded here by the deliberately tiny body, not by a streaming depth limit.

### Verification, Troubleshooting, and Cleanup

Use the printed pytest command and record actual results. An unsupported-tag test should fail at the event policy, not reach a custom constructor. A parsing syntax error outside these fixtures may be `yaml.YAMLError`, `ET.ParseError`, or `JSONDecodeError`; an HTTP adapter must map those expected errors too. Remove the disposable directory after review. No service, external runtime, or .NET fragment was executed.

- [ ] Local Serialization exercise: compare permissive duplicate handling with strict real-parser validation.
- [ ] Boundary check: reject unused XML/YAML features and invalid types while valid controls remain accepted.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[XXE]]
- [[Insecure Deserialization]]
- [[Serialization]]

## References

- [Python 3.12 JSON compliance](https://docs.python.org/3.12/library/json.html#standard-compliance-and-interoperability)
- [PyYAML loaders and parsing events](https://pyyaml.org/wiki/PyYAMLDocumentation)
- [DefusedXML documented controls](https://pypi.org/project/defusedxml/)
- [XmlReaderSettings](https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmlreadersettings)
- [System.Text.Json polymorphism](https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/polymorphism)
