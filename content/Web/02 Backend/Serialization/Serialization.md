---
title: "Serialization"
aliases: []
tags: [web, w2]
domain: web
phase: "W2"
type: tech
status: draft
pair: "[[Serialization Security]]"
updated: 2026-11-03
---
# Serialization

> [!abstract] TL;DR
> Parsing produces values, not trusted domain objects. Define encoding, duplicate-key policy, types, schema version, and resource limits before converting values into application state.

> [!info] Agent scope
> JSON; XML; YAML; schemas; parser options; type construction; entity resolution; resource limits; trust boundaries.

## Prerequisites

- Basic Python, Unicode/UTF-8, mappings, lists, and HTTP media types.
- [[Web Lab Setup]]

## Learn

```text
Teach JSON, XML, and YAML serialization at expert engineering depth. Assume
Python and UTF-8 basics. Trace bytes -> decoder -> tokens -> tree/graph -> schema
-> domain object -> output projection -> encoder. Compare JSON's data model,
XML namespaces/attributes/mixed content/DTDs, and YAML tags, anchors, aliases,
implicit typing and multi-document streams. Explain Python 3.12 json behavior,
PyYAML 6.0.x SafeLoader, defusedxml 0.7.1, and JSON Schema 2020-12.
Work through duplicate names, absent versus null, booleans versus integers,
decimal money, large integer interoperability, dates, and schema evolution.
Show complete real-library code converting one bounded record between all
three formats, including deliberate lexical rules for XML. Demonstrate parse
success versus schema failure using harmless fixtures. Explain why sorted JSON
is not a universal canonical signing format, why object graphs differ from
plain data, and why external resolution/type construction are separate policies.
Give tests, outputs, error handling, streaming tradeoffs, budgets before and
after parse, and troubleshooting. Cite primary docs with version caveats.
Teach here, not by editing notes. No unsafe object loading, external entity
payloads, resource-exhaustion payloads, confidential data or fabricated results.
```

## Cheatsheet

### Data Models and Lossy Boundaries

| Format | Native model | Decisions that must be explicit |
|---|---|---|
| JSON | Object with string names, array, string, number, boolean, null | Duplicate keys, numeric precision, UTF-8, top-level shape |
| XML | Ordered elements, qualified names, attributes, text/tails | Namespace URIs, element multiplicity, mixed content, whitespace, DTD policy |
| YAML | Tagged scalars and collection graph | Implicit types, aliases, merges, non-string keys, duplicate mapping entries |

`{"quantity": 2}` and `<quantity>2</quantity>` do not initially produce the same type: JSON's parser creates an integer; XML exposes text. Define an XML lexical grammar, then convert. Namespace identity is URI plus local name, not the chosen prefix. `<a:x xmlns:a="urn:lab"/>` and `<b:x xmlns:b="urn:lab"/>` name the same element. Use `{urn:lab}x` with ElementTree.

JSON has no date, byte-string, or decimal-money type. Represent timestamps as a documented UTC string, bytes as a specified base64 encoding, and money as integer minor units or decimal strings. JavaScript numbers exactly represent integers only through `2**53 - 1`; use strings for larger opaque identifiers. Python's `bool` is an `int` subclass, so hand validation must use exact types when booleans are forbidden.

### Parser and Schema Contracts

Python 3.12 `json.loads` accepts duplicate names (last wins) and nonstandard `NaN`/infinities by default. `strict=True` concerns unescaped control characters, not these policies. `object_pairs_hook` sees duplicates before information is lost. `parse_constant` rejects named nonfinite constants; exponent overflow still needs a finite-number check or `Decimal`. `json.dumps(..., allow_nan=False)` constrains output. The Python 3.11+ integer-string limit is not a request-size or nesting budget.

PyYAML 6.0.x `safe_load` avoids arbitrary Python constructors, but retains YAML 1.1-style implicit types: `yes` can become a boolean and a date-shaped scalar a date. Quote strings that must remain strings. SafeLoader does not by itself reject duplicate keys or bound alias graphs. Do not register application constructors globally on SafeLoader and then assume it remains a plain-data-only loader.

DefusedXML exposes separate `forbid_dtd`, `forbid_entities`, and `forbid_external` options. Set all three when DTDs are unnecessary. It does not impose your business schema, body limit, element count, or output budget. XInclude, XSLT, and schema imports are additional processing steps with their own I/O policies.

JSON Schema 2020-12 fragment for an input DTO:

```json
{
	"$schema": "https://json-schema.org/draft/2020-12/schema",
	"type": "object",
	"required": ["version", "name", "quantity"],
	"additionalProperties": false,
	"properties": {
		"version": {"const": 1},
		"name": {"type": "string", "minLength": 1, "maxLength": 40},
		"quantity": {"type": "integer", "minimum": 0, "maximum": 100}
	}
}
```

Schemas validate structure, not ownership or business transitions. JSON Schema treats mathematically integral numbers such as `2.0` as integers; a Python exact-type policy can intentionally be stricter. `format` validation may require an explicit checker; `default` is not a command to insert a value. Closed input schemas catch misspelled fields but require deliberate version evolution. Output readers often need a more tolerant compatibility policy.

### Encoding, Framing, and Integrity

Use UTF-8 and a declared media type, not content sniffing between formats. Distinguish an absent property (leave unchanged in some patch contracts) from explicit null (clear a value, if permitted). JSON is not framed: repeated `dump` calls do not form a valid single document. For NDJSON use one complete JSON value per line and a per-record size cap; physical newlines inside strings must be escaped.

Pretty printing, key sorting, Unicode normalization, and number formatting can change bytes without changing a value. `sort_keys=True` is useful for comparisons but not an implementation of a cross-language canonicalization standard. Sign the specified bytes or a standardized canonical form; verify integrity before acting, and validate the resulting data anyway. Signatures do not make native object reconstruction safe.

## Gotchas

Tree parsers allocate before post-parse validation. Limit decompressed bytes at ingress; use event/stream processing and a worker budget for larger inputs. Catch expected parsing/validation exceptions and return a small error, not the original body. Serializing an ORM entity directly can expose internal fields or trigger lazy database work.

## Labs

### Environment and Complete Files

CPython 3.12; PyYAML 6.0.2; defusedxml 0.7.1; pytest 8.3.5. The single file includes all seed data and a deliberately narrow record schema. It uses actual parsers; it is not a replacement JSON/XML/YAML implementation. No service is required. **Not executed by the author.**

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install PyYAML==6.0.2 defusedxml==0.7.1 pytest==8.3.5
.venv\Scripts\python -m pytest -q
```

### File: test_example.py

```python
import json
import re
import xml.etree.ElementTree as ET
import pytest
import yaml
from defusedxml.ElementTree import fromstring

RECORD = {"name": "Ada & Co", "quantity": 2}
SEEDS = {
	"json": b'{"name":"Ada & Co","quantity":2}',
	"yaml": b'name: "Ada & Co"\nquantity: 2\n',
	"xml": b'<record><name>Ada &amp; Co</name><quantity>2</quantity></record>',
}


def unique(pairs):
	result = {}
	for key, value in pairs:
		if type(key) is not str or key in result:
			raise ValueError("duplicate or non-string key")
		result[key] = value
	return result


class RecordLoader(yaml.SafeLoader):
	pass


def yaml_mapping(loader, node):
	return unique((loader.construct_object(key, deep=True),
				   loader.construct_object(value, deep=True))
				  for key, value in node.value)


RecordLoader.add_constructor("tag:yaml.org,2002:map", yaml_mapping)


def invalid_constant(value):
	raise ValueError("nonfinite number")


def validate(value):
	if type(value) is not dict or set(value) != {"name", "quantity"}:
		raise ValueError("fields")
	if type(value["name"]) is not str or not 1 <= len(value["name"]) <= 40:
		raise ValueError("name")
	if type(value["quantity"]) is not int or not 0 <= value["quantity"] <= 100:
		raise ValueError("quantity")
	return value


def parse_record(kind, raw):
	if len(raw) > 1024:
		raise ValueError("size")
	text = raw.decode("utf-8")
	if kind == "json":
		value = json.loads(text, object_pairs_hook=unique,
						   parse_constant=invalid_constant)
	elif kind == "yaml":
		value = yaml.load(text, Loader=RecordLoader)
	elif kind == "xml":
		root = fromstring(text, forbid_dtd=True, forbid_entities=True,
						  forbid_external=True)
		if root.tag != "record" or root.attrib or (root.text or "").strip():
			raise ValueError("root")
		if any(child.attrib or len(child) or (child.tail or "").strip()
			   for child in root):
			raise ValueError("element")
		value = unique((child.tag, child.text or "") for child in root)
		quantity = value.get("quantity", "")
		if not re.fullmatch(r"0|[1-9][0-9]{0,2}", quantity):
			raise ValueError("quantity syntax")
		value["quantity"] = int(quantity)
	else:
		raise ValueError("format")
	return validate(value)


def encode_record(kind, value):
	validate(value)
	if kind == "json":
		return json.dumps(value, allow_nan=False).encode("utf-8")
	if kind == "yaml":
		return yaml.safe_dump(value).encode("utf-8")
	if kind == "xml":
		root = ET.Element("record")
		for key in ("name", "quantity"):
			ET.SubElement(root, key).text = str(value[key])
		return ET.tostring(root, encoding="utf-8")
	raise ValueError("format")


@pytest.mark.parametrize("kind", SEEDS)
def test_equivalence_and_roundtrip(kind):
	assert parse_record(kind, SEEDS[kind]) == RECORD
	assert parse_record(kind, encode_record(kind, RECORD)) == RECORD


@pytest.mark.parametrize("kind,raw", [
	("json", b'{"name":"Ada","quantity":true}'),
	("json", b'{"name":"Ada","quantity":2,"extra":0}'),
	("json", b'{"name":"Ada","quantity":1,"quantity":2}'),
	("yaml", b'name: Ada\nquantity: 1\nquantity: 2'),
	("yaml", b'name: yes\nquantity: 2'),
	("xml", b'<record><name>Ada</name><quantity>02</quantity></record>'),
	("xml", b'<record><name>Ada</name><quantity>2</quantity><quantity>3</quantity></record>'),
])
def test_invalid_records(kind, raw):
	with pytest.raises(ValueError):
		parse_record(kind, raw)


def test_size_boundary():
	with pytest.raises(ValueError, match="size"):
		parse_record("json", b" " * 1025)
```

### Objectives and Hints

Predict the normalized record for all three seeds. Explain why the ampersand changes in XML bytes but not in the domain value. Identify which invalid cases fail at parsing versus at the application schema. Add no new network resources. Hint: YAML's `yes` changes type; XML's `02` violates this lab's explicit canonical integer grammar.

### Solution and Expected Results

The solution is the explicit projection plus `validate`: all three formats become `{"name": "Ada & Co", "quantity": 2}`. Eleven cases are expected to pass. Round-trip equality concerns values, not formatting or order. The custom loader rejects duplicates but does not implement a full YAML resource policy; the security pair supplies a separate, independently complete constrained-ingestion exercise.

### Verification, Troubleshooting, and Cleanup

Record `.venv\Scripts\python -m pip show PyYAML defusedxml` and the Python version. A `ConstructorError` for a merge key is expected under this narrow loader; merges are not part of this record format. Use spaces in YAML. Empty XML text becomes an empty string and fails the name constraint. Remove the disposable directory and venv when finished. No external runtime or service has been verified here.

- [ ] Local Serialization exercise: parse and round-trip the supplied record through JSON, XML, and YAML.
- [ ] Boundary check: reject duplicate fields, ambiguous types, unknown fields, and oversized input.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[XXE]]
- [[Insecure Deserialization]]
- [[Serialization Security]]

## References

- [Python 3.12 JSON behavior](https://docs.python.org/3.12/library/json.html)
- [PyYAML API and type model](https://pyyaml.org/wiki/PyYAMLDocumentation)
- [DefusedXML options](https://pypi.org/project/defusedxml/)
- [JSON Schema 2020-12](https://json-schema.org/draft/2020-12)
- [XML namespaces](https://www.w3.org/TR/xml-names/)
