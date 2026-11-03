---
title: "XXE"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# XXE

> [!abstract] TL;DR
> XXE arises when an XML parser resolves attacker-influenced external entities or related resources beyond the application's intended data boundary.

> [!info] Agent scope
> XML external entity resolution; parser options; in-band and blind lab variants; DTD handling; resource limits.

## Learn

```text
Teach XXE as unintended XML resolver authority. Assume XML elements, attributes,
namespaces, HTTP bodies, and file/network permissions. Explain general versus
parameter entities, internal/external subsets, DTD processing, XInclude, schema
imports, and XSLT resource access as distinct features. Describe in-band and
blind evidence conceptually without resource-reference payloads. Compare parser
defaults and wrapper overrides; cover byte, depth, text, expansion, and CPU limits.
Work through an Expat-based data-only reader that rejects DTDs at parser callbacks,
with ordinary synthetic XML and safe rejection tests. Explain why this does not
configure Java, .NET, libxml2, or a later XML processor. Cite primary parser docs,
state version assumptions, and give review questions with answers. No file/network
resolution demos, theft, bypasses, RCE, scanning, or chains. Do not edit files or
invent test results.
```

## Cheatsheet

> [!important] Defensive scope
> No external entity document or resource retrieval is supplied. The lab rejects an empty DTD declaration and tests ordinary XML under strict limits; it never installs a resolver that performs I/O.

### Mechanisms and Preconditions

XXE needs an XML-processing path with external resource resolution enabled and enough service authority to access a resource. External general entities and parameter entities enter at different parsing stages; external DTDs can also introduce dependencies. In-band behavior returns resolved content; blind behavior has no returned content and requires separate I/O evidence. Neither is assumed from a parser error alone.

| Feature | Defensive choice | What it does not cover |
|---|---|---|
| DTDs | Reject if the application has no DTD requirement | Schema imports or later transformations |
| External entities | Disable and use a rejecting resolver | Internal expansion/resource exhaustion |
| XInclude | Do not invoke on untrusted documents | Ordinary parsing is a separate step |
| XML Schema | Use local reviewed schemas; prohibit external imports | Schema validation does not make parser settings safe |
| XSLT | Restrict stylesheet trust and resource access separately | Parser hardening does not constrain transform helpers |
| Resource budgets | Bound input, depth, text, nodes, CPU | A byte cap alone does not bound every parser cost |

Do not treat a string search for `DOCTYPE` as a general XML security parser. Enforce feature denial at the parser API and reject before application effects. Process untrusted documents under narrow OS permissions and with no unnecessary network access. Legitimate DTD-dependent workflows need an explicit local catalog and a different reviewed contract, not an unrestricted resolver.

### Runtime Details and Secure Settings

Python's XML modules differ. Expat does not itself fetch resources; an external-entity callback can introduce that authority. The lab uses `xml.parsers.expat` with DTD/entity rejection and no resolver implementation. It is not a universal XML serializer. Python may use a bundled or system Expat; check `expat.EXPAT_VERSION`, not just the Python version. Expat releases have fixed expansion and large-token denial-of-service issues, so use a supported patched build; historical minimum fixes do not imply a release is currently safe.

For .NET review `XmlReaderSettings.DtdProcessing = Prohibit` and `XmlResolver = null`. For Java JAXP review external-access properties for DTD/schema and secure-processing limits on the exact factory. For libxml2 wrappers review entity expansion, DTD loading, and network flags independently. A network-only prohibition can still leave local-file resolution possible. Do not assume a framework wrapper preserves library defaults.

Evidence should include parser API, library version, options, resolver callbacks, later processing stages, and rejected feature category. Unexpected parser-originated I/O deserves investigation, but an offline rejection test does not certify every production XML endpoint.

## Defense

Use the smallest data-only format and parser feature set that meets the contract. Reject DTDs unless essential, disable external resolution throughout the pipeline, and bound work before side effects. Patch libraries and test wrappers after upgrades. Keep errors generic externally and precise in redacted internal diagnostics.

## Labs

### Environment and Objectives

Python 3.12 standard library with Expat. One file, no services/packages/files to resolve. Review a proposed parser that enables DTDs without a product requirement. The secure replacement permits only a single text-only `report` element and refuses optional XML features. All XML fixtures are inline and nonexploitative.

### File: test_example.py

```python
from xml.parsers import expat
import unittest


def read_report(data):
	if type(data) is not bytes or len(data) > 1024:
		raise ValueError("input limit")
	parser = expat.ParserCreate()
	pieces = []
	depth = 0
	text_size = 0

	def reject_feature(*args):
		raise ValueError("optional XML feature prohibited")

	def start(name, attrs):
		nonlocal depth
		depth += 1
		if depth != 1 or name != "report" or attrs:
			raise ValueError("report schema")

	def end(name):
		nonlocal depth
		depth -= 1

	def text(value):
		nonlocal text_size
		if depth == 0:
			if value.strip():
				raise ValueError("outside text")
			return
		text_size += len(value)
		if text_size > 128:
			raise ValueError("text limit")
		pieces.append(value)

	parser.StartDoctypeDeclHandler = reject_feature
	parser.EntityDeclHandler = reject_feature
	parser.ExternalEntityRefHandler = reject_feature
	parser.ProcessingInstructionHandler = reject_feature
	parser.StartElementHandler = start
	parser.EndElementHandler = end
	parser.CharacterDataHandler = text
	parser.Parse(data, True)
	return "".join(pieces)


class XmlTests(unittest.TestCase):
	def test_normal_text(self):
		self.assertEqual(read_report(b"<report>A &amp; B</report>"), "A & B")

	def test_unused_dtd_is_rejected(self):
		with self.assertRaises(ValueError):
			read_report(b"<!DOCTYPE report><report>Ready</report>")

	def test_schema_and_limits(self):
		for data in [b"<report><item>Ready</item></report>",
					 b"<report>" + b"A" * 129 + b"</report>", b"A" * 1025]:
			with self.subTest(data=data), self.assertRaises(ValueError):
				read_report(data)

	def test_malformed_xml(self):
		with self.assertRaises(expat.ExpatError):
			read_report(b"<report>")


if __name__ == "__main__":
	print("Expat version:", expat.EXPAT_VERSION)
	unittest.main()
```

### Commands, Hints, and Separate Solution

```powershell
py -3.12 test_example.py -v
```

Use `python3.12` on other systems. Hint: the DTD test contains no entity definitions or external identifiers. Why reject an unused feature before needing to inspect what it might declare?

Solution: optional-feature callbacks stop processing; the application accepts only bounded text in a fixed element. Expected: four tests pass and the installed Expat version is printed. Built-in `&amp;` remains valid ordinary XML text. No I/O resolver exists in this program. This does not measure CPU exhaustion or test another XML stack.

### Verification, Troubleshooting, and Cleanup

No author execution occurred. The command uses direct script execution to print the parser version. Do not name the file `xml.py`. If Expat is absent, use a standard CPython build. Remove the disposable exercise directory; no persistent files, sockets, or parser resources remain beyond process lifetime.

- [ ] Local XXE exercise: Review parser feature and authority boundaries.
- [ ] Boundary check: Run secure DTD rejection, schema, and resource-limit tests.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [Python XML security](https://docs.python.org/3.12/library/xml.html#xml-vulnerabilities)
- [Python Expat callbacks](https://docs.python.org/3.12/library/pyexpat.html)
- [Microsoft XmlReaderSettings.DtdProcessing](https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmlreadersettings.dtdprocessing)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
