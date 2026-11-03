---
title: "LLM and Prompt Injection"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# LLM and Prompt Injection

> [!abstract] TL;DR
> Prompt injection occurs when untrusted text is treated as authority over an assistant's instructions, data access, or tool use.

> [!info] Agent scope
> Instruction/data boundaries; direct and indirect injection; retrieval and tool trust; scoped permissions; output handling; isolated evaluations.

## Learn

```text
Teach prompt injection as confusion between untrusted content and authority over
an assistant's decisions. Assume retrieval, model messages, tools, structured
outputs, access control, and web output handling. Distinguish direct requests
from indirect document/tool-output influence without providing injection prompts.
Trace retrieval authorization before context assembly, provenance, model proposals,
deterministic tool authorization, user confirmation, and output consumers. Explain
least privilege, scoped task capabilities, read/write separation, approval binding,
schema validation, and why instructions/delimiters are not hard isolation.
Review a no-model synthetic tool broker and output renderer; distinguish boundary
regression tests from statistical model-robustness evaluations. Give primary
sources, version/model assumptions, limitations, and questions with answers.
No prompt payloads, protected-data extraction, bypasses, arbitrary execution,
scanning, or chains. Teach, do not edit files or invent model/test performance.
```

## Cheatsheet

> [!important] Defensive scope
> This is a deterministic application-boundary lab, not a prompt-injection demonstration. It uses no model, prompt payload, external tool, or protected data. The tests do not measure model resistance to adversarial language.

### Root Cause and Trust Boundaries

Direct injection attempts come through user-controlled instructions; indirect influence arrives in retrieved pages, documents, messages, or tool results. The security issue is not simply that a model changes its answer: untrusted content must influence a meaningful protected decision or capability. A read-only assistant with no private context has a different risk profile from an agent with broad data access and write tools.

| Boundary | Trusted decision | Untrusted input |
|---|---|---|
| Retrieval | Server-side actor/document ACL before retrieval | Search query, retrieved text, document metadata |
| Context assembly | Application-owned task and provenance labels | Source text and tool output |
| Tool proposal | Model may suggest a typed operation | Tool name, arguments, claimed rationale |
| Tool execution | Deterministic broker validates scope and identity | Model cannot grant itself roles or permissions |
| Consequential action | User approval bound to exact action/resource/version | A general earlier approval is not arbitrary delegation |
| Output | Escape/validate for destination; treat as data | Generated text, URLs, markup, code-like strings |

Do not retrieve unauthorized documents and then ask the model not to reveal them. Apply ACLs before retrieval and partition indexes/caches where required. Preserve document provenance and freshness, but a legitimate source can still contain untrusted instructions. Tool output is data, not a higher-priority policy source.

### Hard Controls Versus Model Guidance

Role separation, delimiters, and instruction reminders help communicate intent but are not memory/process isolation. Keyword filters cannot cover every language/context and can damage legitimate input. Structured output narrows syntax, not authority or truth. A schema-valid request can still name an unauthorized resource. A tool allowlist must also restrict argument values, actor scope, rate, and side effects.

Use task-specific capabilities issued by the application, not model-selected identities. Prefer read-only tools, isolate execution, and deny arbitrary command/URL/file tools unless a separately reviewed product requires them. For writes, show a concrete preview and bind approval to normalized arguments, resource identity/version, and expiry; re-check authorization at execution to avoid stale approval. Logs should contain decisions and provenance references, not private context or raw secrets.

Treat model output like any other untrusted text: HTML-escape display text, validate links, never evaluate generated source, and use safe database/API parameters. A summary can be factually wrong even when every security boundary holds; accuracy and authorization are distinct acceptance criteria.

### Read-Only Proposal Schema

**Fragment / prerequisites:** JSON Schema draft 2020-12 for a task already authorized to read the synthetic `agenda` document. Use a compatible validator in the deterministic broker; this is not provider-specific tool-registration syntax. The application owns the schema and task identity, never retrieved content or model output.

```json
{
	"$schema": "https://json-schema.org/draft/2020-12/schema",
	"type": "object",
	"required": ["tool", "document_id"],
	"additionalProperties": false,
	"properties": {
		"tool": {"const": "read_note"},
		"document_id": {"const": "agenda"}
	}
}
```

**Permission / confirmation boundary:** Only dispatch `read_note` after schema validation and a fresh document ACL check. No write permission exists here, and a model-supplied approval field is rejected. A separate write capability would require server-recorded user confirmation bound to actor, normalized arguments, resource/version, and expiry, consumed once and reauthorized at execution; this schema implements none of that approval workflow.

**Interpretation / false positives:** schema success establishes request shape and task scope, not current access or trustworthy document content. Extra fields from a changed client can cause legitimate requests to fail; version the contract rather than treating every rejection as injection or relaxing authorization.

### Evaluation and Version Details

Pin model identifier, prompt/tool schema version, retrieval configuration, sampling parameters, and dataset version when running model evaluations. Record both unsafe-action rates and legitimate-task success, with repeated trials and uncertainty. A finite suite cannot establish universal resistance. Changes to tool permissions may matter more than a model upgrade.

The Python 3.12 lab tests deterministic enforcement only. It feeds ordinary synthetic proposals directly to a broker, so no model/provider version is required. Passing it would establish the printed invariants for those cases, not robustness to direct/indirect injection language, provider behavior, or hidden reasoning.

## Defense

Keep identity and permissions outside the model, authorize retrieval before context creation, and enforce least-privilege tool arguments at execution. Separate read/write capabilities, require exact approval for consequential actions, and sanitize output for each consumer. Maintain incident controls to revoke capabilities, halt actions, and inspect redacted evidence without relying on prompt changes alone.

## Labs

### Environment and Objectives

Python 3.12 stdlib; one file, no model/API key/packages/network. Review a proposed assistant that accepts the model's chosen tool and document ID without checking the initiating task. The replacement grants one read-only capability for one authorized synthetic note. Evaluate normal proposals for allowed work, wrong resource, unsupported tool, and extra fields. No injection text is needed.

### File: test_example.py

```python
from dataclasses import dataclass
from html import escape
import unittest


DOCUMENTS = {
	"agenda": {"owner": "ada", "text": "Synthetic agenda: review the draft."},
	"checklist": {"owner": "grace", "text": "Synthetic checklist: review dates."},
}


@dataclass(frozen=True)
class Task:
	actor: str
	allowed_document: str


def retrieve(task, document_id):
	if document_id != task.allowed_document:
		raise PermissionError("outside task scope")
	document = DOCUMENTS.get(document_id)
	if document is None or document["owner"] != task.actor:
		raise PermissionError("document authorization")
	return {"source_id": document_id, "text": document["text"]}


def execute_proposal(task, proposal, audit):
	if type(proposal) is not dict or set(proposal) != {"tool", "document_id"}:
		audit.append("denied-schema")
		raise ValueError("proposal schema")
	if proposal["tool"] != "read_note" or type(proposal["document_id"]) is not str:
		audit.append("denied-capability")
		raise PermissionError("read-only capability")
	try:
		result = retrieve(task, proposal["document_id"])
	except PermissionError:
		audit.append("denied-resource")
		raise
	audit.append("allowed-read")
	return result


def render_summary(summary):
	if type(summary) is not str or len(summary) > 500:
		raise ValueError("bounded summary text")
	return "<p>" + escape(summary, quote=True) + "</p>"


class AssistantBoundaryTests(unittest.TestCase):
	def test_allowed_read_and_provenance(self):
		audit = []
		result = execute_proposal(Task("ada", "agenda"),
								 {"tool": "read_note", "document_id": "agenda"}, audit)
		self.assertEqual(result, {"source_id": "agenda",
								  "text": "Synthetic agenda: review the draft."})
		self.assertEqual(audit, ["allowed-read"])

	def test_denied_proposals_have_no_output(self):
		cases = [({"tool": "read_note", "document_id": "checklist"}, PermissionError),
				 ({"tool": "write_note", "document_id": "agenda"}, PermissionError),
				 ({"tool": "read_note", "document_id": "agenda", "role": "admin"}, ValueError)]
		for proposal, error in cases:
			audit = []
			with self.subTest(proposal=proposal), self.assertRaises(error):
				execute_proposal(Task("ada", "agenda"), proposal, audit)
			self.assertEqual(len(audit), 1)
			self.assertTrue(audit[0].startswith("denied-"))

	def test_retrieval_acl_independent_of_task_selection(self):
		with self.assertRaises(PermissionError):
			retrieve(Task("ada", "checklist"), "checklist")

	def test_output_is_text(self):
		self.assertEqual(render_summary("A & B"), "<p>A &amp; B</p>")
		self.assertEqual(render_summary("<b>Draft</b>"), "<p>&lt;b&gt;Draft&lt;/b&gt;</p>")
		with self.assertRaises(ValueError):
			render_summary({"text": "Draft"})


if __name__ == "__main__":
	unittest.main()
```

### Commands, Hints, and Separate Solution

```powershell
py -3.12 -m unittest -v test_example
```

Use `python3.12` on other systems. Hint: why check both task scope and the underlying document ACL? Why reject a proposed role field instead of allowing the model to explain why it needs the role?

Solution: application-owned task identity and server-side ACLs control access; model proposals can request only an already permitted read. Output is encoded as text, and audit records do not contain document text. Expected: four tests pass; the permitted task returns one synthetic note with provenance; wrong resource/tool/extra fields fail; independently wrong ownership fails even when the task names that document.

### Verification, Troubleshooting, and Cleanup

No tests or model evaluations ran during authoring. Run beside the file; no provider credentials are needed. The task object is trusted application state, not user/model input. There is no write tool or approval implementation in this fixture; approval design is covered conceptually above. Remove the disposable directory afterward. This is not a reported prompt-injection success/failure rate and does not establish universal model safety.

- [ ] Local LLM and Prompt Injection exercise: Review retrieval, task, tool, and output authority.
- [ ] Boundary check: Run deterministic authorization and safe-rendering regressions.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [OWASP LLM01 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [OWASP LLM Prompt Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
- [NIST AI Risk Management Framework: Generative AI Profile](https://doi.org/10.6028/NIST.AI.600-1)
- [OpenAI agent safety guidance](https://platform.openai.com/docs/guides/agent-builder-safety)
