---
title: "Style Guide"
aliases: []
tags: [meta, conventions]
domain: meta
phase: ""
type: moc
status: draft
pair: ""
updated: 2026-11-03
---
# Style Guide

## Structure

- Technology: a `tech` note and a reciprocal `security` note, in the same technology folder.
- Attack class: one `technique` note in the domain's Attacks or Exploit Dev phase.
- Workflow or lab setup: one `method` note. Tools use method notes in `Tools/`.
- Navigation: `moc`. Lab writeup: `lab` in the appropriate domain's `Labs/` folder.
- Every learning note has **Learn**, **Cheatsheet**, and **Labs** sections with different responsibilities. Learn is a copy-ready teaching prompt; Cheatsheet is the substantive standalone reference; Labs contains complete exercises/CTFs usable without an agent.
- Use the Tech, Security, Technique, Lab Writeup, or Roadmap template in `_meta/Templates/`. Methods adapt the Tech template: no pair; use workflow exercises instead of technology construction. Templates are excluded from the public site, so do not wikilink to them from published notes.
- Keep the Agent scope callout until its requirements are covered. A stub is an outline, not completed teaching material.

## Frontmatter

Use these keys on all new notes:

```yaml
title: "Display name"
aliases: []
tags: [web, foundations]
domain: web
phase: W0
type: tech
status: stub
pair: "[[Sibling Security]]"
updated: 2026-11-02
```

- `domain`: `web`, `windows`, `tools`, or `meta`. Use the actual phase ID, or `""` for cross-phase notes.
- `type`: `tech`, `security`, `technique`, `method`, `moc`, or `lab`. The original Course Plan retains its legacy `meta` type.
- `status`: `stub` -> `draft` -> `learning` -> `practiced` -> `mastered`.
- Agents set `draft` when material is written and checked. The user owns later promotions and completed lab/roadmap checkboxes.
- `pair`: quoted basename wikilink for both sides of a technology pair; `""` otherwise. Do not invent a pair for a technique or tool.
- Quote titles and wikilinks. Use ISO dates; update only notes you actually changed.
- Aliases are optional display/search aids; avoid ambiguous aliases across domains.

## Names and Links

- Every Markdown basename must be unique throughout the vault, including templates and lab writeups.
- Use `Django Security.md`, never `Django - Security.md`.
- Avoid `/ : # & ? .` within stems and leading dots. Use `DotNet and CLR`, `Nodejs and Express`, and `TLS and PKI`; keep display punctuation in `title`.
- Domain-qualify overlapping subjects: `Web SQL Server` and `Windows SQL Server`.
- Use basename wikilinks, such as `[[HTTP]]` or `[[HTTP|HTTP/1.1]]`. Link only to existing notes.
- Do not put example wikilinks inside template placeholders. Use `{{name}}` tokens until a real note is instantiated.
- Link related attack classes rather than repeating their full payload catalog in each security note.
- Link [[Burp Suite]] from Burp Workflow. Link [[WinDbg]] from Windows notes; never duplicate its commands.

## Writing

- Prefer precise explanations, tables, worked code, commands, and concrete cause/effect. Concise means no filler, not shallow coverage. Expert-level depth takes priority over an arbitrary page-length limit.
- **Learn:** a fenced `text` prompt that can be pasted into an agent conversation without vault access. Name the subject, prerequisites, exact scope, desired depth, internals, implementation/failure examples, verification, sources, and constraints. Ask for teaching, not for filling or editing the note. No required exercise step may depend on that conversation.
- **Cheatsheet:** the actual reference, not a request for an agent to create one. Explain mechanisms, decision points, failure modes, and version-sensitive behavior. Include concrete syntax, commands, annotated-by-prose code, request/response examples, and secure alternatives where relevant. Label fragments versus complete programs.
- **Labs:** self-contained local exercises or CTFs with prerequisites, dependency versions, every required file/configuration, seed data, launch commands, target scope, objectives, hints, separated solution, expected observations, automated/manual acceptance checks, troubleshooting, and reset/cleanup. Do not replace these with "build an app", "test authorization", or an external link. External platforms are optional additional practice, not the only exercise.
- Technology exercises build or observe a real mechanism. Security exercises establish a baseline, prove a specific failure using harmless synthetic data, apply a concrete fix, and repeat the same test. Demonstrate permitted behavior still works.
- Security examples stay in explicitly authorized labs. Explain root cause, conditions, observable result, detection, and remediation.
- Separate vulnerable behavior from supported defaults. State relevant versions and prerequisites; do not present unverified commands as tested.
- Do not fabricate lab completions, measured results, references, or tool output. Mark unverified details explicitly.
- Use official documentation first and current reputable training material second. References are Markdown URLs, not unresolved source-note links.
- Keep source paths in metadata/workflow guidance, not as public links to local files.
- Use fenced code blocks with language identifiers, standard callouts, and normal Markdown. No Dataview, Templater, or plugin-specific syntax.

### Content Acceptance

- A reader must be able to use Cheatsheet and finish the supplied Lab without an agent, an unwritten companion file, or unstated implementation decisions.
- A prompt, headings, bullet count, resolved links, and a bibliography do not constitute expert content. Cover the topic's actual scoped subtopics, including meaningful edge cases and tradeoffs.
- For runnable examples, test the exact code printed in the note when execution is available. Report versions, checks performed, limitations, and warnings separately from user study completion.
- [[FastAPI]] and [[FastAPI Security]] established the revised section contract. All 290 learning notes were rewritten on 2026-11-03; future edits still require topic-specific review and meaningful checks. Neither revision status nor a structural pass proves every claim or runtime exercise.
- `_meta/Fill-Course.ps1` and its JSON source are legacy outline-generation material. Do not use their output as finished content or bulk-expand generic paragraphs to satisfy this standard. They do not synchronize revised notes.

## Preferences and Privacy

- No page-table hierarchy or page-table writeups; VADs, heaps, and memory protections remain in scope.
- No Firewire/IEEE 1394 material.
- WinDbg commands live only in [[WinDbg]]. Its fresh reference is not an import of the user's separate existing notes.
- Public notes must contain no Intel-confidential content, credentials, real internal targets, or corporate data. Do not collect such content while researching.
- `Private/` is reserved for nonpublic user-managed notes. Do not link to it from public notes.
- Before publishing, Quartz must exclude `_meta/Templates`, `Private`, `.obsidian`, and `AGENTS.md`. A folder name or `.gitignore` alone does not prevent publication.

## Source Material

Old HackBook root: `C:\Users\brafalsk\repos\HackBook`. Inspect only relevant files, rewrite concisely, and verify current behavior:

| Phases | Sources |
|---|---|
| W0, W6 | `archive/Web/HTTP.md`, `archive/Web/XSS.md`, `archive/Web/nginx.md` |
| X0, X4 | `archive/Windows/smb/smbclient.md`, `pages/windows/architecture.html` |
| X1, X2 | `pages/arch/x86-os-internals.html`; skip all page-table material |

## Verification

- Run `pwsh -NoProfile -File "_meta/Test-Vault.ps1" -CheckRevisedContent` from the real vault root. The compatibility junction location is not a recursive validation root; use `C:\Users\brafalsk\repos\HackVault\content` or supply its path with `-VaultRoot`.
- Confirm unique basenames, no unresolved public wikilinks, reciprocal pairs, complete phase coverage, and valid template settings.
- After content edits, also check reference URLs, technical accuracy, lab prerequisites, and expected outcomes manually.
- Use [[Web Roadmap]] and [[Windows Roadmap]] to navigate. Check boxes only after the user meets the exit criteria.
- Quartz rendering, private-content exclusion, and GitHub Pages availability are separate Phase B checks; the scaffold checker does not certify publication.