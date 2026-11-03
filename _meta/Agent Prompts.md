---
title: "Agent Prompts"
aliases: []
tags: [meta, prompts]
domain: meta
phase: ""
type: moc
status: draft
pair: ""
updated: 2026-11-03
---
# Agent Prompts

Use the blocks below as reusable requests; replace `<placeholders>`. These are plain Markdown prompts, not VS Code slash commands.

## Shared Contract

Every prompt below includes this contract:

- Follow AGENTS.md, [[Style Guide]], and [[Course Plan]]. Preserve the existing phase inventory and unique names.
- Read the existing note's Agent scope before writing. Use the matching template under `_meta/Templates/`; resolve all placeholders and links.
- Learn is a copy-ready expert teaching prompt, not the lesson itself or an instruction to edit this vault. Cheatsheet and Labs are substantive, independently usable content requiring no agent conversation. Follow the Content Acceptance rules in Style Guide.
- Include real code/commands and fully specified local exercises/CTFs: dependencies, every file, seeds, requests, objectives, hints, solution, expected results, validation, troubleshooting, and cleanup. External links supplement rather than replace the supplied exercise.
- Use public, current sources. Do not claim execution or completion without evidence. Set filled notes to `draft`; preserve user-owned higher statuses and checked boxes.
- Source pool: `C:\Users\brafalsk\repos\HackBook`. W0/W6: `archive/Web/HTTP.md`, `archive/Web/XSS.md`, `archive/Web/nginx.md`; X0/X4: `archive/Windows/smb/smbclient.md`, `pages/windows/architecture.html`; X1/X2: `pages/arch/x86-os-internals.html` (skip page tables). Read only relevant files, rewrite rather than copy, and verify against official documentation. If absent, report that and use public sources.
- Exclude page-table writeups, Firewire, and confidential information. WinDbg commands belong only in the WinDbg note.
- Run `pwsh -NoProfile -File "_meta/Test-Vault.ps1"` after note/link changes. Report changed notes, verification results, and anything unverified. Do not publish, commit, move the vault, or mark labs complete.

## Fill One Technology Pair

```text
Fill the existing <technology> and <technology> Security notes.
Apply the Shared Contract in _meta/Agent Prompts.md and read _meta/Style Guide.md.
Use _meta/Templates/Tech Template.md and _meta/Templates/Security Template.md.
Read the relevant HackBook source paths listed in the Shared Contract when available.
Write Learn as a self-contained prompt asking an agent to teach the complete
topic at expert depth, without requiring vault access or requesting file edits.
Put the actual mental model, internals, implementation choices, worked code,
commands, edge cases, and compact reference tables in Cheatsheet.
In Security, include concrete vulnerable/fixed patterns, exact harmless requests,
authorization prerequisites, detection, and regression tests.
Link shared attack classes instead of duplicating them. Preserve reciprocal pair links.
Make each page's Labs runnable independently: all files and setup, synthetic data,
objectives, hints, separate solution, expected outcomes, checks, and cleanup.
Test the printed examples where possible; distinguish author validation from
user-owned lab completion. Do not use generic paragraph expansion as a shortcut.
```

## Fill a Whole Phase

```text
Fill phase <W0 or X0 etc.> using the matching domain roadmap as the authoritative
checklist of existing notes. Apply the Shared Contract in _meta/Agent Prompts.md
and read _meta/Style Guide.md plus each note's Agent scope.
Use Tech + Security templates for pairs, Technique for attack classes, and Tech
adapted to type method with an empty pair for workflows. Templates live in
_meta/Templates/. Read relevant HackBook sources from the Shared Contract.
Fill every listed note and both sides of each pair, preserving filenames and scope.
For every note, Learn is the copy-ready teaching prompt; Cheatsheet and Labs
contain the complete reference and exercises, not instructions to ask an agent.
Review each subject independently. Do not equate scaffold validation with depth.
Do not expand into neighboring phases. Shared tool notes are link targets; fill
them only if explicitly included in this request. Add only resolving related links.
Use the roadmap's goal, labs, and exit criteria to align exercises. Leave completion
checkboxes untouched. If the phase cannot be finished, list the exact remaining stubs.
```

## Write a Technique Note

```text
Fill the existing <technique> note in phase <phase>.
Apply the Shared Contract in _meta/Agent Prompts.md; read _meta/Style Guide.md
and _meta/Templates/Technique Template.md. Consult applicable HackBook sources
listed in the Shared Contract; use official/public references for missing material.
Make Learn a copy-ready prompt for detailed tutoring. In Cheatsheet, cover root
cause, prerequisites, variants, discovery signals, concrete lab-scoped requests,
representative payloads where appropriate, bypass conditions, and defense.
Provide a complete local CTF/lab with files, setup, objectives, hints, solution,
expected evidence, fix, tests, and cleanup. No agent or external platform should
be required to supply missing steps. Distinguish versions and supported defaults.
Keep it a single technique note with an empty pair, linked from relevant existing notes.
```

## Turn a Lab Into a Writeup

```text
Turn the supplied evidence from <lab> into a writeup under <Web or Windows>/Labs/.
Apply the Shared Contract in _meta/Agent Prompts.md and read _meta/Style Guide.md
and _meta/Templates/Lab Writeup Template.md. Check the HackBook source paths in
the Shared Contract only for relevant background, never as evidence of this run.
Choose a vault-unique filename prefixed with the domain and lab name.
Record the authorized target, environment/version, recon, foothold, escalation,
lessons, and concise cheatsheet additions. Mark absent evidence or inapplicable
stages explicitly; do not invent results, flags, secrets, or completed steps.
Redact sensitive data and respect the platform's writeup policy before publication.
Link the writeup from the matching domain Labs index and relevant learning notes.
```

## Generate Quiz or Review Questions

```text
Generate a concise review from the Cheatsheet in <note>.
Apply the Shared Contract in _meta/Agent Prompts.md and read _meta/Style Guide.md.
Read the note's matching Tech, Security, Technique, or Lab Writeup template under
_meta/Templates/ to understand its scope. Use relevant HackBook sources listed
in the Shared Contract only to verify background, not to expand the quiz scope.
Include recall, explain-why, and short scenario questions, with a separate answer
key grounded in the note. Flag gaps instead of inventing unsupported facts.
Return the quiz in chat unless asked to save it. Do not change the note's status
or completion checkboxes based on generating questions.
```