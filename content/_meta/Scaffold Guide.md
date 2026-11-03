---
title: "Scaffold Guide"
aliases: []
tags: [meta, scaffold]
domain: meta
phase: ""
type: moc
status: draft
pair: ""
updated: 2026-11-03
---
# Scaffold Guide

## Phase A

- 16 phases, 165 course entries, 117 technology/security pairs, and 48 standalone course notes.
- 282 course notes plus 8 shared tool references. All 290 have revised references, tutoring prompts, exercises, and unchecked study tasks; authoring does not promote their `draft` status.
- [[Web Roadmap]] and [[Windows Roadmap]] list each course note separately, including both members of every pair.
- Python has its own pair alongside Flask, Django, and FastAPI. The four SQL engines have separate pairs.
- [[Web SQL Server]] covers application data access; [[Windows SQL Server]] covers enterprise operation.
- [[Windows Tooling Setup]] is a method, as are shared tool notes. X7 control notes retain technology/security pairs, with limitations and bypass conditions scoped to Security.
- Obsidian's built-in Templates folder is `_meta/Templates`. Tokens such as `{{title}}` and `{{date}}` are native; remaining custom tokens must be replaced manually or by the agent. No plugin-specific templating engine is required.

## Maintenance

The planned topic inventory and scoped subtopics are stored in `_meta/Course Catalog.json`. The generated roadmaps are the day-to-day checklist for content work.

From the vault root, with PowerShell 7:

```powershell
pwsh -NoProfile -File "_meta/Test-Vault.ps1" -CheckRevisedContent
```

To restore missing generated stubs or roadmaps:

```powershell
pwsh -NoProfile -File "_meta/Initialize-Vault.ps1"
```

The initializer uses the five templates and preserves every existing file, including edited notes and checked roadmap items. It does not refresh existing roadmaps after catalog changes: update those manually, then validate. The home page, guides, settings, and lab/tool indexes are maintained directly, not regenerated.

The validator checks the vault's simple frontmatter schema, note inventory, unique filenames, reciprocal pairs, public wikilinks and heading targets, excluded-link targets, roadmap coverage, and Templates settings. It is not a general YAML linter, technical-content reviewer, browser renderer, or external-URL checker.

Use the real `C:\Users\brafalsk\repos\HackVault\content` directory for recursive validation, not the compatibility junction root. `-CheckRevisedContent` additionally checks for copy-ready Learn prompts, concrete reference syntax, and fenced lab examples. It does not evaluate expert depth or prove runtime behavior.

## Phase B - Local Publishing Setup

- Quartz v4 lives at `C:\Users\brafalsk\repos\HackVault`; the actual Obsidian vault is its `content` folder. The original `Documents\HackVault` location retains directory junctions and root-file hard links for compatibility, not a second independent copy.
- Dependencies, Quartz configuration, and a GitHub Pages Actions workflow are prepared. Public rendering excludes `_meta/Templates`, `Private`, `.obsidian`, and `AGENTS.md`; Git also ignores private notes and local Obsidian settings.
- The user supplied `https://github.com/benrafalski/HackVault`; both fetch and push URLs for `origin` now point there. Quartz uses `benrafalski.github.io/HackVault` as its production `baseUrl`; the production build and all 300 sitemap URLs were checked.
- Publication is still blocked: the selected credential authenticates as `benjaminrafalski`, not the required `benrafalski`. No commit or push was performed. Reauthenticate with `git credential-manager github login --username benrafalski --browser --force`, verify the authenticated login and commit identity, then commit and push `v4`. In the repository's Settings > Pages, select GitHub Actions as the source. Never publish using the other account.
- Compatible dependency fixes were applied. Nine npm advisories remained at that check (4 low, 3 moderate, 2 high); major dependency migrations were not forced. Reassess before publication or exposing the preview server beyond localhost.

From the repository root, with Node 22 available:

```powershell
npm ci
& './node_modules/.bin/tsc.cmd' --noEmit
& './content/_meta/Test-Vault.ps1'
npx quartz build
& './content/_meta/Test-Publication.ps1' -OutputRoot './public'
```

CI uses `Test-Vault.ps1 -SkipObsidianSettings` because private/local settings are intentionally absent from Git. The publication checker verifies excluded output, search-index entries, roadmap links, and callouts; it does not certify technical accuracy or a live Pages deployment.

## Phase C - Revised Draft Content

- All W0-W7 and X0-X7 notes and shared tools have been substantively rewritten. Learn is optional agent tutoring; Cheatsheet and Labs are usable from the page. Study completion, VM provisioning, paid platform work, mastery, and roadmap checkboxes remain user-owned.
- `_meta/Templates/Course Drafts.json` holds the legacy outline source, excluded from the website. `Fill-Course.ps1 -Phase W0` fills only stubs and preserves all existing non-stub notes. Its output does not meet the revised content standard. Maintain revised Markdown directly.
- [[WinDbg]] contains a fresh public-documentation reference. The user's separate existing note has not been located, imported, or replaced.
- Use [[Agent Prompts]] for content authoring; readers do not need an agent to supply missing lab files or solutions. Security labs use defensive validation, synthetic evidence, and remediation rather than operational credential theft, evasion, persistence, or exploit chains. Platform-specific runtime prerequisites and offline-model limits are explicit. Author verification is not user lab completion.
- Open the real `content` directory as the Obsidian vault when convenient. Existing compatibility links preserve access from the old location, but do not constitute an Obsidian registration change.

## Verification Record

On 2026-11-03 the content contract changed: Learn is a copy-ready teaching prompt; Cheatsheet and Labs/CTFs must be self-contained. After the [[FastAPI]] pair, all 288 remaining learning notes were rewritten in place. The legacy outline renderer was not used for this rewrite. All 290 remain `draft`.

### Full Rewrite Checks

- All 290 learning notes pass the revised-format gate. Metadata, the 117 reciprocal pairs, 16 phases, and public links pass structural validation. This is coverage evidence, not a blanket technical-accuracy certificate.
- The final local build processes 300 Markdown inputs and emits 489 files; publication-exclusion checks pass with 1,489 resolving public wikilinks in the source vault. Eight representative web, Windows, and tool pages loaded at 1440px and 390px with all required sections and code blocks, no page-level horizontal overflow, and no observed JavaScript errors. Desktop/mobile screenshots were reviewed. This checks the notes' presentation, not browser enforcement inside every embedded lab.
- Exact named files were extracted from Markdown using `_meta/Test-FastAPIExamples.ps1`, now supporting any uniquely named learning note, fixture/config files, and `-ExtractOnly` for review. Its original FastAPI defaults remain compatible. Tests run in separate temporary directories, not against production targets.
- The table records validation batches. Counts overlap where notes were retested; do not sum them as unique tests or interpret subtests as additional test methods.

| Batch | Observed Checks | Limits |
|---|---|---|
| Foundations, web techniques, methodology, SQLite | 47 notes; 160 tests plus 106 subtests | Linux/Bash and OpenSSL exercises not run; initial Jinja2/GraphQL dependency gaps remained in their standalone technique labs |
| Identity, infrastructure, Windows internals/platform | 42 notes; 100 tests, 45 subtests, 16 standalone Python checks, one temporary-file NTFS script | Primarily offline models; native/API/cloud/VM enforcement not established |
| Python frameworks, ORMs, identity protocols | 34 notes; 101 tests; gRPC stub generation and dependency compatibility checks | Browser authenticators, external federation, alternate PHP/.NET implementations not run |
| Enterprise, advanced Windows analysis, defenses, tools | 50 Python suites; 241 passed, two optional Impacket integrations skipped, 99 subtests; three PowerShell scripts passed in two shells | SQL Server scripts, native/GUI debugging, BloodHound ingestion, Sigma conversion, and KQL execution not run |
| Frontend | All 28 notes/116 named files extracted; 95 syntax checks; framework builds, typechecks, artifact gates, and supplied Node checks passed | Browser interaction, origin enforcement, rendering of lab apps, and service-worker lifecycle not established by Node checks |
| Review repairs | SAML pair: six tests including 14 qualifier-rejection subcases; Kubernetes/Detection Engineering offline retests pass; all 20 public YAML blocks parse | Kubernetes cluster/CNI enforcement and target-specific YAML schemas remain separate runtime checks |

An independent static review sampled 17 phase/tool references plus a companion. It found and prompted fixes for SAML NameID qualifier handling, YAML indentation, and an incomplete Kubernetes runtime exercise. The Kubernetes note now includes the approved-VM setup, manifests, context guard, authorization/connection matrices, and teardown; no cluster was provisioned here. Extraction formatting defects and an ineffective Entra SQL negative-test mutation were also repaired and retested. This sample is not a line-by-line review of all 290 pages.

**Versions and warnings:** Python checks used 3.12.10 in isolated environments. Frontend checks used Node 22.23.4/npm 10.9.9, not Node 24. Per-note Python dependency pins/ranges were installed in a separate validation environment where needed. A rejected JWT fixture produced a short-HMAC-key warning with installed PyJWT 2.15.1 rather than its older teaching pin. React builds emitted two `use client` warnings; each Angular lab reported 16 moderate dependency findings. The vulnerable WebSocket teaching pin was replaced with `ws@8.22.1`; both lab audits then reported zero advisories and their Node/startup checks passed. These audits are time-specific, not perpetual safety claims.

**Not executed:** several C/C++/MASM, .NET, Java, PHP, Go, Linux, container/database, browser, VM, kernel, cloud, and GUI-tool exercises require additional runtime validation. Expected outputs in those sections remain predictions. Offline tests prove their fixture contracts, not actual enterprise permissions, product enforcement, provider behavior, or exploitation. Do not infer completion of those gates from this authoring pass.

### Initial Pair Checks

- Tests extracted directly from Markdown by `_meta/Test-FastAPIExamples.ps1`: 19 FastAPI tests and 22 FastAPI Security tests passed on Python 3.12. The final run used the printed pins, including `httpx2==2.16.0`, without test warnings. Author test runs are distinct from user lab completion.
- Vault validation passes with 1,462 resolving public wikilinks. The build processes 300 Markdown inputs and emits 489 files; publication-exclusion checks pass. Direct Node invocation reports a dependency `punycode` deprecation warning; the build still succeeds.
- Both revised pages load at 1440px and 390px widths with teaching prompts, code blocks, and tables present; no page-level horizontal overflow or JavaScript errors were observed. Fresh requests were needed to bypass cached initial-draft HTML.
- These checks cover in-process example tests and rendered notes, not live API-server deployment, real identity providers, concurrent load, or user exercise completion.

### Initial Draft Checks

The historical checks below certify structure and rendering at the initial-draft stage, not expert-level teaching quality across the vault.

- Vault checks pass locally and in CI mode: 282 course notes, 117 reciprocal pairs, 8 tools, 16 phase sections, and 1,459 resolving public wikilinks.
- Structured YAML parsing passes for all 300 public Markdown inputs; all 290 learning notes are `draft`, with zero completed checklist items.
- Quartz v4.5.2 build and TypeScript checks pass. The 488-file output passes the publication-exclusion, homepage, roadmap, search-index, and callout checks.
- Browser checks pass at 1440px and 390px widths for roadmap navigation, HTTP, AD Attacks, and WinDbg, with no page-level horizontal overflow or observed JavaScript errors. Search opens the Kerberos note successfully; desktop and mobile screenshots were reviewed.
- 169 of 170 distinct primary reference URLs responded successfully. The MySQL 8.4 security documentation returned HTTP 403; its reachability remains unverified here, not confirmed broken. URL availability does not validate every technical claim.
- The final npm audit reports 9 advisories: 4 low, 3 moderate, 2 high, none critical. They remain a dependency-maintenance concern, not a clean audit result.
- These checks validate local authoring and rendering only. No study labs, live GitHub Pages deployment, or migration of the user's separate WinDbg material was performed.

## Related

[[Course Plan]] | [[Style Guide]] | [[Agent Prompts]] | [[index|Home]]