---
title: Course Plan
tags: [meta, plan]
type: meta
updated: 2026-11-02
---
# HackVault: Course Plan (Web + Windows)

## Summary

Each technology gets a **pair of notes**:

- `<Tech>.md`: how the technology works and how to build with it.
- `<Tech> Security.md`: how to attack it and how to defend it.

Every note has three parts:

1. **Learn**: read the material, then do the hands-on exercises.
2. **Cheatsheet**: a condensed section for quick review later.
3. **Labs**: a checklist of CTFs and labs to complete.

Attack techniques that apply to many technologies get their own single note in each domain's `Attacks/` phase folder. Technology notes link to them.

Each domain has a **roadmap** page. It lists the phases, links to every note in each phase, the exit criteria for finishing the phase, and recommended labs.

`_meta/Agent Prompts.md` holds reusable prompts. With them, any agent can later be asked to "fill phase W2" and will produce consistent notes.

All notes use only standard wikilinks, frontmatter and callouts. This keeps them compatible with Quartz, so the vault can be published to GitHub Pages.

### Material from the old HackBook

Old material lives in `C:\Users\brafalsk\repos\HackBook`. Use it as source material for agents to draw from; don't copy it in.

- `archive/Web/XSS.md`, `archive/Web/HTTP.md`, `archive/Web/nginx.md`: sources for W0 and W6.
- `archive/Windows/smb/smbclient.md`, `pages/windows/architecture.html`: sources for X0 and X4.
- `pages/arch/x86-os-internals.html`: source for X1 and X2. Skip any page-table material.

---

## Vault layout

```
HackVault/
├── index.md                  # home page: links to both roadmaps
├── AGENTS.md                 # points agents to Style Guide + Agent Prompts
├── _meta/
│   ├── Course Plan.md        # this file
│   ├── Style Guide.md        # note rules, frontmatter, statuses, naming, user prefs
│   ├── Agent Prompts.md      # copy-paste prompts for future agents
│   └── Templates/            # Tech, Security, Technique, Lab Writeup, Roadmap
├── Web/
│   ├── Web Roadmap.md
│   ├── 00 Foundations/HTTP/HTTP.md + HTTP Security.md
│   ├── ...
│   ├── 06 Attacks/<Technique>.md
│   └── Labs/
├── Windows/
│   ├── Windows Roadmap.md
│   ├── 00 Foundations/...
│   ├── ...
│   └── Labs/
├── Tools/                    # Burp Suite, WinDbg (link only), Ghidra/IDA, Sysinternals, BloodHound, Impacket ...
└── Private/                  # never published
```

### Conventions

- **Frontmatter fields:**
  - `title`
  - `aliases`
  - `tags`
  - `domain`
  - `phase`
  - `type`: `tech` | `security` | `technique` | `method` | `moc` | `lab`
  - `status`: `stub` → `draft` → `learning` → `practiced` → `mastered`
  - `pair`: link to the sibling note
  - `updated`
- **File naming:**
  - Name the security note `Django Security.md`, not `Django - Security.md`. Quartz turns ` - ` into `---` in the URL.
  - Avoid `/ : # & ? .` and leading dots in file names, e.g. use `DotNet and CLR` and `Nodejs and Express`. Put the nicer display name in `title`.
  - File names must be unique across the whole vault, because wikilinks resolve by name.
- **Note types:**
  - **Pair** (`tech` + `security`): a technology to learn and to attack.
  - **Technique**: a single note for an attack class that applies across technologies (W6, X5, X6).
  - **Method**: a single note on methodology or workflow (W7, lab setup).

### User preferences (apply to every note)

- Keep notes concise and cheatsheet-style, not long prose.
- Don't include the page-table hierarchy; the user knows it already.
- Don't include Firewire/IEEE 1394.
- WinDbg commands live **only** in the WinDbg note. Elsewhere, link to it.
- The site is public, so nothing Intel-confidential goes in. Use `Private/` for that.

---

## Web track

| Phase | Notes |
|---|---|
| **W0 Foundations** | TCP/IP, DNS, TLS & PKI, HTTP/1.1, HTTP/2 & HTTP/3, URLs & Encoding, Browser Security Model (SOP, CORS, cookies, CSP), Linux CLI, Git, Web Lab Setup (method) |
| **W1 Frontend** | HTML, CSS, JavaScript, TypeScript, DOM & Browser APIs, React, Angular, Vue, Bundlers (Vite/webpack), npm Ecosystem, WebSockets, postMessage, Service Workers, WebAssembly |
| **W2 Backend** | Node.js/Express, Next.js, Python (Flask, Django, FastAPI), PHP/Laravel, Java/Spring, ASP.NET Core, Go, Template Engines (Jinja2, Twig, Razor), Serialization (JSON, XML, YAML), REST APIs, GraphQL, gRPC, Nginx, Apache, IIS |
| **W3 Data** | SQL (MySQL, PostgreSQL, MSSQL, SQLite), ORMs, MongoDB, Redis, Elasticsearch, Object Storage (S3/Blob), Message Queues |
| **W4 Identity** | Sessions & Cookies, Password Storage, JWT, OAuth 2.0, OpenID Connect, SAML, MFA & WebAuthn/Passkeys |
| **W5 Infra/Cloud** | Docker, Kubernetes, CI/CD (GitHub Actions), Reverse Proxies/CDN/WAF, HTTP Caching, AWS, Azure, Serverless, Terraform |
| **W6 Attacks** (technique notes) | XSS, CSRF, Clickjacking, CORS Misconfig, SQLi, NoSQLi, Command Injection, Path Traversal, File Upload, SSRF, XXE, SSTI, Insecure Deserialization, Prototype Pollution, Broken Access Control/IDOR, Business Logic, Race Conditions, Request Smuggling, Cache Poisoning/Deception, Host Header, OAuth Attacks, JWT Attacks, GraphQL Attacks, WebSocket Attacks, Supply Chain, LLM/Prompt Injection |
| **W7 Methodology** (method notes) | Recon & Subdomain Enum, Content Discovery, Burp Workflow (see Tools/Burp Suite), Source Code Review, Bug Bounty Methodology, Reporting |

**Labs:**
- PortSwigger Web Security Academy (main platform for W6)
- HTB Academy and HTB machines
- pwn.college CSE365
- Local vulnerable apps: OWASP Juice Shop, DVWA, crAPI

## Windows track

| Phase | Notes |
|---|---|
| **X0 Foundations** | x64 Assembly & Windows x64 ABI, C/C++ on Windows (MSVC), Windows Architecture Overview, Tooling Setup (Sysinternals, System Informer, x64dbg, Ghidra/IDA, WinDbg link), Windows Lab Setup (method: AD lab, kernel-debug VM) |
| **X1 User-mode Internals** | Processes & Threads, Virtual Memory (VADs, heaps), PE Format, Loader & DLLs (PEB, IAT/EAT), Win32 vs Native API & Syscalls, Objects & Handles, Security Model (tokens, SIDs, privileges, integrity levels, ACLs, UAC), Registry, Services & SCM, Scheduled Tasks, IPC (Named Pipes, ALPC, RPC), COM/DCOM, Exceptions & SEH, NTFS (ADS), WMI, ETW & Event Log |
| **X2 Kernel & Platform** | Kernel Architecture (IRQL, DPC/APC, scheduler), Drivers (WDM/KMDF, IRPs, IOCTLs), Kernel Callbacks & Minifilters, WFP, Boot Process (UEFI, Secure Boot, ELAM, Measured Boot, TPM), VBS/HVCI/Credential Guard/Hyper-V, PatchGuard |
| **X3 Development** | PowerShell, .NET/C# & CLR, Win32 Programming, COM Programming, Driver Development |
| **X4 Enterprise** | SMB, RDP, WinRM, LDAP, NTLM, Kerberos, Active Directory (domains, forests, trusts), Group Policy, AD CS, LAPS, Entra ID & Hybrid, MSSQL |
| **X5 Offensive** (technique notes) | Local PrivEsc, Credential Access (LSASS, SAM, DPAPI), Lateral Movement, Persistence, AD Attacks (Kerberoasting, AS-REP, delegation, DCSync, ADCS ESC1–ESC15, relay), Evasion (AMSI, ETW, unhooking, direct syscalls), Process Injection |
| **X6 Exploit Dev** (technique notes) | Mitigations (DEP, ASLR, CFG/XFG, CET, ACG/CIG, SMEP/SMAP, kCFG), Stack/SEH Overflows, Heap (NT/Segment heap), ROP on Windows, Kernel Exploitation (token stealing, BYOVD), Malware Analysis/RE |
| **X7 Defense** (pairs: tool + bypass) | Defender/EDR Architecture, Sysmon, ETW-TI, AppLocker/WDAC, ASR Rules, Detection Engineering (Sigma, KQL), Hardening Baselines |

**Labs:**
- HTB Academy (CPTS/CAPE paths), HTB Pro Labs
- A home AD lab such as GOAD
- A VM set up for kernel debugging
- HEVD (HackSys Extreme Vulnerable Driver)
- Exploit Education / Corelan-style exercises
- pwn.college CSE466 for exploitation fundamentals

---

## Steps

### Phase A: Scaffold (one agent run)

1. In `Documents\HackVault`:
   1. Delete `Welcome.md`.
   2. Create `index.md`, `AGENTS.md`, `_meta/` and `Private/`.
2. Write `_meta/Style Guide.md` and the five templates in `_meta/Templates/`:
   - **Tech template:** TL;DR callout, Prerequisites, Learn (mental model, core concepts, under the hood), Build It exercises, Cheatsheet, Gotchas, Related, References.
   - **Security template:** TL;DR, Attack Surface, Learn (root causes), Exploitation Cheatsheet, Detection & Defense, Labs checklist, Related techniques.
   - **Technique template:** TL;DR, Root cause, Variants, Detection (finding it), Exploitation cheatsheet (payloads), Bypasses, Defense, Labs.
   - **Lab Writeup template:** Target, Recon, Foothold, Escalation, Lessons, Cheatsheet additions.
   - **Roadmap template:** Phase goal, Notes, Labs, Exit criteria.
   - Then set Obsidian's Templates folder to `_meta/Templates`.
3. Write `_meta/Agent Prompts.md`, with prompts to:
   - fill one technology pair,
   - fill a whole phase,
   - write a technique note,
   - turn a lab into a writeup,
   - generate quiz/review questions from a cheatsheet.

   Each prompt points the agent to the Style Guide, the matching template, and the HackBook source paths. *(Can run in parallel with step 2.)*
4. Create `Web/Web Roadmap.md` and `Windows/Windows Roadmap.md`. For each phase, include:
   - a goal,
   - a checklist of links to its notes,
   - an exit criterion (e.g. "solve all PortSwigger Apprentice labs for W6"),
   - recommended labs.
5. Create a stub for every entry in both tables. Each stub has frontmatter with `status: stub`, an "Agent scope" callout listing the subtopics to cover, and the empty template headings. This means every link in the roadmaps works from day one. *Depends on steps 2 and 4.*

### Phase B: Quartz publishing (depends on A)

1. Create a Quartz v4 repo at `C:\Users\brafalsk\repos\HackVault`.
2. Move the vault into the repo's `content/` folder, then open `content/` in Obsidian as the vault.
3. Before running `npm i`, set the npm proxy:
   - `npm config set proxy http://proxy-dmz.intel.com:912`
   - `npm config set https-proxy http://proxy-dmz.intel.com:912`
4. In `quartz.config.ts`, set `ignorePatterns` to `["_meta/Templates", "Private", ".obsidian", "AGENTS.md"]`.
5. Add the GitHub Pages deploy workflow from the Quartz docs and push.

### Phase C: Content (repeat over time, one phase per agent session)

1. Ask an agent to use the "Fill phase" prompt, e.g. *"Fill W0 per `_meta/Agent Prompts.md`"*. The agent fills the notes and sets their status to `draft`.
2. Read the Learn sections and do the Build It exercises (`learning`).
3. Do the labs and write them up in `Labs/` using the Lab Writeup template (`practiced`).
4. Check yourself against the phase's exit criteria, then tick the boxes in the roadmap (`mastered`).
5. Suggested order: alternate between tracks (W0 → X0 → W1 → X1 → …), or finish one track first.

---

## Verification

1. In Obsidian, the unresolved-links view shows nothing, or graph view shows no orphan "ghost" nodes.
2. Every Tech note's `pair` link resolves to its Security note, and every Security note links back.
3. Running `npx quartz build --serve` shows no `_meta/Templates` or `Private` pages, and wikilinks and callouts render correctly.
4. After deploying, the GitHub Pages site loads both roadmaps.

## Scope

- **Included:** the Web and Windows tracks, and a structure that can later take more domains (Linux, Cloud, Mobile, Hardware/Firmware) using the same pattern.
- **Excluded:**
  - Firewire
  - page-table write-ups
  - WinDbg commands outside the WinDbg note
  - anything Intel-confidential
