# HackVault Agent Instructions

- Read [_meta/Style Guide.md](_meta/Style%20Guide.md) before editing notes.
- Use the matching workflow in [_meta/Agent Prompts.md](_meta/Agent%20Prompts.md) and template in `_meta/Templates/`.
- The scope and phase inventory live in [_meta/Course Plan.md](_meta/Course%20Plan.md); roadmaps list the actual note filenames.
- Fill existing stubs in place. Preserve their scope, unique filenames, reciprocal pair links, and the user's completed checkboxes.
- Use old HackBook material only as a source; verify it and write fresh notes. Do not import the archive wholesale.
- Keep notes concise. No page-table hierarchy, Firewire, or Intel-confidential content. WinDbg commands belong only in `WinDbg.md`.
- Use only standard Markdown, wikilinks, YAML frontmatter, and Obsidian callouts. Do not require plugins to render notes.
- Content starts at `draft` after an agent fills it. Only the user promotes it through `learning`, `practiced`, and `mastered`.
- Run `pwsh -NoProfile -File "_meta/Test-Vault.ps1"` after scaffold or link changes. Do not move the vault, publish, push, or commit unless asked.