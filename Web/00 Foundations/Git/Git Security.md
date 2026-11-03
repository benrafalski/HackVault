---
title: "Git Security"
aliases: []
tags: [web, w0, security]
domain: web
phase: "W0"
type: security
status: draft
pair: "[[Git]]"
updated: 2026-11-03
---
# Git Security

> [!abstract] TL;DR
> Ignore rules are not history removal, signatures are not code review, and a remote name is not an ownership guarantee. Review staged content and destination, minimize automation privileges, and revoke exposed credentials before coordinating repository cleanup.

## Attack Surface

Source bytes, commit/ref history, local hooks/configuration, build scripts, dependency metadata, automation tokens, artifacts and remotes form separate trust boundaries. An untrusted contribution can change CI behavior as well as application code. Merely removing a file from the working tree does not remove reachable historical blobs.

## Learn

```text
Teach me Git and repository security from objects/refs to collaboration. Cover
index versus ignore rules, historical/reflog/clone retention, staged review,
remote destination verification, merge/rebase trust, signatures, local hooks,
filters, submodules, build/CI trust and least-privilege tokens. Give a complete
offline temporary-repository lab with only an obviously synthetic marker:
track it, add an ignore rule, prove the rule does not untrack it, remove it from
the index and prove prior history remains. Include an independent staged-policy
test that preserves allowed content. No real secrets, publication, credential
collection, hook execution or history-rewrite walkthrough. Explain incident
response order and primary documentation. Teach here without editing files or
claiming execution; end with worked review decisions.
```

## Cheatsheet

### Data States and Exposure

| Location | What removal/ignore changes | What it does not change |
|---|---|---|
| Untracked working file | Ignore can suppress routine staging/status | File remains on disk and in backups |
| Index | `git rm --cached` removes tracked staging entry | Earlier commits and worktree file |
| Current commit | New deletion commit changes latest tree | Parent commits, tags, reflogs and clones |
| Rewritten branch | New ancestry/ref placement | Other refs, caches, forks, artifacts and retained copies |
| Hosted secret scanner | Detection/alert or push protection | Guaranteed absence, credential revocation or every private format |

A blob is content-addressed and reachable through trees/commits/refs; filename deletion is not erasure. Reflogs and unreachable-object retention complicate local cleanup. Real exposed credentials must be revoked or rotated, affected systems investigated, and dependent services updated. Then coordinate history cleanup and hosting support as appropriate; never promise universal deletion from already copied data.

### Review Before Recording or Publishing

Read-only inspection in a repository you are authorized to review:

```sh
git status --short
git diff --no-ext-diff --no-textconv
git diff --cached --no-ext-diff --no-textconv
git diff --cached --check
git remote -v
git ls-files -- .env
git check-ignore -v --no-index -- .env
git config --show-origin --get core.hooksPath
```

These commands can print sensitive data already present; do not paste it into notes or chats. Use synthetic fixtures for teaching. `--no-ext-diff --no-textconv` avoids invoking configured external diff/text conversion helpers during this review, but Git itself should still be current and repository ownership/configuration trusted. Local/global/system configuration precedence can affect behavior; inspect its source when a setting is unexpected.

Avoid broad `git add .` in a dirty worktree when you intend only selected files. Review the index after staging and after merge conflict resolution; a conflict-free merge is not a security review. Branch protections, mandatory checks and appropriate reviewers enforce process at the remote, while local hooks are useful but bypassable and not a sole enforcement boundary.

### Executable and Automation Trust

| Surface | Defense | Distinction |
|---|---|---|
| Hooks / templates | Review local installation and `core.hooksPath` | Ordinary clone does not simply install repository hooks as active local hooks |
| Filters / external tools | Audit configured helpers before checkout/build | Source checkout and later build execution have different triggers |
| Submodules | Review URLs and pinned commits before initializing | A pinned commit is content identity, not safe code |
| CI workflow changes | Separate untrusted PR validation from privileged release jobs | Do not expose production secrets to untrusted code |
| Dependencies/actions | Pin reviewed versions/immutable identities and update deliberately | Pinning prevents drift, not known vulnerabilities |
| Tokens | Minimum repository/action scope and short lifetime | Read access can still expose all accessible history |

Keep repository ownership checks enabled; do not globally set `safe.directory=*` to quiet an ownership warning. Fix ownership or explicitly trust the intended repository after review. Keep Git and hosting integrations patched; feature minimums such as Git 2.28 are not security recommendations.

Signatures verify that a key signed content under your trust policy. A valid signature does not establish that the human intended every change, that the key was uncompromised, or that a build is reproducible. Author name/email fields without verified signatures are metadata, not authenticated identity. Verify deployment artifacts and provenance separately where required.

### Remote and History Decisions

Inspect remote fetch and push URLs and the destination repository owner before publication. Fetch updates local remote-tracking refs and objects, not a live guarantee of current server state. Force-with-lease guards against some overwrites but can still conflict with team workflows and background fetch assumptions. Avoid rewriting shared branches without explicit coordination. Secrets in commit messages, tags, build logs, test snapshots and release archives are exposure surfaces even if the source tree is clean.

## Detection and Defense

Monitor secret-scan alerts, branch-policy changes, new deploy keys/tokens, workflow privilege changes and unexpected publish destinations. Scanner findings need triage: test fixtures can intentionally resemble credentials, while novel credential formats can be missed. Do not test a suspected real credential to see whether it works; use the issuer's revocation/inventory workflow. Maintain synthetic training markers that cannot authenticate anywhere.

## Labs

### Environment and Complete Files

Python 3.12+, patched Git 2.28+ on PATH. No packages/network. Every test creates its own temporary repository with synthetic identity, empty hooks/templates and isolated configuration. The marker is explicitly not a credential. No user repository, remote or history is modified.

### File: test_example.py

```python
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


MARKER = "SYNTHETIC_TRAINING_MARKER_NOT_A_CREDENTIAL"


class GitSecurityTests(unittest.TestCase):
	def setUp(self):
		if shutil.which("git") is None:
			raise RuntimeError("Git 2.28+ required")
		temporary = tempfile.TemporaryDirectory()
		self.addCleanup(temporary.cleanup)
		self.root = pathlib.Path(temporary.name)
		self.repo = self.root / "repo"
		self.repo.mkdir()
		self.empty = self.root / "empty"
		self.empty.mkdir()
		self.environment = {key: value for key, value in os.environ.items()
							if not key.upper().startswith("GIT_")}
		self.environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
								GIT_TERMINAL_PROMPT="0")
		self.git("init", "--initial-branch=main", "--template=" + str(self.empty))
		(self.repo / "README.txt").write_text("synthetic project\n", encoding="utf-8")
		self.git("add", "--", "README.txt")
		self.git("commit", "-m", "base")

	def git(self, *arguments, check=True):
		return subprocess.run(["git", "-C", str(self.repo),
							   "-c", "user.name=Lab User", "-c", "user.email=lab@example.test",
							   "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false",
							   "-c", "core.hooksPath=" + str(self.empty), *arguments],
							  env=self.environment, check=check, capture_output=True,
							  text=True, timeout=15)

	def test_ignore_baseline_and_index_fix(self):
		marker_file = self.repo / "local.env"
		marker_file.write_text(MARKER + "\n", encoding="utf-8")
		self.git("add", "--", "local.env")
		self.git("commit", "-m", "synthetic marker")
		marker_commit = self.git("rev-parse", "HEAD").stdout.strip()
		(self.repo / ".gitignore").write_text("local.env\n", encoding="utf-8")
		self.git("add", "--", ".gitignore")
		self.assertEqual(self.git("ls-files", "--", "local.env").stdout.strip(), "local.env")
		self.assertEqual(self.git("check-ignore", "local.env", check=False).returncode, 1)
		self.git("rm", "--cached", "--", "local.env")
		self.assertTrue(marker_file.exists())
		self.assertEqual(self.git("ls-files", "--", "local.env").stdout, "")
		self.assertEqual(self.git("check-ignore", "local.env").returncode, 0)
		self.assertEqual(self.git("show", marker_commit + ":local.env").stdout.strip(), MARKER)

	def test_staged_content_policy(self):
		target = self.repo / "README.txt"
		target.write_text(MARKER + "\n", encoding="utf-8")
		self.git("add", "--", "README.txt")
		staged = self.git("show", ":README.txt").stdout
		self.assertIn(MARKER, staged)
		target.write_text("approved synthetic documentation\n", encoding="utf-8")
		self.assertIn(MARKER, self.git("show", ":README.txt").stdout)
		self.git("add", "--", "README.txt")
		fixed = self.git("show", ":README.txt").stdout
		self.assertNotIn(MARKER, fixed)
		self.assertIn("approved synthetic documentation", fixed)


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

1. Record Git/Python versions; run `python -m unittest -v test_example`.
2. Explain why adding an ignore pattern leaves `local.env` tracked, and why `rm --cached` leaves its disk content intact.
3. Explain why the old commit still returns the marker after the index fix. No real secret is present and no rewrite is performed.
4. Remove the final `git add` in the staged-policy test; observe failure because editing the working file does not replace staged bytes. Restore it and retest.

### Hints

`git show :README.txt` reads the index. `git show <commit>:local.env` reads historical content. A policy check should inspect the state it intends to approve, not merely the working directory.

### Solution and Fixed Retest

Expected: two tests pass. Ignore alone changes no tracked entry; removing the index entry activates ordinary ignore behavior while preserving the local file and earlier history. Staged marker remains after a worktree edit until restaging; the fixed staged content contains only approved documentation. This is a deterministic marker policy, not a production secret scanner and not evidence of history erasure.

### Verification, Troubleshooting, and Cleanup

Unexecuted by the author. Optional `python -m pytest -q test_example.py` requires pytest. No signing key, authentication or remote is needed. A failing native Git command is a prerequisite/behavior failure, not a reason to run against the vault. Temporary repositories are removed automatically; delete the saved test/caches. No credentials require rotation because the marker cannot authenticate anywhere.

- [ ] Record tracked/ignored/index/history distinctions.
- [ ] Prove the staged-policy fix preserves approved content.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W0 Foundations|W0 Foundations]]
- [[Git]]

## References

- [Git ignore](https://git-scm.com/docs/gitignore)
- [Git configuration and safe.directory](https://git-scm.com/docs/git-config)
- [Git hooks](https://git-scm.com/docs/githooks)
- [Git object model](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects)
