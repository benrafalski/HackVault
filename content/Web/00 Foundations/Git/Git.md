---
title: "Git"
aliases: []
tags: [web, w0]
domain: web
phase: "W0"
type: tech
status: draft
pair: "[[Git Security]]"
updated: 2026-11-03
---
# Git

> [!abstract] TL;DR
> Git stores snapshots and a commit graph. Working tree, index, HEAD, local branches and remote-tracking refs are distinct states; inspect the relevant comparison before changing any of them.

## Prerequisites

Files, processes and a terminal; Git 2.28+ for `init --initial-branch` and `switch`, Python 3.12+ for the lab. Prefer a currently patched Git release. All lab commits exist only in generated temporary repositories; never run the exercise in this vault.

## Learn

```text
Teach me Git internals and safe collaboration. Explain blobs, trees, commits,
annotated tags, content addressing, reachability, refs/HEAD/reflogs, working tree
versus index, staged diffs, branches, merge bases/conflict stages, merge versus
rebase, fetch versus pull, remote-tracking refs and push policy. Cover ignore
rules, tracked secret boundaries, line-ending attributes and signatures without
equating signatures with safe code. Give a complete disposable local-repository
lab with a merge conflict, independent file tests and local-only fetch; no hosted
remotes or publication. Include version prerequisites, expected outcomes and
cleanup. Cite official Git documentation. Teach here without editing files or
claiming execution; finish with worked state-transition questions.
```

## Cheatsheet

### Objects, Refs, and the Three States

A blob stores file content, not its filename. A tree maps names/modes to blobs or subtrees. A commit names a root tree, parents, author/committer metadata and message. An annotated tag is its own object; a lightweight tag is only a ref. Object IDs depend on encoded object content and the repository hash format; do not assume every repository uses a 40-character SHA-1 ID. Content addressing detects object identity, not author trust.

Branches are movable refs under `refs/heads`; remote-tracking refs under `refs/remotes` are your last fetched view, not a live remote query. HEAD usually symbolically names a branch; detached HEAD names a commit directly. Reflogs record local ref movements and can aid recovery until expiry; they are not permanent backups. Objects remain while reachable from refs/reflogs or until retention and garbage collection remove unreachable data.

| Command | Comparison / effect |
|---|---|
| `git diff` | Working tree versus index |
| `git diff --cached` | Index versus HEAD; what the next commit would contain |
| `git diff HEAD` | Working tree versus last commit |
| `git status --short` | Two columns: index state then worktree state; `??` untracked |
| `git add -- path` | Copies current content into index, not future edits |
| `git show HEAD:path` | Content stored in that commit, regardless of current file |
| `git cat-file -p HEAD` | Commit object internals |
| `git ls-tree HEAD` | Names/modes/object IDs in committed tree |

If you edit after staging, both `git diff` and `git diff --cached` can be nonempty for the same file. Review staged content explicitly before committing. `git diff --check` detects whitespace errors, not semantic bugs or secrets. Diff rename detection is a similarity inference, not a rename object stored in the repository.

### Branches, Integration, and Collaboration

`git switch -c topic` creates and switches to a branch. A fast-forward moves a ref along existing ancestry; a merge commit joins histories with multiple parents. A three-way merge compares the merge base with both sides. During a conflict, index stages 1/2/3 store base/ours/theirs; resolve the worktree and `git add` the resolution before completing the merge. Meaning of ours/theirs can be counterintuitive during rebase because commits are replayed onto another base.

```sh
git status --short
git diff --no-ext-diff
git diff --cached --no-ext-diff
git log --oneline --graph --decorate -10
git ls-files -u
git remote -v
```

| Need | Preferred decision | Caution |
|---|---|---|
| Inspect upstream changes | Fetch then inspect remote-tracking diff/log | Fetch updates refs/objects, not current worktree integration |
| Integrate without surprise merges | Explicit `pull --ff-only` when policy fits | Fails on divergence rather than choosing an integration strategy |
| Preserve shared history | Merge or new corrective/revert commit | Rebase rewrites commit identities |
| Revise unpublished topic work | Rebase can be appropriate after review | Replayed conflict resolution and signatures need rechecking |
| Publish | Verify remote URL, branch and staged/committed content first | A remote name such as origin proves no ownership |

Force-with-lease reduces accidental overwrites compared with blind force but is not universal safety; know the expected remote commit and team policy. Do not rewrite shared history or publish without authorization. A signed commit verifies a signature against a key/trust configuration, not that tests passed or the author reviewed every dependency.

### Ignore Rules and Secret Boundaries

`.gitignore` applies to untracked paths; it does not untrack indexed files. Patterns are relative to the containing ignore file; a leading slash anchors there, a trailing slash selects directories, and later matching patterns can override earlier ones. Negation cannot re-include a file through an excluded parent unless the parent is also traversable by the ignore rules. `.git/info/exclude` is local; global excludes are user-specific. Use `git check-ignore -v -- path` to identify the rule; `--no-index` can explain a matching rule even for a tracked path.

`git rm --cached -- path` removes a path from the index while leaving the worktree file, but existing commits remain. Exposed credentials require revocation/rotation first; removing history is a separately coordinated containment task. `.gitattributes` controls content transformations such as text/eol and diff behavior; platform autocrlf can make bytes differ between working tree and repository. Define intentional attributes and inspect actual diffs, not just filenames.

## Gotchas

Local hooks, signing, clean/smudge filters and external diff drivers can execute tools. Review untrusted repositories before building or changing configuration. `git restore`, reset and clean can discard work; they are not routine first-line diagnostics. Stash is local state with retention/recovery caveats, not a substitute for reviewed commits/backups.

## Labs

### Environment and Complete Files

Python 3.12+, patched Git 2.28+ on PATH. No packages/network. Each test creates a fresh repository, isolated Git config and empty template/hook directories. It sets synthetic identity only per invocation; no user/global config changes. The local bare clone/fetch never publishes to a service.

### File: test_example.py

```python
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


class GitTests(unittest.TestCase):
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
		self.file = self.repo / "message.txt"
		self.file.write_text("base\n", encoding="utf-8")
		self.git("add", "--", "message.txt")
		self.git("commit", "-m", "base")

	def git(self, *arguments, check=True):
		return subprocess.run(["git", "-C", str(self.repo),
							   "-c", "user.name=Lab User", "-c", "user.email=lab@example.test",
							   "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false",
							   "-c", "core.hooksPath=" + str(self.empty), *arguments],
							  env=self.environment, check=check, capture_output=True,
							  text=True, timeout=15)

	def test_index_and_objects(self):
		self.file.write_text("staged\n", encoding="utf-8")
		self.git("add", "--", "message.txt")
		self.file.write_text("working\n", encoding="utf-8")
		self.assertIn("+staged", self.git("diff", "--cached").stdout)
		self.assertIn("+working", self.git("diff").stdout)
		self.assertEqual(self.git("show", "HEAD:message.txt").stdout, "base\n")
		self.assertEqual(self.git("cat-file", "-t", "HEAD").stdout.strip(), "commit")
		self.assertIn("blob", self.git("ls-tree", "HEAD").stdout)

	def test_merge_conflict_and_resolution(self):
		self.git("switch", "-c", "topic")
		self.file.write_text("topic\n", encoding="utf-8")
		self.git("commit", "-am", "topic change")
		self.git("switch", "main")
		self.file.write_text("main\n", encoding="utf-8")
		self.git("commit", "-am", "main change")
		merge = self.git("merge", "--no-edit", "topic", check=False)
		self.assertEqual(merge.returncode, 1)
		self.assertTrue(self.git("ls-files", "-u").stdout)
		self.file.write_text("combined\n", encoding="utf-8")
		self.git("add", "--", "message.txt")
		self.git("commit", "--no-edit")
		self.assertEqual(len(self.git("rev-list", "--parents", "-n", "1", "HEAD").stdout.split()), 3)
		self.assertEqual(self.git("status", "--porcelain").stdout, "")

	def test_local_remote_fetch(self):
		remote = self.root / "training.git"
		self.git("clone", "--bare", "--template=" + str(self.empty), str(self.repo), str(remote))
		self.git("remote", "add", "training", str(remote))
		before = self.git("rev-parse", "HEAD").stdout
		self.git("fetch", "training")
		self.assertEqual(self.git("rev-parse", "training/main").stdout, before)
		self.assertEqual(self.git("rev-parse", "HEAD").stdout, before)


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. Record `git --version`; run `python -m unittest -v test_example` outside any important repository.
2. Explain why staged, working and committed values all differ in the first test.
3. Identify the conflict's base and both sides; explain why the final commit has two parents, represented by three IDs including itself.
4. Explain why fetch creates `training/main` without moving HEAD. No push is performed.

### Hints

A commit snapshots the index, not whatever is now in the file. Merge conflict status 1 is expected here, while other subprocess failures indicate setup or behavior differences. No particular commit hash is assumed.

### Solution and Expected Results

Expected: three tests pass. Staged diff contains `+staged`, unstaged diff `+working`, and HEAD remains `base`. Diverging same-line edits conflict; recording `combined` creates a clean two-parent merge. Local fetch updates the remote-tracking ref and leaves HEAD unchanged. Removing the `git add` before the merge-resolution commit makes that test fail because unresolved index stages remain.

### Verification, Troubleshooting, and Cleanup

Unexecuted by the author. Optional runner: `python -m pytest -q test_example.py`. No hosted credentials needed. Missing `switch`/initial-branch support means the Git prerequisite is unmet. Antivirus may temporarily hold Windows temporary files; close only the lab processes before retrying cleanup. All repositories are temporary and auto-removed; delete the saved test/caches. No vault branch, commit, remote or config was changed by authoring this note.

- [ ] Explain index/object/ref state and merge conflict resolution.
- [ ] Record local-fetch behavior without publication.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W0 Foundations|W0 Foundations]]
- [[Git Security]]

## References

- [Pro Git](https://git-scm.com/book/en/v2)
- [Git revisions](https://git-scm.com/docs/gitrevisions)
- [Git diff](https://git-scm.com/docs/git-diff)
- [Git ignore](https://git-scm.com/docs/gitignore)
