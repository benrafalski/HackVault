---
title: "NTFS and Alternate Data Streams"
aliases: []
tags: [windows, x1]
domain: windows
phase: "X1"
type: tech
status: draft
pair: "[[NTFS Security]]"
updated: 2026-11-03
---
# NTFS and Alternate Data Streams

> [!abstract] TL;DR
> Inspect final resolved object, streams, ACLs, and sharing mode. Validate containment with filesystem semantics, especially before privileged writes.

> [!info] Agent scope
> Files and metadata; ADS; reparse points; hard links; ACLs; sharing modes; path normalization; filesystem observations.

## Prerequisites

- Windows 10/11, Windows PowerShell 5.1, a local NTFS user temporary directory. Standard user; no compiler, external packages, reparse creation or system-directory writes.
- [[Windows Lab Setup]]

## Learn

```text
Teach NTFS file identity, streams, names, sharing and access control at Windows
API depth. Assume handles, DACLs, basic storage and Unicode paths. Explain file
records/attributes, unnamed and named $DATA, stream sizes versus file times,
hard-link identity, reparse tags, symlink/junction distinctions, and deletion
while handles/names remain. Separate requested access, DACL evaluation and
bidirectional share compatibility. Explain DELETE versus parent delete-child,
rename behavior, oplocks versus locks, and file-ID/volume identity limits.
Cover DOS/extended/UNC paths, drive-relative names, reserved devices, trailing
dots/spaces, ADS colon syntax, case sensitivity, long-path opt-in and TOCTOU.
Give complete harmless stream/hard-link/share observations only inside a newly
created own temporary directory. No system reparse manipulation, privileged
writer, access-control changes or external paths. Explain handle-based final
object checks without pretending string normalization guarantees containment.
Use official Microsoft sources, exact commands, failure codes, version caveats,
verification and answered questions. Do not edit notes or fabricate results.
```

## Cheatsheet

### File, Name, Stream, Handle

NTFS file records contain attributes; file data can be resident or stored in extents. A pathname resolves a directory entry to a file and possibly a named stream. The ordinary `file.txt` opens its unnamed `$DATA` stream; `file.txt:note:$DATA` names a separate data stream. A directory can also have named data streams. A hash of the unnamed stream is not a hash of the whole file's metadata/stream set.

| Object/property | Consequence |
|---|---|
| Hard link | Another name for the same file on the same volume; contents, streams and file security are shared. Removing one name does not necessarily remove data. Directory hard links are not ordinary supported application links. |
| Reparse point | Tagged data invokes filesystem/filter-specific processing. Not all reparse tags are symlinks; cloud placeholders and mount points need different handling. |
| ADS | Separate size/allocation/sparse/compression state, but no independent ordinary file DACL or independent file timestamps. Stream writes can update file times. |
| Open handle | Holds access granted at open time and references the object even if names change. It is not equivalent to repeatedly reopening the original path. |
| File ID + volume identity | Useful for comparing opened objects; IDs may be reused after deletion and are not permanent global identifiers. |

`FindFirstStreamW`/`FindNextStreamW` enumerate data streams; close their search handle with `FindClose`. `GetFileInformationByHandleEx(FileIdInfo)` retrieves opened-object identity; `FileAttributeTagInfo` reports attributes/tag. `GetFinalPathNameByHandleW` reports a resolved path, but that string can become stale. `FILE_FLAG_OPEN_REPARSE_POINT` affects the final component; it does not prevent reparse processing in every intermediate directory. `FILE_FLAG_BACKUP_SEMANTICS` permits appropriate directory opens and is not by itself a grant of backup privileges.

### Access and Sharing Are Different

`CreateFileW` access bits request permitted operations. `dwShareMode` declares what other opens may request. Compatibility is checked in both directions against existing opens; a valid ACL can still produce `ERROR_SHARING_VIOLATION` (32). `FILE_SHARE_DELETE` permits compatible delete/rename opens, not permission to delete. Delete authority can derive from `DELETE` on the file or `FILE_DELETE_CHILD` on its parent; evaluate both with actual token and filesystem semantics.

Sharing and oplocks are primarily per stream, but opening a file for delete checks open streams' delete-sharing compatibility. Byte-range locks coordinate particular data regions, not names or authorization. Oplocks coordinate cache/lease behavior and are not security locks. Modern disposition/POSIX-style deletion flags can change observable name lifetime on supported filesystems/Windows releases; do not generalize one legacy `DeleteFileW` experiment to every API.

### Path Semantics and Observation

| Syntax | Meaning/risk |
|---|---|
| `C:\dir\file` | Drive-absolute DOS path. |
| `C:file` | Relative to drive C's current directory, not necessarily `C:\file`. |
| `\file` | Root-relative to the current drive. |
| `\\server\share\file` | UNC path, remote filesystem/server semantics apply. |
| `\\?\C:\...` | Extended path syntax changes normalization rules; not a universal safety prefix. |
| `name:stream` | ADS selector, not an ordinary leaf filename for a flat-file application. |

Windows paths are commonly case-insensitive, but per-directory case sensitivity exists on supported modern Windows. Long-path support depends on API, application manifest and policy; extended paths have separate constraints. Reserved device names and trailing dot/space normalization complicate validation. Canonicalizing a string does not bind it to a stable object; untrusted directory mutation creates a check/open race.

Read-only commands for a known lab file:

```powershell
Get-Item -LiteralPath .\marker.txt -Stream *
Get-Content -LiteralPath .\marker.txt -Stream note
Get-Acl -LiteralPath .\marker.txt | Format-List Owner,AccessToString
```

The commands require that lab file, not any system file. A displayed ACL is not a complete effective-access evaluation. Some copy/archive tools omit streams; verify preservation explicitly rather than assuming it.

## Gotchas

- ADS are a legitimate filesystem mechanism; presence alone is not malicious. Stream names and contents may be application metadata.
- `Zone.Identifier` is one consumer-specific stream, not a universal guarantee of origin or trust. This lab does not alter it.
- Filesystem/filter/SMB behavior can differ from local NTFS. Fail the prerequisite rather than silently switching to a generic model.

## Labs

### Environment and Complete Files

One script in a scratch directory. It creates a unique child of the current user's local NTFS temporary directory and touches only two file names there. No reparse points, permissions changes, cross-user access or system files. Do not run while another process intentionally modifies this lab directory.

### File: observe-ntfs.ps1

```powershell
$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ('HV-NTFS-' + [guid]::NewGuid().ToString('N'))
$drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($root))
if ($drive.DriveFormat -ne 'NTFS') { throw 'A local NTFS temp volume is required' }
[void][IO.Directory]::CreateDirectory($root)
$root
$original = Join-Path $root 'marker.txt'
$alias = Join-Path $root 'alias.txt'
$held = $null
try {
	Set-Content -LiteralPath $original -Value 'BASE' -Encoding Ascii -NoNewline
	Set-Content -LiteralPath $original -Stream note -Value 'STREAM' -Encoding Ascii -NoNewline
	[void](New-Item -ItemType HardLink -Path $alias -Target $original)
	Get-Item -LiteralPath $original -Stream * | Select-Object Stream,Length
	if ((Get-Content -LiteralPath $alias -Stream note -Raw) -ne 'STREAM') { throw 'ADS mismatch' }
	Set-Content -LiteralPath $alias -Value 'EDIT' -Encoding Ascii -NoNewline
	if ((Get-Content -LiteralPath $original -Raw) -ne 'EDIT') { throw 'Hard-link mismatch' }
	Get-Acl -LiteralPath $original | Format-List Owner,AccessToString
	$held = [IO.File]::Open($original, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
	$denied = $false
	try { [void][IO.File]::ReadAllText($alias) }
	catch {
		$failure = $_.Exception
		while ($null -ne $failure.InnerException) { $failure = $failure.InnerException }
		if ($failure -isnot [IO.IOException] -or ($failure.HResult -band 0xffff) -ne 32) { throw }
		$denied = $true
	}
	if (-not $denied) { throw 'Expected sharing violation through the other name' }
	$held.Dispose()
	$held = $null
	Remove-Item -LiteralPath $original
	if ((Get-Content -LiteralPath $alias -Raw) -ne 'EDIT') { throw 'Remaining link lost data' }
	if ((Get-Content -LiteralPath $alias -Stream note -Raw) -ne 'STREAM') { throw 'Remaining link lost ADS' }
	'PASS: shared contents/ADS, sharing denial, surviving hard link'
} finally {
	if ($null -ne $held) { $held.Dispose() }
	foreach ($path in @($alias, $original)) {
		if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
	}
	if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root }
}
```

### Objectives, Steps, and Hints

Run `powershell.exe -NoProfile -File .\observe-ntfs.ps1` under existing script policy. Predict unnamed-stream length 4 and `note` length 6. Explain why editing through `alias.txt` changes `marker.txt`, why an exclusive open blocks reads through the other name, and why deleting the original leaves both contents and ADS accessible through the alias.

### Solution and Expected Results

Expected stream table includes `:$DATA` length 4 and `note` length 6 (display naming may vary), followed by inherited ACL evidence and PASS. The script asserts the contents, sharing error 32, and surviving name/ADS. This distinguishes file identity from path spelling and sharing from authorization. No second user is created or tested.

### Verification, Troubleshooting, and Cleanup

All assertions must pass, exit successfully, and leave no unique lab directory. Non-NTFS/UNC temp storage is outside prerequisites. If a security product holds a file open, record the resulting failure; do not disable it. `finally` removes only the two known names and the empty created directory, without recursive deletion. If interrupted, inspect the printed/known `HV-NTFS-*` directory and remove only this run's two names; do not wildcard-delete other runs. Source reviewed, not executed; parent must validate Windows PowerShell 5.1, ADS, hard links and sharing on local NTFS.

- [ ] Local NTFS exercise: Observe real streams, hard-link identity, ACL evidence and sharing denial in own temp paths.
- [ ] Boundary check: Explain why path spelling and ACL display alone do not prove containment or effective access.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[NTFS Security]]

## References

- [File streams](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)
- [Hard links and junctions](https://learn.microsoft.com/en-us/windows/win32/fileio/hard-links-and-junctions)
- [CreateFileW access and sharing](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [Naming files, paths and namespaces](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
