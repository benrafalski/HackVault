---
title: "Virtual Memory Security"
aliases: []
tags: [windows, x1, security]
domain: windows
phase: "X1"
type: security
status: draft
pair: "[[Virtual Memory]]"
updated: 2026-11-03
---
# Virtual Memory Security

> [!abstract] TL;DR
> Writable executable regions, lifetime errors, unchecked allocation sizes, and unsafe cross-process access can enable memory corruption or unintended execution.

> [!info] Agent scope
> Defensive reserve/commit, VAD observations, protections, mapped files, heaps and allocation APIs. Validate sizes, permissions and lifetimes in owned memory only.

## Attack Surface

- Size arithmetic, allocation failure, stale aliases, allocator mismatch, shared-view permissions, and synchronization are independent failure surfaces.
- Page protection constrains accesses through a mapping; it does not validate logical object bounds or protect against equally trusted code changing that mapping.

## Learn

```text
Teach defensive Windows memory API engineering at expert depth. Assume C and
Win32 basics. Cover checked SIZE_T arithmetic, allocation budgets, reserve/commit
versus protection, VAD/VirtualQuery snapshot limits, heap ownership, private versus
mapped storage, stale aliases, synchronization, clearing sensitive bytes, and
view/section lifetime. Explain why query-before-use and catch-all exceptions do not
make pointers safe. Give a complete self-process C lab that writes an owned page,
makes it read-only, catches only the expected write access violation at that page,
proves reads still work, restores write access for clearing, and releases it.
Explain W^X and allocator/compiler defenses without executable-memory examples or
exploitation. No address-translation internals, arbitrary-process access, bypasses,
private data or debugger commands. Cite Microsoft docs; distinguish predicted
results, build constraints and actual evidence. Teach here, not file authoring.
```

## Cheatsheet

### Failure, Fix, and Boundary

| Root cause | Concrete defense | Limit |
| --- | --- | --- |
| `count * width` wraps before allocation | Test `width != 0 && count <= SIZE_MAX / width`; impose a smaller byte budget | A representable size may still exhaust commit |
| Treat allocation failure as a usable buffer | Check `VirtualAlloc`/`HeapAlloc` for `NULL` before any access | HeapAlloc does not generally set last error |
| Query then use a pointer another thread can free | Own the allocation or hold the same lock/reference protocol across use | VirtualQuery is a snapshot, not pinning or object validation |
| Suballocations share one page | Keep protection changes on dedicated VirtualAlloc regions | Protecting a heap block can break neighboring blocks and allocator metadata |
| Free with wrong allocator | Pair HeapAlloc/HeapFree with the same heap; map/unmap views; reserve/release original base | Clearing a local pointer does not invalidate aliases elsewhere |
| Writable shared alias exists | Restrict section access, mapping access and distribution of section handles | A read-only view cannot prevent writes through another writable view |
| Sensitive data left in live storage | `SecureZeroMemory` while still writable, after all users stop | Copies, registers, logs, dumps and backing-store history are separate concerns |

`VirtualProtect` requires committed memory and returns `BOOL`; on failure capture last error and leave the program in its previous safe state. It affects every page touched by the byte range. Save old protections carefully: the returned old value describes only the first page. Mixed-protection restoration needs tracked ranges, not one value reused everywhere.

Use data-only pages (`PAGE_READWRITE` while building, `PAGE_READONLY` when immutable); do not grant execution to data. W^X is a design constraint, not an automatic consequence of `VirtualAlloc`. DEP, ASLR, CFG and compiler diagnostics address different failure classes and do not fix use-after-free or unchecked lengths. `PAGE_GUARD` is consumed by the first access; do not treat it as a stable read-only policy.

### Lifetimes and Privileges

Normal self-process reserve/commit/protect/release and ordinary heap operations require no elevation. Ownership inside a process is an application convention: another thread with a stale pointer can still access a reused address. Stop and join all users before clearing, decommitting or releasing. Recommit after decommit yields zero-initialized data, while committing an already committed page preserves contents. `MEM_RESET` does not promise zeros.

VADs describe region allocation, not whether a C++ object is live. Heap implementation and diagnostic behavior vary by OS and process configuration. Do not inspect allocator metadata to decide whether a pointer is safe. `IsBadReadPtr`-style probing is not validation. Shared mappings require a synchronization protocol and checked serialized data; avoid embedding absolute pointers in shared data.

### Controlled Faults Are Tests, Not Recovery Policy

The lab's baseline writes a synthetic byte while RW. After `PAGE_READONLY`, a second write should raise `EXCEPTION_ACCESS_VIOLATION`. The SEH filter verifies exception code, write access type (`ExceptionInformation[0] == 1`), and the exact owned address. Other exceptions continue searching. This intentionally narrow fixture is not a recommendation to resume arbitrary application corruption or swallow access violations in production.

## Detection and Defense

Track allocation owner, logical size, protection transitions and shutdown order. Treat unexpected access violations as defects; record a minimal crash report without secret contents. Compiler sanitizers and Application Verifier can improve coverage but are separate optional prerequisites, not evidence supplied here. Executable-memory transitions can occur legitimately in JITs; correlate with application behavior rather than labeling all transitions malicious. Debugger procedures belong to [[WinDbg]].

## Labs

### Environment and Complete Files

Windows 11 x64, already installed VS 2022 MSVC v143 and Windows SDK 10.0.22621+, x64 Native Tools Command Prompt. Standard user. Use **C**, not C++, for this SEH fixture; it has no C++ unwinding objects. Only `protect.c` is needed.

> [!warning] Unverified execution
> The authoring session did not compile or run this lab, and no VM was exercised. The fault, cleanup, and compiler behavior below are expected, not observed. Shared-file ACLs, concurrency stress, and alternative heap implementations remain untested.

```bat
mkdir x1-protect
cd x1-protect
ver
cl /Bv
```

```c
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

static int ExpectedWrite(EXCEPTION_POINTERS* exception, const void* address) {
	EXCEPTION_RECORD* record = exception->ExceptionRecord;
	if (record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
		record->NumberParameters >= 2 &&
		record->ExceptionInformation[0] == 1 &&
		record->ExceptionInformation[1] == (ULONG_PTR)address)
		return EXCEPTION_EXECUTE_HANDLER;
	return EXCEPTION_CONTINUE_SEARCH;
}
static int WriteByte(volatile unsigned char* address) {
	__try {
		*address = 91;
		return 1;
	} __except (ExpectedWrite(GetExceptionInformation(), (const void*)address)) {
		return 0;
	}
}
static int Sized(SIZE_T count, SIZE_T width, SIZE_T* bytes) {
	if (!count || !width || count > SIZE_MAX / width) return 0;
	*bytes = count * width;
	return *bytes <= 1024 * 1024;
}
int main(void) {
	SYSTEM_INFO system;
	SIZE_T bytes = 0;
	DWORD old = 0;
	int passed = Sized(16, 8, &bytes) && bytes == 128;
	passed = !Sized(SIZE_MAX, 8, &bytes) && passed;
	GetSystemInfo(&system);
	unsigned char* region = (unsigned char*)VirtualAlloc(NULL,
		system.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!region) return 1;
	int baseline = WriteByte(region);
	if (!VirtualProtect(region, system.dwPageSize, PAGE_READONLY, &old)) {
		VirtualFree(region, 0, MEM_RELEASE);
		return 2;
	}
	int fixed = WriteByte(region) == 0;
	int readable = region[0] == 91;
	if (!VirtualProtect(region, system.dwPageSize, PAGE_READWRITE, &old)) {
		VirtualFree(region, 0, MEM_RELEASE);
		return 3;
	}
	SecureZeroMemory(region, system.dwPageSize);
	passed = baseline && fixed && readable && region[0] == 0 && passed;
	if (!VirtualFree(region, 0, MEM_RELEASE)) passed = 0;
	region = NULL;
	printf("baseline=%d denied-write=%d retained-read=%d checks=%d\n",
		   baseline, fixed, readable, passed);
	return passed ? 0 : 4;
}
```

### Objectives and Baseline

1. Predict which write succeeds and which is handled, without changing the address.
2. Explain why the valid read remains permitted and why restoration precedes clearing.
3. Confirm an oversized allocation request is rejected before any allocation.

```bat
cl /nologo /W4 /TC /std:c17 protect.c /Fe:protect.exe /link /DYNAMICBASE /NXCOMPAT
if errorlevel 1 exit /b 1
protect.exe
echo Exit=%ERRORLEVEL%
```

### Hints

The faulting write is deliberate and constrained to a single byte. No freed or uncommitted memory is dereferenced. The oversized arithmetic case uses a scalar check, not an enormous allocation.

### Solution and Fixed Retest

The baseline sets byte 91. After protection changes to read-only, the same write faults before changing storage, and the precise filter handles it. Reading 91 still succeeds. Restore RW, securely clear the page, verify zero, then release the original reservation. Expected line: `baseline=1 denied-write=1 retained-read=1 checks=1`, exit zero. Re-running repeats both baseline and fixed paths without configuration changes.

### Verification, Troubleshooting, and Cleanup

- [ ] Observe both write outcomes, retained read and successful cleanup.
- [ ] Explain why the filter is not a general memory-safety mechanism.
- [ ] Record OS/compiler versions and actual results separately from predictions.

Use MSVC on Windows; other compilers may not implement Microsoft SEH syntax. A debugger can report a first-chance exception before the program's handler; that alone is not test failure. A fault at another address is deliberately not swallowed. A policy or allocation failure is a failed prerequisite/result, not permission to change system policy.

```bat
del protect.exe protect.obj
```

The process leaves no persistent objects or data. Remove the source directory when done.

## Related Techniques

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[Windows Heap Exploitation]]
- [[Windows Exploit Mitigations]]
- [[WinDbg]]
- [[Virtual Memory]]

## References

- [VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [Memory protection constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [Exception records](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
- [SecureZeroMemory](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa366877(v=vs.85))
- [HeapFree](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapfree)
