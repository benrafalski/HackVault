---
title: "Virtual Memory"
aliases: []
tags: [windows, x1]
domain: windows
phase: "X1"
type: tech
status: draft
pair: "[[Virtual Memory Security]]"
updated: 2026-11-03
---
# Virtual Memory

> [!abstract] TL;DR
> Reserve is not commit; commit is not permission to execute. Match VirtualAlloc/VirtualFree and mapping APIs correctly; see [[WinDbg]] for debugger commands.

> [!info] Agent scope
> Reserve and commit; VADs; protections; mapped files; heaps; allocation APIs. Region-level memory management only.

## Prerequisites

- C++ pointer arithmetic, checked sizes, resource ownership, and [[Windows Lab Setup]].
- Windows 11 x64; already installed MSVC v143 (VS 2022), Windows SDK 10.0.22621+, x64 Native Tools Command Prompt. Standard user; no special privileges.

## Learn

```text
Teach Windows user-mode virtual memory at expert depth, assuming C++ pointers and
ownership. Scope is VADs, address reservations, commitment and working set,
VirtualAlloc/VirtualFree/VirtualProtect/VirtualQuery, page-size versus allocation
granularity, mapped files and copy-on-write, and HeapAlloc/HeapFree ownership.
Explain precisely why a VirtualQuery region is not a VAD or allocation boundary,
why commit is not residency, and why readable does not mean alive or synchronized.
Work through reserve -> partial commit -> read-only -> decommit -> recommit ->
release, with exact inputs, return conventions, cleanup and predicted states.
Compare private regions, mapped views, image mappings, NT heap and Segment Heap
without undocumented layout dependencies. Include bounded self-process code,
mapping/view lifetime, flush-versus-durability caveats and allocation overflow
checks. Use Microsoft primary docs and distinguish supported contracts from
version-sensitive internals. No address-translation internals, remote memory,
executable payloads, exploitation, private data or debugger commands. Teach here;
do not write notes or change study status. Never invent runtime evidence.
```

## Cheatsheet

### Regions, Backing, and Observations

Reservation claims an address interval so other allocations cannot use it; it does not supply accessible storage. Committing private memory charges the system commit limit and guarantees initially zero contents on first access, but does not mean every byte is resident. The working set measures resident pages associated with a process, not its total virtual size or commit charge. Touching memory can fault normally as backing becomes resident.

A VAD is kernel bookkeeping describing an allocated virtual-address range and its attributes. Its private layout and tree implementation are not application contracts. A heap may suballocate thousands of objects inside a few regions. `VirtualQuery` reports consecutive pages sharing state, type and protection within the relevant allocation; it does not return a VAD tree or enumerate C++ objects. Splitting protections can produce multiple query regions sharing `AllocationBase`.

| State / type | Meaning and valid inference |
| --- | --- |
| `MEM_FREE` | No reservation at query time; other fields including protection/allocation information are not generally meaningful |
| `MEM_RESERVE` | Address owned, not committed; do not dereference; `Protect` is undefined for uncommitted pages |
| `MEM_COMMIT` | Backing committed; access still depends on protection and object lifetime |
| `MEM_PRIVATE` | Private allocation, often from VirtualAlloc or heap backing |
| `MEM_MAPPED` | Data section view, file-backed or paging-file-backed |
| `MEM_IMAGE` | Image section view; not equivalent to a raw PE file buffer |

Copy-on-write makes a modified page private to the writing process, but `VirtualQuery` can continue reporting `MEM_MAPPED` or `MEM_IMAGE`. Region type alone does not establish physical sharing. Queries race with frees/protection changes; the only reliable ownership proof is a lifetime protocol, not a successful probe.

### Exact Allocation Contracts

| API | Inputs, result and release rule |
| --- | --- |
| `GetSystemInfo(&info)` | Obtain `dwPageSize` and `dwAllocationGranularity`; do not assume they are equal |
| `VirtualAlloc(NULL, size, MEM_RESERVE, PAGE_NOACCESS)` | Returns base or `NULL` with last error. Size rounds to pages; a supplied reserve address rounds down to allocation granularity |
| `VirtualAlloc(base, size, MEM_COMMIT, PAGE_READWRITE)` | Supplied range must be reserved; commitment rounds to page boundaries. Recommitting already committed memory does not zero existing data |
| `VirtualProtect(base, size, PAGE_READONLY, &old)` | `BOOL`; entire affected range must be committed and within one reservation. `old` receives the first page's prior protection, not an array |
| `VirtualFree(base, size, MEM_DECOMMIT)` | `BOOL`; removes commitment, retains reservation. A later successful recommit yields zero-initialized memory |
| `VirtualFree(allocationBase, 0, MEM_RELEASE)` | Release the entire ordinary reservation; original base and zero size are required. No partial ordinary release |
| `VirtualQuery(address, &mbi, sizeof mbi)` | Number of bytes written, or zero with last error. `RegionSize` describes the run starting at `BaseAddress`, not necessarily the complete allocation |

Sizes are bytes and use `SIZE_T`. Check multiplication before allocation: reject `count > SIZE_MAX / elementSize`, reject zero when your schema disallows it, and impose an application budget below representational limits. Capture last error only after the documented failure result.

### Heaps and Mappings

`HeapAlloc(heap, HEAP_ZERO_MEMORY, bytes)` returns a pointer or `NULL` by default; it does **not** set last error on allocation failure. `HeapFree` must receive the same heap and original allocation pointer. `GetProcessHeap` is borrowed: never `HeapDestroy` it. A private `HeapCreate` heap is owned and can be destroyed only after all users stop. Heap serialization protects allocator metadata, not concurrent application access to blocks. `HEAP_NO_SERIALIZE` needs external synchronization. NT heap versus Segment Heap and low-fragmentation behavior depend on OS/build/application configuration; don't decode allocator headers or rely on address reuse.

`CreateFileMappingW(file, ..., protection, maxHigh, maxLow, name)` returns an owned section handle or `NULL`; an existing named object can return success plus `ERROR_ALREADY_EXISTS`, so creation arguments may not describe a new object. `MapViewOfFile` returns a view or `NULL`. Offsets must satisfy allocation-granularity alignment; view access must be compatible with section protection and file access. Release a view with `UnmapViewOfFile`, not `VirtualFree`; close the section with `CloseHandle`. Closing the handle does not invalidate existing views. `INVALID_HANDLE_VALUE` as the mapping's file argument selects paging-file backing and requires a nonzero maximum size.

For real file mappings, open the file with appropriate read/write access, keep mapping extent within a valid file size, and serialize against truncation. `FlushViewOfFile` flushes dirty mapped data, not all metadata; `FlushFileBuffers` on the file handle is a separate durability step. Neither is an inter-thread synchronization primitive, and storage/network durability has additional constraints. The lab uses an unnamed paging-file-backed section so it cannot alter a real file.

## Gotchas

- Do not `VirtualProtect` arbitrary heap blocks: unrelated allocations can share their pages.
- Guard protection is a one-shot alarm, not a permanent access-denial policy. `PAGE_NOACCESS` and read-only protections are distinct.
- `MEM_RESET` does not guarantee zeros and is not secure erasure. Decommit is not a substitute for clearing sensitive data before release.
- A free region query is a snapshot; an immediate reuse by another thread is possible. Debugger procedures are only in [[WinDbg]].

## Labs

### Environment and Complete Files

> [!warning] Unverified execution
> No VM, compiler or runtime was exercised in this authoring session. Expected states are documented predictions. VAD visualization, physical residency, file durability and alternate heap implementations are not measured here.

In the developer prompt, create a fresh lab folder. The complete file is `memory.cpp`; no project, data, or packages are needed.

```bat
mkdir x1-memory
cd x1-memory
ver
cl /Bv
```

```cpp
#include <windows.h>
#include <cstdio>

bool State(void* address, DWORD expected, DWORD protection = 0) {
	MEMORY_BASIC_INFORMATION information{};
	if (!VirtualQuery(address, &information, sizeof information)) return false;
	std::printf("state=%lx type=%lx bytes=%zu\n", information.State,
				information.Type, information.RegionSize);
	return information.State == expected &&
		(!protection || information.Protect == protection);
}
int main() {
	SYSTEM_INFO system{};
	GetSystemInfo(&system);
	SIZE_T page = system.dwPageSize;
	std::printf("page=%lu granularity=%lu\n", system.dwPageSize,
				system.dwAllocationGranularity);
	auto* region = static_cast<unsigned char*>(
		VirtualAlloc(nullptr, page * 2, MEM_RESERVE, PAGE_NOACCESS));
	if (!region) return 1;
	bool passed = State(region, MEM_RESERVE);
	if (!VirtualAlloc(region, page, MEM_COMMIT, PAGE_READWRITE)) {
		VirtualFree(region, 0, MEM_RELEASE);
		return 2;
	}
	passed = State(region, MEM_COMMIT, PAGE_READWRITE) && passed;
	passed = State(region + page, MEM_RESERVE) && passed;
	region[0] = 42;
	DWORD old = 0;
	if (!VirtualProtect(region, page, PAGE_READONLY, &old)) passed = false;
	else passed = old == PAGE_READWRITE &&
				  State(region, MEM_COMMIT, PAGE_READONLY) && passed;
	if (!VirtualFree(region, page, MEM_DECOMMIT)) passed = false;
	else {
		passed = State(region, MEM_RESERVE) && passed;
		if (!VirtualAlloc(region, page, MEM_COMMIT, PAGE_READWRITE)) passed = false;
		else passed = region[0] == 0 && passed;
	}
	if (!VirtualFree(region, 0, MEM_RELEASE)) passed = false;
	region = nullptr;
	HANDLE heap = GetProcessHeap();
	void* block = heap ? HeapAlloc(heap, HEAP_ZERO_MEMORY, 32) : nullptr;
	if (!block) return 3;
	passed = static_cast<unsigned char*>(block)[0] == 0 && passed;
	if (!HeapFree(heap, 0, block)) passed = false;
	HANDLE section = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr,
										 PAGE_READWRITE, 0, 4096, nullptr);
	if (!section) return 4;
	auto* writer = static_cast<unsigned char*>(
		MapViewOfFile(section, FILE_MAP_WRITE, 0, 0, 4096));
	auto* reader = static_cast<const unsigned char*>(
		MapViewOfFile(section, FILE_MAP_READ, 0, 0, 4096));
	if (!writer || !reader) passed = false;
	else {
		writer[0] = 73;
		passed = reader[0] == 73 && passed;
	}
	if (writer && !UnmapViewOfFile(writer)) passed = false;
	if (reader && !UnmapViewOfFile(reader)) passed = false;
	if (!CloseHandle(section)) passed = false;
	std::printf("lifecycle, heap and shared-view checks=%d\n", passed);
	return passed ? 0 : 5;
}
```

### Objectives and Steps

1. Predict the state of each of the two pages after partial commit.
2. Explain why the recommitted first byte is zero, while a second `MEM_COMMIT` without decommit would not erase 42.
3. Distinguish the three release families used by this one process.

```bat
cl /nologo /W4 /EHsc /std:c++17 memory.cpp /Fe:memory.exe /link /DYNAMICBASE /NXCOMPAT
if errorlevel 1 exit /b 1
memory.exe
echo Exit=%ERRORLEVEL%
```

### Hints

Protection is independent of commitment. A read-only mapping and writable mapping can alias the same section without allowing writes through the read-only view. This single-threaded lab needs no cross-thread visibility protocol.

### Solution and Expected Results

The state sequence is reserve (`0x2000`), first-page commit (`0x1000`), second-page reserve, first-page read-only commit, then reserve after decommit. The recommitted byte is zero. The zeroed heap block and section alias both pass. Final line should end in `checks=1`, exit zero. Actual addresses, query run sizes and system granularity are observations, not fixed fixture values.

### Verification, Troubleshooting, and Cleanup

- [ ] Observe all state checks and zero exit; identify base, page size and ownership.
- [ ] Explain which data/protection fields are undefined for reserved/free memory.
- [ ] Record versions and deviations; do not claim VMMap or durability validation from this output.

A nonzero exit is failure; inspect the relevant API contract and record its failure result. Commit pressure can make allocation fail even with a large free address range. Do not retry by requesting executable memory or extra privileges. All resources are released on the normal path; process exit also reclaims this disposable process's remaining resources after an error.

```bat
del memory.exe memory.obj
```

No persistent mapping or real file is created. Remove the source directory when finished.

## Related

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[Windows Heap Exploitation]]
- [[Windows Exploit Mitigations]]
- [[WinDbg]]
- [[Virtual Memory Security]]

## References

- [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
- [VirtualFree](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree)
- [VirtualQuery](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery)
- [HeapAlloc](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc)
- [File mapping](https://learn.microsoft.com/en-us/windows/win32/memory/file-mapping)
