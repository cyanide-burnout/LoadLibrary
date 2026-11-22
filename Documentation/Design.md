# LoadLibrary: design

A minimal loader of Windows x64 DLLs (PE32+) into a Linux x86-64 process.
It runs a DLL's computational exports directly, in the caller's thread, with
no Wine, no separate process and no IPC.

Files:

| File | What |
|---|---|
| `Loader/LoadLibrary.h` | API: `LoadLibrary`, `GetProcAddress` (also by `LIBRARY_ORDINAL`), `FreeLibrary`, `PatchLibrary`, `PrepareLibraryThread`, `AttachLibrary`, `GetLibraryLastError`, `GetLibraryUnresolvedImports`, `GetLibraryAddressName`, providers (`LIBRARY_PROVIDER`, `LIBRARY_IMPORT`, `RegisterLibraryProvider`, `FindLibraryImport`) |
| `Loader/LoadLibrary.c` | Loader: mapping, relocations, imports, exports, protections, TEB, TLS, registries of providers and modules |
| `Loader/Kernel32.c` | KERNEL32.dll functions on top of Linux, the provider registers itself (no header: nothing refers to it) |
| `Tests/Kernel32Test.c` | Calls the provider's functions through ms_abi pointers |
| `Tests/LoadLibraryTest.py`, `Tests/LoadLibraryTest.c` | Generator of small test DLLs (no Windows toolchain needed) and the test of the loader on them |
| `Tools/LibraryCheck.c`, `Tools/LibraryCheck.py` | `loadlibrary-check` (does the DLL load, what is unresolved, does `DllMain` pass) and the static check of what the needed exports reach |
| `Examples/Call.c` | The smallest use: load a DLL, call an export |
| `Documentation/TODO.md` | Known gaps and how to close them |

## Why not Wine, and why not taviso/loadlibrary

Wine runs a DLL in its own process, so the caller needs a separate process,
a pipe or shared memory to talk to it, and Wine packages on every host.

[taviso/loadlibrary](https://github.com/taviso/loadlibrary) loads only 32-bit
PE (i386, `IMAGE_NT_OPTIONAL_HDR32_MAGIC`, built with `-m32`), so it cannot be
used inside a 64-bit process. It also takes the opposite approach: it
*emulates* Windows with about 50 files of Win32 implementations (heap, files,
threads, SEH, TLS, registry...) and a TEB on `%fs`, because it was made for
mpengine.

This loader takes the minimal approach. It proves that the exports we call do
not need an environment, and closes every remaining gap explicitly: a patch, a
refusal, or a thunk that aborts with the name of the import. Environment is
added only when a DLL actually needs it, one function at a time, through
providers. The loader itself knows nothing about any emulated DLL.

## Where the line is, and when to use Wine

The loader covers what is cheap to do right: computational DLLs with a
statically linked CRT, their relocations, imports, dependencies, static TLS,
`DllMain` and the startup of the CRT. Everything past that is Windows itself,
which is what Wine exists for:

- exceptions: SEH, `__try`/`__except`, C++ `throw` (an unwinder over `.pdata`,
  `RaiseException`, translation of Linux signals into Windows exceptions);
- the dynamic CRT: `vcruntime140.dll`, `msvcp140.dll` and `ucrtbase.dll`, which
  import hundreds of functions of NTDLL and KERNEL32;
- files, consoles, the registry, real locales, `KUSER_SHARED_DATA`, 32-bit
  pointers of images that are not large address aware.

Implementing that piece by piece would grow into a second Wine. So there are
two steps: a DLL inside the line runs in the process through this loader; a
DLL outside it runs in a separate process under Wine, behind a pipe or shared
memory, as before.

To see on which side a DLL is, run the tools of Assessing a new DLL below:

- imports of `vcruntime*`, `msvcp*`, `ucrtbase` or `api-ms-win-crt-*`: the
  dynamic CRT, Wine;
- `RaiseException`, `RtlUnwindEx` or `_CxxThrowException` reachable from the
  exports in normal work (not only from `__report_gsfailure`): exceptions,
  Wine;
- file, registry or console functions reachable from the exports: Wine, unless
  a few of them are worth a provider;
- only computation, the heap, synchronization, time and the startup of a
  static CRT: this loader.

## How it works

1. **Identity.** A file that is already loaded (the same device and inode) is
   shared: its counter grows, and the providers of this call are not applied
   (a warning if they differ). A different file with the name of a loaded
   module is loaded, with a warning: imports by that name keep resolving to
   the first one, as in Windows.
2. **Validation.** `MZ`, `PE\0\0`, machine `0x8664`, optional header magic
   `0x20b` (PE32+), `IMAGE_FILE_LARGE_ADDRESS_AWARE` (see Memory layout).
3. **Mapping.** An anonymous RW mapping of `SizeOfImage`, anywhere, or exactly
   at `ImageBase` (`MAP_FIXED_NOREPLACE`) for an image with stripped
   relocations; a taken `ImageBase` is a failure. Headers and every section are
   copied to their RVAs, and the BSS tail stays zero. Every RVA read from the
   image is bounds-checked (`GetAddress`, `GetString`).
4. **Relocations.** `IMAGE_REL_BASED_DIR64` gets the delta added. `ABSOLUTE`
   is skipped. Any other type is refused. An empty `.reloc` is fine: such a
   DLL has no absolute pointers.
5. **Registration.** The module is put into the registry of modules before
   its imports are bound, so a dependency that imports back from it (a cycle)
   finds it.
6. **Imports.** Regular and delayed imports are bound the same way, at load
   time. For delayed ones the IAT gets final addresses and the module handle
   slot is filled, so `__delayLoadHelper2` of the DLL is never called (the old
   VA format of delayed imports is refused). Every import `MODULE!Function`,
   by name or by ordinal, is resolved in this order:
   1. providers given to `LoadLibrary` by the caller (inherited by the
      dependencies it loads);
   2. registered providers of `MODULE`;
   3. exports of the real PE module `MODULE`. It is shared if it is already
      loaded, or loaded from the directory of the importing image (the name as
      is, then in lower case). Providers **overlay** the real DLL: they
      replace some of its functions, and the rest comes from the file. A DLL
      that exists only as an emulation (`KERNEL32.dll`) is simply not on
      disk, so its missing functions go to step 4;
   4. a 48-byte thunk `mov rcx, <name>; mov rdx, <module>; mov r8, <image>;
      jmp [rip]; <HandleUnresolvedImport>`. Calling it reports
      `PE image A.dll called unsupported import B.dll!Nope, aborting`
      (`B.dll!#99` for an ordinal) through the report of the image, and
      aborts.

   An entry with `function == NULL` in step 1 or 2 forbids the import (step
   4), even if the real DLL has the function. Providers know names only, so
   an import by ordinal goes straight to step 3. A missing dependency without
   a provider is reported as a warning, and only its functions abort, when
   called.

   An unexpected call is therefore never silent and never undefined.
   Messages go through `LibraryReport`, which has the signature of
   `syslog(3)`: `syslog` itself can be passed, or any function like it.
7. **Protections.** Headers get R, and each section gets its own R/W/X from
   its characteristics. This happens inside `LoadLibrary`, because
   dependencies have no caller that could do it. An image with SectionAlignment
   below the page size has sections sharing pages, so it is one RWX region.
8. **Patches.** `PatchLibrary(pattern, replacement)` replaces a byte pattern
   in executable sections only if it occurs **exactly once**. It lifts the
   protection of the page for the write and then restores it. On any other
   count it returns that count, and the caller refuses the DLL as an unknown
   build.
9. **Exports.** `GetProcAddress` looks up by name, or by ordinal with
   `LIBRARY_ORDINAL(n)` (as `MAKEINTRESOURCE` in Windows). A forwarded export
   `OTHER.Function` or `OTHER.#n` is resolved like an import of `OTHER.dll`
   with the providers of the forwarding module's first load. The forwarding
   module owns the reference. A loop of forwards ends with NULL.
10. **Unloading.** `FreeLibrary` decreases the counter and collects the
   registry. The counter of a module is the sum of outside references
   (`LoadLibrary` calls) and references from dependency lists of other
   modules. A module is alive when it has outside references or an alive
   module depends on it; the rest goes away at once, cycles included (for
   example D ↔ E made by a loop of forwards).

`LoadLibrary` never runs code of the DLL: no `DllMain`, no CRT startup, no
TLS callbacks. A DLL that needs them is initialized explicitly with
`AttachLibrary` (below).

### Memory layout

A DLL does not need the address space of a Windows process. Only an image
without relocations has to sit at its `ImageBase`, and that is the usual case
for `.exe` files (linked with `/FIXED`, `.reloc` stripped). A DLL is built to
be loaded anywhere: it has `.reloc`, and normally `DYNAMIC_BASE` (ASLR). The
loader takes any address from `mmap` and adds the delta to every absolute
pointer listed in `.reloc`. x64 code itself is RIP-relative, so only pointers
in data (vtables, dispatch tables, strings in tables) are fixed up. The only
requirement is that the whole image is one contiguous mapping, which it is.

What can still tie a DLL to Windows addresses:

- **Stripped relocations** (a DLL linked `/FIXED`): it is mapped at its
  `ImageBase` with `MAP_FIXED_NOREPLACE`. `0x180000000` is usually free in a
  Linux process; when it is taken, the load fails with a report.
- **Not large address aware:** the code may keep pointers in 32 bits. Linux
  mappings and malloc are above 4 GB, so such an image is refused. Supporting
  it would need `MAP_32BIT` for the image and every allocation it gets.
- **`KUSER_SHARED_DATA` at `0x7ffe0000`:** some code reads time or CPU
  features from it without calling the system (taviso/loadlibrary maps it).
  To check, grep the disassembly for `0x7ffe0`.
- **TEB through `gs:`** (below).

### Calling convention

Windows x64 code uses the Microsoft ABI. GCC and Clang support it with
`__attribute__((ms_abi))`, provided as `LIBRARY_ABI`. Use it on both sides:

- typedefs of exports you call: `typedef void (LIBRARY_ABI *Function)(void*);`
- implementations you give to the DLL: `static void* LIBRARY_ABI HeapAlloc(...)`

The compiler then handles shadow space, argument registers and the callee-saved
xmm6–xmm15 itself. No assembler glue is needed.

### TEB and segment registers

Windows code reaches the TEB through `gs:`. A Linux thread has no TEB (the GS
base is 0), so any such access is SIGSEGV. The typical case is MSVC
`__chkstk`, which reads `StackLimit` from `gs:[0x10]` in functions with more
than a page of locals:

```
65 4c 8b 1c 25 10 00 00 00    mov r11, gs:[0x10]
```

`PrepareLibraryThread()` gives the calling thread a TEB and points GS at it
with `arch_prctl(ARCH_SET_GS)`. glibc on x86-64 does not use GS. The TEB has
the real stack of the thread from `pthread_getattr_np` (StackBase at 0x08,
StackLimit at 0x10), Self (0x30), ClientId (0x40, 0x48), the array of static
TLS blocks (`ThreadLocalStoragePointer`, 0x58), the PEB (0x60),
`LastErrorValue` (0x68, kept there by `GetLastError`/`SetLastError` of
`Kernel32.c`) and the slots of `TlsAlloc` (0x1480). The PEB has
`BeingDebugged` = 0, `ProcessHeap` (0x30, set by `Kernel32.c`), the number of
processors and the version of Windows 10 (10.0.19045). The rest is zero. With it `__chkstk` probes the stack page
by page as in Windows, and a frame larger than the stack stops at the guard
page instead of writing past it. The TEB is freed with the thread.

The loader cannot hook threads it does not know, so a module calls
`PrepareLibraryThread()` in every thread before calling into a DLL. It costs
one check of a thread-local variable after the first call, so a module can
call it in each of its entry points.

`PatchLibrary` stays for code that a TEB cannot satisfy.

### Static TLS

A TLS directory (`__declspec(thread)`, C++ `thread_local`) gets one of 128
indexes, written to `AddressOfIndex` of the image. Every prepared thread has
its own block of each such module: a copy of the template with the zero fill
after it, in the array at `gs:[0x58]`. A thread prepared before the module
was loaded gets the block on its next `PrepareLibraryThread()`: every change
of the environment bumps a generation, and a thread whose generation differs
brings itself up to date (one comparison otherwise). Blocks of a freed module
are released by each thread on its next synchronization or at its exit.

### Initialization: AttachLibrary

`AttachLibrary(image)` runs the initialization of the image in the calling
thread, as Windows does on a load: dependencies first, then the TLS callbacks
and `DllMain` with `DLL_PROCESS_ATTACH` (TLS callbacks before `DllMain` on
attach, after it on detach). Afterwards:

- a thread gets `DLL_THREAD_ATTACH` on its next `PrepareLibraryThread()` and
  `DLL_THREAD_DETACH` at its exit; `DisableThreadLibraryCalls()` silences
  `DllMain` for threads, TLS callbacks still run;
- `FreeLibrary` sends `DLL_PROCESS_DETACH` when the module goes away, in the
  reverse order of attachment;
- `DllMain` returning FALSE is reported, the image stays loaded and not
  attached.

The startup code of a statically linked MSVC CRT works on the functions of
`Kernel32.c` below: checked on a real DLL, its `DllMain` returns TRUE, and the
exports compute the same results after it as before it, also in a new thread.

## What DLLs it can load

**Works:** x64 DLLs whose exports only compute: codecs, signal processing,
crypto cores, where the caller allocates the context and the export works on it.

**Does not work yet, and how to fix:**

| Need of the DLL | Symptom | Fix |
|---|---|---|
| Calls a Win32 import (heap, files, time...) | abort with the import name | Add the function to a table (below) |
| Needs `DllMain` / CRT init (C++ static constructors, tables built at startup, CRT heap) | Wrong results or a crash in CRT code | `AttachLibrary`, and the imports its startup asks for |
| `gs:` access in a thread without `PrepareLibraryThread()` | SIGSEGV on an address < 0x2000 | Call it in that thread |
| Fields of the TEB or PEB beyond the ones above | Wrong values (zero) | Fill them in `PrepareLibraryThread` |
| Locale beyond Latin-1, the environment of the process | Characters above 0xff have no type, `GetEnvironmentStrings` is empty | Extend `Kernel32.c` |
| SEH or C++ exceptions thrown inside the DLL | abort in `RtlUnwindEx` / `RaiseException` | An unwinder over `.pdata`, which is a big job |
| 32-bit DLL | Refused at load | Not possible in a 64-bit process |

Backtraces of crashes stop at DLL frames: the DLL has `.pdata` but no DWARF.
`GetLibraryAddressName(address, buffer, length)` names such an address as
`A.dll+0x1003 (Twice+0x3)` (the nearest export), or `A.dll import thunk`. It
does not allocate and only tries the lock, so a fault handler may call it.

## Assessing a new DLL

Two tools in `Tools/` answer whether a DLL fits, and why not. `make` builds them.

**`loadlibrary-check [--attach] library.dll`** loads the DLL with the real
loader and the registered providers, so its verdict about loading is what a
module gets:

- a failure with its reason (the code of `GetLibraryLastError()`: not PE32+
  x86-64, not large address aware, broken image, ImageBase taken...);
- `DllMain`, static TLS, dependencies;
- unresolved imports grouped: dynamic CRT and Windows subsystems (beyond the
  line, Wine), exceptions, files and consoles (beyond the line unless only
  error paths need them), and the rest (candidates for a provider);
- with `--attach`, `DllMain` runs in a child process (`AttachLibrary`): it
  passes, returns FALSE, or aborts on an unresolved import named in the
  output. The exit status is 1 when the DLL does not load or `DllMain`
  does not pass, so scripts can use it.

**`LibraryCheck.py library.dll [export ...]`** tells what the exports you
need actually reach. It parses the PE, disassembles it with `objdump` (binutils
or LLVM) and walks the call graph from the exports over direct calls:

- imports reached through the IAT: implemented by `Kernel32.c`, exported by a
  DLL next to this one, beyond the line, or missing;
- accesses to the TEB through `gs:` at fixed offsets: filled by
  `PrepareLibraryThread` or not;
- for each reached import, the function that calls it, so an error path
  (`__report_gsfailure`, a fatal message of the runtime) can be told from
  normal work.

Indirect calls through registers and tables of pointers are not followed, so
the result is a lower bound. Check by hand that function pointers in `.data`
are static (initialized in the file and fixed by relocations), not written by
the startup code.

A module can make the same decision at run time: `LoadLibrary` returns NULL
with `GetLibraryLastError()`, `GetLibraryUnresolvedImports()` lists what went
to the aborting thunks, and a module may fall back to Wine for what is beyond
the line.

## Providers: extending the imports

Imports are resolved on two levels: the DLL name selects providers, and the
function name selects an entry of a provider's table. A provider is plain
data:

```c
struct LibraryImport   { const char* name; void* function; };
struct LibraryProvider { const char* module; const struct LibraryImport* imports; struct LibraryProvider* next; };
```

**Registered providers** emulate a DLL for every image. A new one is a new
file, and nothing else is edited:

```c
static void* LIBRARY_ABI HeapAlloc(void* heap, uint32_t flags, size_t size) { ... }

static const struct LibraryImport Kernel32Imports[] =
{
  LIBRARY_IMPORT(HeapAlloc),        // { "HeapAlloc", (void*)HeapAlloc }
  { "HeapSize", NULL },             // forbidden explicitly
  { NULL, NULL }
};

LIBRARY_PROVIDER(Kernel32Provider, "KERNEL32.dll", Kernel32Imports)
```

`LIBRARY_PROVIDER` makes a constructor that calls `RegisterLibraryProvider`
when the object (or a separate `.so` with providers) is loaded, and a
destructor that unregisters it. Providers can also be registered and
unregistered at run time with `RegisterLibraryProvider` and
`UnregisterLibraryProvider`. Several providers may serve one DLL, and the one
registered last is checked first. A provider needs no header and exports
neither its table nor its functions: it is found through the registry
(`FindLibraryImport` in a test).

**Caller's providers** are passed to `LoadLibrary` as an array terminated by
`imports == NULL`. They apply to one load and to the dependencies it loads,
are checked before registered ones, and may use `module == NULL` to match
any DLL:

```c
static const struct LibraryImport Imports[] = { { "HeapAlloc", (void*)MyAlloc }, { NULL, NULL } };
static const struct LibraryImport Forbidden[] = { { "CreateFileA", NULL }, { NULL, NULL } };

static const struct LibraryProvider Providers[] =
{
  { "KERNEL32.dll", Imports,   NULL },  // overrides the registered provider
  { NULL,           Forbidden, NULL },  // forbidden in any DLL
  { NULL,           NULL,      NULL }
};

image = LoadLibrary(path, Providers, report);
```

Module names are compared case-insensitively.

**Real DLLs** need no provider. If `A.dll` imports from `B.dll`, the loader
takes `B.dll` from the directory of `A.dll` (or the one already loaded) and
binds A's imports to B's real exports. B's own imports may come from
providers, so a chain "A uses B, B uses emulated KERNEL32" works. A module is
shared by file name: a later `LoadLibrary("B.dll")` returns the same image
with its counter increased, and a module loaded first is used by the ones
loaded after it.

A provider for a real DLL's name is an **overlay**. It replaces the functions
it lists for every importer, and the other functions still come from the
file. `{ "Function", NULL }` takes a function away even though the file has
it.

Rules for implementations:

- Always `LIBRARY_ABI`. Win32 types: `BOOL` = `int32_t`, `DWORD` = `uint32_t`,
  `SIZE_T` = `size_t`, `HANDLE` = `void*`, `LONG` = `int32_t` (32-bit on
  Windows, unlike Linux `long`).
- Keep Windows semantics, not just the signature: critical sections are
  recursive, `HeapSize` returns the requested size (a 16-byte header keeps
  it), `HeapReAlloc` with `HEAP_ZERO_MEMORY` zeroes exactly the new tail,
  `Sleep(0)` yields. If the semantics cannot be kept exactly, do not add the
  function, and let the call abort.
- Implementations run in the caller's thread, inside the host process: no blocking
  without a reason, no global state without locking.
- Add a check for each new function to the test of its provider (`Kernel32Test.c`).

Implemented now in `Kernel32.c`:

- errors and identifiers: `GetLastError`, `SetLastError` (in the TEB),
  `GetCurrentThreadId`, `GetCurrentProcessId`, `GetCurrentProcess`,
  `IsDebuggerPresent`;
- time: `GetTickCount`, `QueryPerformanceCounter`, `QueryPerformanceFrequency`,
  `GetSystemTimeAsFileTime`, `Sleep`;
- synchronization: `InitializeCriticalSection`,
  `InitializeCriticalSectionAndSpinCount`, `EnterCriticalSection`,
  `LeaveCriticalSection`, `DeleteCriticalSection` (`pthread_mutex_t` fits into
  the 40-byte `CRITICAL_SECTION`);
- heap: `GetProcessHeap`, `HeapCreate`, `HeapDestroy`, `HeapSetInformation`,
  `HeapAlloc`, `HeapFree`, `HeapReAlloc`, `HeapSize` (one heap on malloc);
- thread storage: `TlsAlloc`, `TlsGetValue`, `TlsSetValue`, `TlsFree` (slots
  of the TEB), `FlsAlloc`, `FlsGetValue`, `FlsSetValue`, `FlsFree` (callbacks
  at the exit of a prepared thread and in `FlsFree`);
- modules: `GetModuleHandleA`, `GetModuleHandleW`, `GetProcAddress` (emulated
  KERNEL32.dll and loaded images), `GetModuleFileNameA`,
  `DisableThreadLibraryCalls`;
- startup of the CRT: `GetCommandLineA`, `GetStartupInfoA`,
  `GetEnvironmentStrings`, `GetEnvironmentStringsW`, `FreeEnvironmentStringsA`,
  `FreeEnvironmentStringsW`, `EncodePointer`, `DecodePointer`,
  `SetUnhandledExceptionFilter`, `UnhandledExceptionFilter`, `ExitProcess`
  and `TerminateProcess` (both report and abort);
- standard streams: `GetStdHandle`, `GetFileType`, `SetHandleCount`,
  `WriteFile`;
- code pages and locale (Windows-1252, 437, UTF-8, Latin-1 types and case):
  `GetACP`, `GetOEMCP`, `GetThreadLocale`, `IsValidCodePage`, `GetCPInfo`,
  `WideCharToMultiByte`, `MultiByteToWideChar`, `GetStringTypeW`,
  `GetStringTypeA`, `LCMapStringW`, `LCMapStringA`, `GetLocaleInfoA`.

## Concurrency

One recursive mutex guards both registries. `LoadLibrary`, `FreeLibrary`,
`GetProcAddress` (forwards may load modules) and the registration functions
take it, and loading a dependency re-enters it. Calls into DLL code do not
take it: they are as thread-safe as the DLL is.

## Allocators

When the host process is built with another allocator (jemalloc, tcmalloc)
and loads the module with `RTLD_DEEPBIND`, the module's own calls to
`malloc`/`free` bind to glibc. But functions inside libc that allocate
(`strdup`, `asprintf`, `realpath(path, NULL)`, `getline`...) call `malloc`
through PLT, which resolves in the global scope to the allocator of the
process. A string from `strdup` freed by the module's `free` goes to the wrong
allocator, and glibc aborts with `free(): invalid pointer`.

Rules: in modules use `CopyLibraryString` instead of `strdup`, and never free
memory that libc allocated internally. A test program of a module should link
the same allocator as the host process, otherwise it cannot see this.

## Verification

A new DLL or a change to the loader is verified against Wine: a small winelib
program loads the same DLL with `LoadLibraryA`/`GetProcAddress`, gets the same
input, and its output is compared with `cmp`. The results must be bit-exact, which
holds when the code, the DLL and the CPU are the same. Concurrency is checked
by running N threads over the same input and comparing their outputs.

The loader itself is tested on generated DLLs (`LoadLibraryTest.py`):

- `A.dll` → `B.dll` dependency, a forward `B.Mul` → `C.Mul`;
- `KERNEL32` through the registered provider, a DIR64 relocation;
- B shared with A and its counter;
- an unresolved import aborts with its name;
- caller's providers override the registered one and are inherited by B;
- an explicitly forbidden import;
- a provider registered at run time overlays B (Add from it, Mul from the
  file), with B loaded before or by A, and is then unregistered;
- a provider forbids a function the real B has;
- repeated lookups of a forward keep one reference, and a loop of forwards
  (D ↔ E) ends with NULL;
- imports by ordinal (existing and missing, with `B.dll!#99` in the report),
  `GetProcAddress` by ordinal, a forward by ordinal `C.#1`;
- a delayed import bound at load, with the module handle slot filled;
- two images with stripped relocations and the same `ImageBase`: the first
  lands there, the second fails while the first is loaded and lands after it
  is freed;
- SectionAlignment 0x200: one RWX region, `PatchLibrary` still works;
- identity by file: a copy of B in another directory is another module (with
  a warning), the same file is shared; providers of a second load are
  reported and not applied;
- `GetLibraryAddressName` for an export, a thunk and a foreign address;
- the cycle D ↔ E goes away with the last outside reference;
- TEB: `gs:` without it is SIGSEGV; with it Self, StackLimit and the thread
  id are right, each thread has its own TEB; the `__chkstk` of MSVC byte for
  byte probes a 20 KB frame, and a 4 MB frame in a thread with a 256 KB stack
  stops at the guard page with SIGSEGV;
- `LastErrorValue`, a slot of `TlsAlloc` and the PEB read by code directly;
- static TLS: the template in a new block, a block of its own per thread, a
  thread prepared before the load gets its block, no code runs without
  `AttachLibrary`;
- `AttachLibrary` of W attaches U first (TLS callback, then `DllMain`), once;
  threads get `DLL_THREAD_ATTACH`/`DETACH`, `DisableThreadLibraryCalls`
  silences `DllMain` but not TLS callbacks; `FreeLibrary` detaches W, then U
  (`DllMain` before its TLS callback); `DllMain` returning FALSE leaves the
  image not attached;
- non-PE and missing files.
