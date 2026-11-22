# LoadLibrary

A minimal loader of Windows x64 DLLs (PE32+) into a Linux x86-64 process.

It runs the exports of a DLL directly, in the caller's thread: no Wine, no
separate process, no IPC. It is meant for computational DLLs with a statically
linked CRT (codecs, signal processing, crypto cores) that have to be called
from a Linux program at full speed.

Two C files and a header, no dependencies beyond glibc.

## Why

- **Wine** runs a DLL in its own process: the caller needs a second process, a
  pipe or shared memory to talk to it, and Wine packages on every host.
- **[taviso/loadlibrary](https://github.com/taviso/loadlibrary)** loads 32-bit
  PE only, so it cannot be used in a 64-bit process, and it emulates a large
  part of Win32 for one specific DLL.

This loader takes the opposite, minimal approach: it does what a DLL needs to
be mapped and bound, gives every thread a TEB, and adds Win32 functions only
when a DLL actually calls them, one at a time, through providers. An import
nobody implements is bound to a thunk that reports its name and aborts, so an
unexpected call is never silent.

## What it does

- relocations, imports by name and by ordinal, delayed imports, exports,
  forwards (`OTHER.Function`, `OTHER.#n`), images without relocations at their
  `ImageBase`;
- dependencies loaded from the directory of the importing DLL, shared by
  identity, cycles collected on `FreeLibrary`;
- per-section protections, `PatchLibrary` for a byte pattern found exactly once;
- a TEB and a PEB per thread on `gs:` (stack bounds, last error, TLS slots),
  so `__chkstk` and friends work as on Windows;
- static TLS (`__declspec(thread)`), TLS callbacks, `DllMain` with process and
  thread attach/detach (`AttachLibrary`), the startup of a static MSVC CRT;
- providers: tables of Win32 functions per DLL name, registered by a
  constructor or passed per load, overlaying real DLLs or replacing them;
  `Loader/Kernel32.c` implements the part of KERNEL32 a static CRT and plain
  computational code need (errors, time, critical sections, heap, TLS and FLS,
  code pages, a few stubs);
- error codes for failures, a list of unresolved imports, names for addresses
  inside DLLs (`A.dll+0x1003 (Twice+0x3)`) that are safe in a fault handler;
- messages through a function with the signature of `syslog(3)`;
- observers of loads and unloads, and two of them on top: `FrameBridge.c`
  translates the `.pdata` of DLLs into DWARF CFI for libgcc and libunwind, so
  backtraces of fault handlers pass through DLL frames, epilogues included;
  `SymbolBridge.c` puts each image inside an ELF object of ld.so, so `dladdr`,
  `dlsym`, `dl_iterate_phdr` and gdb see its functions (with FrameBridge the
  object carries the CFI too, and gdb unwinds through DLL frames).

## Where the line is

Everything past that is Windows itself, which is what Wine is for: SEH and
C++ exceptions thrown inside the DLL, the dynamic CRT (`vcruntime140`,
`msvcp140`, `ucrtbase`), files, consoles, the registry, real locales, 32-bit
images and images that are not large address aware. A DLL that needs those
belongs in Wine; the tools below tell on which side a DLL is.

## Quick start

```bash
make check
```

builds the loader, the tools and the example, generates small test DLLs with a
Python script (no Windows toolchain is needed) and runs the tests on them.

Using it in a program:

```c
#include <syslog.h>
#include "LoadLibrary.h"

typedef int (LIBRARY_ABI *Function)(int value1, int value2);

struct Module* image = LoadLibrary("Library.dll", NULL, syslog);
if (image == NULL)
  fprintf(stderr, "%s\n", GetLibraryErrorText(GetLibraryLastError()));

PrepareLibraryThread();         // in every thread that calls into a DLL
AttachLibrary(image);           // only if the DLL needs DllMain and its CRT startup

Function function = (Function)GetProcAddress(image, "Add");
int result = function(2, 3);

FreeLibrary(image);
```

Compile `Loader/LoadLibrary.c` and `Loader/Kernel32.c` into the program and
link the objects directly: `Kernel32.c` registers itself in a constructor and
nothing refers to it, so a static archive would lose it. Functions given to a
DLL and pointers to its exports use `LIBRARY_ABI` (`__attribute__((ms_abi))`).
The full example is `Examples/Call.c`.

## Tools

- `Tools/loadlibrary-check [--attach] library.dll` loads the DLL with the real
  loader and tells why it fails, what stays unresolved (grouped by the side of
  the line), and with `--attach` whether `DllMain` passes.
- `Loader/FrameBridge.c` and `Loader/SymbolBridge.c` are optional: link their
  objects like `Kernel32.o`, and the usual `backtrace()`, `_Unwind_Backtrace`,
  libunwind and `dladdr` of a fault handler go through DLL frames and name
  them.
- `Tools/LibraryCheck.py library.dll [export ...]` walks the call graph from
  the exports you need (with `objdump`) and lists the imports and TEB fields
  they reach, so error paths can be told from normal work.

## Documentation

- [Documentation/Design.md](Documentation/Design.md): how it works, memory
  layout, TEB, TLS, `AttachLibrary`, providers, assessing a new DLL.
- [Documentation/TODO.md](Documentation/TODO.md): known gaps and how to close
  them.

## License

MIT, see [LICENSE](LICENSE).
