# Technical debt and possible work

Everything below is known and deliberate. See `Design.md` for how things work
now and for where the line with Wine is.

## LoadLibrary

### Kernel32.c

- **Freeing TLS and FLS indexes with other threads alive.** `TlsFree` clears
  the slot of the calling thread only, Windows clears it in every thread: an
  index freed and allocated again shows the old value to other threads.
  `FlsFree` calls the callback for the value of the calling thread only,
  Windows does it for every thread: values of other threads leak, and a
  thread exiting during `FlsFree` and a new `FlsAlloc` of the same index may
  pass its old value to the new callback. It matters only when a DLL with its
  own CRT is freed or detached while threads that called it are alive. Fix: a
  list of prepared threads to clear the slot and to collect FLS values in
  `TlsFree`/`FlsFree`, and the callbacks taken under `SlotLock`.

### Beyond the line (decided: Wine, see "Where the line is" in Design.md)

Exceptions, the dynamic CRT, real locales, `KUSER_SHARED_DATA` and images that
are not large address aware are what Wine is for. They stay here as a record
of what a DLL may need and what it would take, not as work to do.

- **Not large address aware** images are refused. It would take `MAP_32BIT`
  for the image and for every allocation a provider hands to it, malloc
  included.
- **Locale and environment.** Code pages are Windows-1252, 437 and UTF-8,
  character types and case are Latin-1, `GetEnvironmentStrings` is empty.
- **SEH and C++ exceptions** inside the DLL abort in `RtlUnwindEx` /
  `RaiseException`. It would take an unwinder over `.pdata`/`.xdata`. This is
  the largest item here, do it only for a DLL that really throws.
- **`KUSER_SHARED_DATA` at `0x7ffe0000`.** Not mapped. Some code reads time
  or CPU features from it. It would take a page mapped there with the time
  fields kept updated, only if a DLL reads it (grep the disassembly for
  `0x7ffe0`).

### Diagnostics

- **Crash stacks stop at DLL frames.** The DLL has `.pdata` but no DWARF.
  `GetLibraryAddressName` already names an address as `module+offset` with
  the nearest export, and is safe in a fault handler. What is left is to call
  it from the fault handler of the host process: the loader cannot install one
  itself without taking over the signals of its host.
