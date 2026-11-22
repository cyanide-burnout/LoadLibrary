#ifndef LOADLIBRARY_H
#define LOADLIBRARY_H

#include <stddef.h>
#include <stdint.h>
#include <syslog.h>

#ifdef __cplusplus
extern "C"
{
#endif

// Minimal loader of PE32+ (x86-64) DLLs into a Linux process, see Documentation/Design.md
// LoadLibrary() never runs code of a DLL, AttachLibrary() does. The loader knows nothing about emulated DLLs:
// they are providers that register themselves (Kernel32.c, LIBRARY_PROVIDER). Nor about debuggers and unwinders:
// they are observers of loads and unloads (FrameBridge.c, SymbolBridge.c, LIBRARY_OBSERVER).
//
// An import MODULE!FUNCTION (by name or by ordinal) is resolved in this order:
//   1. providers given to LoadLibrary() by the caller (inherited by dependencies)
//   2. registered providers of MODULE
//   3. exports of the PE module MODULE: already loaded, or loaded from the directory of the importing image
//      (providers overlay the real DLL: they replace some of its functions, the rest comes from the file)
//   4. a thunk that reports MODULE!FUNCTION and aborts the process
// An entry with function == NULL in 1 or 2 forbids the import explicitly (step 4)
// Providers are looked up by name only, an import by ordinal goes to step 3

#define LIBRARY_ABI  __attribute__((ms_abi))

// Ordinal in place of a name, as MAKEINTRESOURCE does: GetProcAddress(image, LIBRARY_ORDINAL(1))

#define LIBRARY_ORDINAL(number)  ((const char*)(uintptr_t)(uint16_t)(number))

// Same signature as syslog(3), which can be passed as is; priorities are LOG_*

typedef void (*LibraryReport)(int priority, const char* format, ...);

// Copy of a string by malloc() called directly from the module, use it instead of strdup()
// A module dlopen()ed with RTLD_DEEPBIND binds its own malloc()/free() to libc, while strdup() and other functions
// of libc call malloc() through PLT, which resolves to the allocator of the process (jemalloc, for example).
// A string from strdup() released by free() of the module goes to the wrong allocator

char* CopyLibraryString(const char* string);

struct LibraryImport
{
  const char* name;  // Name of function, NULL terminates a table
  void* function;    // Implementation declared with LIBRARY_ABI, NULL forbids the import
};

// Entry of a table for a function with the same name as in Windows: LIBRARY_IMPORT(HeapAlloc)

#define LIBRARY_IMPORT(name)  { #name, (void*)name }

struct LibraryProvider
{
  const char* module;                   // Name of DLL (case-insensitive, "KERNEL32.dll"), NULL matches any (caller's providers only)
  const struct LibraryImport* imports;  // Table of functions, NULL terminates an array of caller's providers
  struct LibraryProvider* next;         // Used by the registry
};

// Registry of providers, safe to call from constructors of shared objects

void RegisterLibraryProvider(struct LibraryProvider* provider);
void UnregisterLibraryProvider(struct LibraryProvider* provider);

// Declares a provider that registers itself when the object is loaded and unregisters when it is unloaded

#define LIBRARY_PROVIDER(identifier, module, imports)                                                              \
  static struct LibraryProvider identifier = { module, imports, NULL };                                            \
  static void __attribute__((constructor)) Register##identifier(void) { RegisterLibraryProvider(&identifier); }    \
  static void __attribute__((destructor)) Unregister##identifier(void) { UnregisterLibraryProvider(&identifier); }

// Lookup in registered providers (step 2), NULL when not found

const struct LibraryImport* FindLibraryImport(const char* module, const char* name);

struct Module
{
  uint8_t* base;                            // Mapped image
  size_t size;                              // SizeOfImage
  uint8_t* thunks;                          // Executable pages of thunks for unresolved imports
  size_t length;                            // Length of thunks mapping
  char* name;                               // File name, imports refer to modules by it
  char* directory;                          // Directory of the file, dependencies are searched there
  uint64_t device;                          // Identity of the file: the same file is one module
  uint64_t inode;                           //
  int flat;                                 // SectionAlignment below the page size: the image is one RWX region
  int count;                                // References: LoadLibrary() calls and dependent modules
  const struct LibraryProvider* providers;  // Caller's providers of the first load, also used for forwards
  LibraryReport report;                     // Report function of the first load
  struct Module** dependencies;             // Modules this one imports from
  size_t number;                            // Count of dependencies
  struct Module* next;                      // Registry of modules
  int internal;                             // References from dependencies of other modules (collector)
  int alive;                                // Reachable from references outside the registry (collector)
  uint64_t serial;                          // Unique number of the load (owner of a TLS index)
  void* entry;                              // AddressOfEntryPoint (DllMain), NULL when there is none
  int attached;                             // DllMain was called with DLL_PROCESS_ATTACH (AttachLibrary)
  int threads;                              // DLL_THREAD_ATTACH/DETACH are wanted (DisableThreadLibraryCalls)
  uint64_t stamp;                           // Serial of the attachment, threads notified before it get THREAD_ATTACH
  int slot;                                 // Static TLS index, -1 when the image has no TLS
  uint8_t* data;                            // TLS template
  size_t initial;                           // Length of the template (initialized data)
  size_t zero;                              // SizeOfZeroFill
  uint64_t* callbacks;                      // TLS callbacks, NULL terminated, NULL when none
  size_t unresolved;                        // Imports bound to thunks (step 4)
  int published;                            // Observers got LIBRARY_EVENT_LOADED
  struct
  {
    const uint8_t* data;                    // The PE file as read, during LIBRARY_EVENT_MAPPING only
    size_t length;                          //
  } file;
  struct LibraryObserver* mapper;           // Observer that provided the memory of the image, NULL for mmap()
};

// Observers of modules, a chain in the order of registration, as la_objopen()/la_objclose() of rtld-audit:
//   LIBRARY_EVENT_MAPPING    before the image is mapped (not for images with stripped relocations, they need their
//                            ImageBase): image->file and image->size are known, an observer may provide zeroed memory
//                            of image->size bytes, page aligned and writable, in image->base; the first one does, the
//                            rest see image->base set; otherwise the loader maps it
//   LIBRARY_EVENT_LOADED     the module is ready (relocated, bound, protected, before LoadLibrary() returns it, for
//                            every dependency too)
//   LIBRARY_EVENT_UNLOADING  before the module goes away (FreeLibrary() and the collector, cycles included)
//   LIBRARY_EVENT_UNMAPPING  to the observer that provided the memory only, when it is to be released (after
//                            LIBRARY_EVENT_UNLOADING, or after a failed load)
// A failed load is not published (no LOADED and UNLOADING). Observers are called with the lock of the loader held and
// must not call LoadLibrary() or FreeLibrary(). Registration replays LIBRARY_EVENT_LOADED for modules already loaded,
// unregistration LIBRARY_EVENT_UNLOADING; an observer that provided memory is unregistered after its images are freed

#define LIBRARY_EVENT_MAPPING    0
#define LIBRARY_EVENT_LOADED     1
#define LIBRARY_EVENT_UNLOADING  2
#define LIBRARY_EVENT_UNMAPPING  3

typedef void (*LibraryObserverFunction)(int event, struct Module* image);

struct LibraryObserver
{
  struct LibraryObserver* next;         // Next in the chain
  LibraryObserverFunction function;
};

void RegisterLibraryObserver(struct LibraryObserver* observer);
void UnregisterLibraryObserver(struct LibraryObserver* observer);

// Declares an observer that registers itself when the object is loaded and unregisters when it is unloaded

#define LIBRARY_OBSERVER(identifier, function)                                                                     \
  static struct LibraryObserver identifier = { NULL, function };                                                   \
  static void __attribute__((constructor)) Register##identifier(void) { RegisterLibraryObserver(&identifier); }    \
  static void __attribute__((destructor)) Unregister##identifier(void) { UnregisterLibraryObserver(&identifier); }

// providers may be NULL, otherwise an array terminated by an entry with imports == NULL. It has to stay valid while
// the module is loaded (forwards are resolved later). A file that is already loaded is shared: its counter is
// increased, and providers of the call are not applied (reported when they differ)
// The image is returned with final protections of sections

struct Module* LoadLibrary(const char* path, const struct LibraryProvider* providers, LibraryReport report);
void FreeLibrary(struct Module* image);

// name may be LIBRARY_ORDINAL(n). Forwarded exports ("OTHER.Function", "OTHER.#n") are resolved in the same
// order as imports

void* GetProcAddress(struct Module* image, const char* name);

// Thread Environment Block for the calling thread: Windows code reaches it through gs:. Call it in every thread
// before it calls into a DLL (cheap after the first call). The TEB has the real stack of the thread
// (StackBase, StackLimit), so __chkstk of MSVC probes the stack and catches an overflow at the guard page,
// Self, ClientId, the static TLS of loaded modules and a pointer to the PEB. glibc on x86-64 does not use GS.
// It also brings the thread up to date: TLS blocks of new modules, DLL_THREAD_ATTACH of new attachments.
// Returns 0 on success

int PrepareLibraryThread(void);

// Runs the initialization of the image in the calling thread: dependencies first, then TLS callbacks and DllMain
// with DLL_PROCESS_ATTACH. LoadLibrary() never runs code of a DLL, a DLL that needs its CRT initialized is
// attached explicitly. Prepared threads get DLL_THREAD_ATTACH (unless DisableThreadLibraryCalls) and
// DLL_THREAD_DETACH at their exit, FreeLibrary() sends DLL_PROCESS_DETACH. Returns 0 on success, -1 when DllMain
// returns FALSE (the image stays loaded and not attached)

int AttachLibrary(struct Module* image);

// For providers: a function called at the exit of every prepared thread, after DLL_THREAD_DETACH and before its
// TLS blocks and TEB are freed (DLL code still sees its TEB). Up to 8 functions, returns 0 on success

typedef void (*LibraryThreadExit)(void);

int RegisterLibraryThreadExit(LibraryThreadExit function);

// For providers: DisableThreadLibraryCalls(), GetModuleHandle(), GetModuleFileName(), GetProcAddress() of Windows

int SetLibraryThreadCalls(const void* base, int enabled);
struct Module* GetLibraryByAddress(const void* address);
struct Module* GetLibraryByName(const char* name);

// For providers: blocks reached by Windows code without calling the system, NULL TEB when the thread is not prepared

#define LIBRARY_TEB_LAST_ERROR      0x0068
#define LIBRARY_TEB_TLS_SLOTS       0x1480
#define LIBRARY_TEB_TLS_SLOT_COUNT  64
#define LIBRARY_PEB_PROCESS_HEAP    0x0030

uint8_t* GetLibraryTEB(void);
uint8_t* GetLibraryPEB(void);

// Replace exactly one occurrence of the pattern inside executable sections, returns count of found occurrences
// Protection of the page is lifted for the write and restored

int PatchLibrary(struct Module* image, const uint8_t* pattern, const uint8_t* replacement, size_t length);

// Why the last LoadLibrary() or AttachLibrary() of the calling thread failed, and a text for it
// A module may use it to decide what to do, for example to fall back to Wine for LIBRARY_ERROR_ADDRESS_AWARE

#define LIBRARY_ERROR_NONE           0
#define LIBRARY_ERROR_OPEN           1   // The file cannot be opened or read
#define LIBRARY_ERROR_FORMAT         2   // Not a PE32+ x86-64 image
#define LIBRARY_ERROR_ADDRESS_AWARE  3   // Not large address aware
#define LIBRARY_ERROR_BROKEN         4   // Broken headers, sections, relocations, imports or TLS
#define LIBRARY_ERROR_UNSUPPORTED    5   // A feature the loader does not support
#define LIBRARY_ERROR_IMAGE_BASE     6   // Stripped relocations and the ImageBase is taken
#define LIBRARY_ERROR_TLS_INDEXES    7   // No free TLS index
#define LIBRARY_ERROR_ENTRY          8   // DllMain returned FALSE (AttachLibrary)
#define LIBRARY_ERROR_SYSTEM         9   // The system refused memory or a thread

int GetLibraryLastError(void);
const char* GetLibraryErrorText(int error);

// Imports of the image bound to the aborting thunk: missing in providers and dependencies, or forbidden
// name may be an ordinal (below 0x10000). Returns their count, callback may be NULL

typedef void (*LibraryImportCallback)(const char* module, const char* name, void* context);

size_t GetLibraryUnresolvedImports(struct Module* image, LibraryImportCallback callback, void* context);

// Name of an address for fault reports: "A.dll+0x1003 (Twice+0x3)", "A.dll+0x2000", "A.dll import thunk"
// Returns 0 when the address belongs to a loaded image or to its thunks, -1 otherwise

int GetLibraryAddressName(const void* address, char* buffer, size_t length);

#ifdef __cplusplus
}
#endif

#endif
