#define _GNU_SOURCE

#include "LoadLibrary.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#ifdef __linux__
#include <asm/prctl.h>
#endif

#ifndef ARCH_SET_GS
#define ARCH_SET_GS  0x1001
#endif

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE  0x100000
#endif

#define IMAGE_FILE_MACHINE_AMD64          0x8664
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC     0x020b
#define IMAGE_FILE_RELOCS_STRIPPED        0x0001
#define IMAGE_FILE_LARGE_ADDRESS_AWARE    0x0020

#define IMAGE_DIRECTORY_ENTRY_EXPORT      0
#define IMAGE_DIRECTORY_ENTRY_IMPORT      1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC   5
#define IMAGE_DIRECTORY_ENTRY_TLS         9
#define IMAGE_DIRECTORY_ENTRY_DELAY       13

#define IMAGE_REL_BASED_ABSOLUTE          0
#define IMAGE_REL_BASED_DIR64             10

#define IMAGE_SCN_MEM_EXECUTE             0x20000000
#define IMAGE_SCN_MEM_READ                0x40000000
#define IMAGE_SCN_MEM_WRITE               0x80000000

#define IMAGE_ORDINAL_FLAG64              0x8000000000000000ULL
#define DELAY_ATTRIBUTE_RVA               0x00000001

#define THUNK_SIZE                        48
#define FORWARD_DEPTH                     8

// Fields of the image are read directly, x86-64 reads unaligned memory natively

#define READ16(pointer)          (*(const uint16_t*)(pointer))
#define READ32(pointer)          (*(const uint32_t*)(pointer))
#define READ64(pointer)          (*(const uint64_t*)(pointer))
#define WRITE64(pointer, value)  (*(uint64_t*)(pointer) = (value))

// A name below 0x10000 is an ordinal, as in Windows

#define IS_ORDINAL(name)         ((uintptr_t)(name) < 0x10000)

// Every RVA from the image goes through this check

static inline uint8_t* GetAddress(struct Module* image, uint64_t address, uint64_t length)
{
  if ((address          > image->size) ||
      (length           > image->size) ||
      (address + length > image->size))
    return NULL;

  return image->base + address;
}

// A string of the image, NULL when it is not terminated inside the image

static inline char* GetString(struct Module* image, uint64_t address)
{
  uint8_t* string;

  if (((string = GetAddress(image, address, 1)) == NULL) ||
      (memchr(string, '\0', image->size - address) == NULL))
    return NULL;

  return (char*)string;
}

struct Layout
{
  const uint8_t* header;    // IMAGE_NT_HEADERS64 in the mapped image
  const uint8_t* optional;  // IMAGE_OPTIONAL_HEADER64
  const uint8_t* sections;  // IMAGE_SECTION_HEADER[]
  uint16_t count;           // Count of sections
  uint32_t directories;     // NumberOfRvaAndSizes
};

static int GetLayout(const uint8_t* data, size_t size, struct Layout* layout)
{
  uint32_t offset;
  uint16_t length;

  if ((size < 0x40) ||
      (data[0] != 'M') ||
      (data[1] != 'Z'))
    return -1;

  offset = READ32(data + 0x3c);

  if (((uint64_t)offset + 24 > size) ||
      (memcmp(data + offset, "PE\0\0", 4) != 0) ||
      (READ16(data + offset + 4) != IMAGE_FILE_MACHINE_AMD64))
    return -1;

  layout->header   = data + offset;
  layout->count    = READ16(layout->header + 6);
  length           = READ16(layout->header + 20);
  layout->optional = layout->header + 24;
  layout->sections = layout->optional + length;

  if ((length < 112) ||
      ((uint64_t)offset + 24 + length + 40ULL * layout->count > size) ||
      (READ16(layout->optional) != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
    return -1;

  layout->directories = READ32(layout->optional + 108);

  if ((layout->directories > 16) ||
      (112 + 8 * layout->directories > length))
    return -1;

  return 0;
}

static void GetDirectory(struct Layout* layout, uint32_t index, uint32_t* address, uint32_t* size)
{
  *address = 0;
  *size    = 0;

  if (index < layout->directories)
  {
    *address = READ32(layout->optional + 112 + 8 * index + 0);
    *size    = READ32(layout->optional + 112 + 8 * index + 4);
  }
}

// Reason of the last failure of LoadLibrary() / AttachLibrary() in the calling thread

static __thread int LibraryError = LIBRARY_ERROR_NONE;

int GetLibraryLastError(void)
{
  return LibraryError;
}

const char* GetLibraryErrorText(int error)
{
  switch (error)
  {
    case LIBRARY_ERROR_NONE:           return "no error";
    case LIBRARY_ERROR_OPEN:           return "the file cannot be opened or read";
    case LIBRARY_ERROR_FORMAT:         return "not a PE32+ x86-64 image";
    case LIBRARY_ERROR_ADDRESS_AWARE:  return "not large address aware (32-bit pointers, beyond the line: Wine)";
    case LIBRARY_ERROR_BROKEN:         return "broken image (headers, sections, relocations, imports or TLS)";
    case LIBRARY_ERROR_UNSUPPORTED:    return "a feature of PE the loader does not support";
    case LIBRARY_ERROR_IMAGE_BASE:     return "stripped relocations and the ImageBase is taken";
    case LIBRARY_ERROR_TLS_INDEXES:    return "no free TLS index";
    case LIBRARY_ERROR_ENTRY:          return "DllMain returned FALSE";
    case LIBRARY_ERROR_SYSTEM:         return "the system refused memory or a thread";
  }

  return "unknown error";
}

// One recursive lock for both registries: LoadLibrary() loads dependencies recursively

static pthread_mutex_t LibraryLock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static struct LibraryProvider* Providers = NULL;
static struct LibraryObserver* Observers = NULL;
static struct Module* Modules = NULL;

// Environment of Windows code: TEB per thread, one PEB, static TLS of modules, notifications of DllMain
// Offsets are of the x64 layout, only fields that Windows code reads without calling the system are filled

#define TEB_SIZE                          0x2000
#define TEB_STACK_BASE                    0x0008
#define TEB_STACK_LIMIT                   0x0010
#define TEB_SELF                          0x0030
#define TEB_PROCESS_ID                    0x0040
#define TEB_THREAD_ID                     0x0048
#define TEB_TLS_POINTER                   0x0058
#define TEB_PEB                           0x0060

#define PEB_SIZE                          0x1000
#define PEB_BEING_DEBUGGED                0x0002
#define PEB_NUMBER_OF_PROCESSORS          0x00b8
#define PEB_OS_MAJOR_VERSION              0x0118
#define PEB_OS_MINOR_VERSION              0x011c
#define PEB_OS_BUILD_NUMBER               0x0120
#define PEB_OS_PLATFORM_ID                0x0124

#define TLS_SLOT_COUNT                    128

#define DLL_PROCESS_DETACH                0
#define DLL_PROCESS_ATTACH                1
#define DLL_THREAD_ATTACH                 2
#define DLL_THREAD_DETACH                 3

typedef void (LIBRARY_ABI *TLSCallback)(void* module, uint32_t reason, void* reserved);
typedef int32_t (LIBRARY_ABI *EntryPoint)(void* module, uint32_t reason, void* reserved);

static uint8_t LibraryPEB[PEB_SIZE] __attribute__((aligned(64)));
static pthread_key_t LibraryKey;
static int LibraryKeyError;
static pthread_once_t LibraryOnce = PTHREAD_ONCE_INIT;

// Global state changes (a module with TLS loaded or freed, a module attached) bump the generation, every thread
// brings itself up to date in PrepareLibraryThread() when its generation differs

static struct Module* Slots[TLS_SLOT_COUNT];      // Owners of TLS indexes
static uint64_t Serial = 0;                       // Serial numbers of loads and attachments
static uint32_t Generation = 1;                   //

#define EXIT_FUNCTION_COUNT               8

static LibraryThreadExit ExitFunctions[EXIT_FUNCTION_COUNT];

static __thread uint8_t* LibraryTEB = NULL;
static __thread uint32_t ThreadGeneration = 0;    // Generation the thread is synchronized to
static __thread uint64_t ThreadSerial = 0;        // Attachments up to this serial were notified in the thread
static __thread uint64_t ThreadOwners[TLS_SLOT_COUNT];  // Serial of the module each TLS block was made for

static void CallTLSCallbacks(struct Module* image, uint32_t reason)
{
  for (uint64_t* callback = image->callbacks; (callback != NULL) && (*callback != 0); callback ++)
    ((TLSCallback)*callback)(image->base, reason, NULL);
}

// As in Windows: TLS callbacks before DllMain on attach, after it on detach. DisableThreadLibraryCalls() silences
// DllMain for threads, TLS callbacks still run

static void NotifyModule(struct Module* image, uint32_t reason)
{
  int attach = (reason == DLL_PROCESS_ATTACH) || (reason == DLL_THREAD_ATTACH);
  int called = (image->entry != NULL) && ((image->threads != 0) || (reason == DLL_PROCESS_ATTACH) || (reason == DLL_PROCESS_DETACH));

  if (attach)
    CallTLSCallbacks(image, reason);

  if (called)
    ((EntryPoint)image->entry)(image->base, reason, NULL);

  if (!attach)
    CallTLSCallbacks(image, reason);
}

// Called with LibraryLock, LibraryTEB is set: TLS blocks follow owners of indexes, attachments made after the last
// synchronization are notified with DLL_THREAD_ATTACH

static void SynchronizeThread(void)
{
  struct Module* image;
  void** blocks;
  uint8_t* block;
  uint64_t serial;

  blocks = (void**)READ64(LibraryTEB + TEB_TLS_POINTER);

  for (int index = 0; index < TLS_SLOT_COUNT; index ++)
  {
    image  = Slots[index];
    serial = image ? image->serial : 0;

    if (ThreadOwners[index] == serial)
      continue;

    // A stale block of a freed module, or a new module

    free(blocks[index]);
    blocks[index]        = NULL;
    ThreadOwners[index]  = 0;

    if ((image != NULL) &&
        ((block = (uint8_t*)malloc(image->initial + image->zero + 1)) != NULL))
    {
      memcpy(block, image->data, image->initial);
      memset(block + image->initial, 0, image->zero + 1);
      blocks[index]       = block;
      ThreadOwners[index] = serial;
    }
  }

  for (image = Modules; image != NULL; image = image->next)
    if ((image->attached != 0) &&
        (image->stamp > ThreadSerial))
      NotifyModule(image, DLL_THREAD_ATTACH);

  ThreadSerial     = Serial;
  ThreadGeneration = Generation;
}

static void ReleaseTEB(void* argument)
{
  struct Module* image;
  void** blocks;

  // Destructor of the thread: GS still points to the TEB, so DLL code can run

  pthread_mutex_lock(&LibraryLock);

  for (image = Modules; image != NULL; image = image->next)
    if ((image->attached != 0) &&
        (image->stamp <= ThreadSerial))
      NotifyModule(image, DLL_THREAD_DETACH);

  // Providers clean up after DLL_THREAD_DETACH (FLS callbacks of Kernel32.c)

  for (int index = 0; (index < EXIT_FUNCTION_COUNT) && (ExitFunctions[index] != NULL); index ++)
    ExitFunctions[index]();

  blocks = (void**)READ64(LibraryTEB + TEB_TLS_POINTER);

  for (int index = 0; index < TLS_SLOT_COUNT; index ++)
    free(blocks[index]);

  pthread_mutex_unlock(&LibraryLock);

  free(blocks);
  free(argument);
  LibraryTEB = NULL;
}

static void InitializeEnvironment(void)
{
  LibraryPEB[PEB_BEING_DEBUGGED] = 0;

  *(uint32_t*)(LibraryPEB + PEB_NUMBER_OF_PROCESSORS) = (uint32_t)sysconf(_SC_NPROCESSORS_ONLN);
  *(uint32_t*)(LibraryPEB + PEB_OS_MAJOR_VERSION)     = 10;     // Windows 10 22H2
  *(uint32_t*)(LibraryPEB + PEB_OS_MINOR_VERSION)     = 0;
  *(uint16_t*)(LibraryPEB + PEB_OS_BUILD_NUMBER)      = 19045;
  *(uint32_t*)(LibraryPEB + PEB_OS_PLATFORM_ID)       = 2;      // VER_PLATFORM_WIN32_NT

  LibraryKeyError = pthread_key_create(&LibraryKey, ReleaseTEB);
}

int RegisterLibraryThreadExit(LibraryThreadExit function)
{
  int index;

  pthread_mutex_lock(&LibraryLock);

  for (index = 0; (index < EXIT_FUNCTION_COUNT) && (ExitFunctions[index] != NULL); index ++);

  if (index < EXIT_FUNCTION_COUNT)
    ExitFunctions[index] = function;

  pthread_mutex_unlock(&LibraryLock);
  return (index < EXIT_FUNCTION_COUNT) ? 0 : -1;
}

uint8_t* GetLibraryTEB(void)
{
  return LibraryTEB;
}

uint8_t* GetLibraryPEB(void)
{
  pthread_once(&LibraryOnce, InitializeEnvironment);
  return LibraryPEB;
}

int PrepareLibraryThread(void)
{
  pthread_attr_t attributes;
  uint8_t* block;
  void** blocks;
  void* address;
  size_t size;

  if ((LibraryTEB != NULL) &&
      (ThreadGeneration == __atomic_load_n(&Generation, __ATOMIC_ACQUIRE)))
    return 0;

  pthread_once(&LibraryOnce, InitializeEnvironment);

  if (LibraryTEB == NULL)
  {
    // Without the key the TEB could not be freed at the exit of the thread

    if (LibraryKeyError != 0)
      return -1;

    block  = (uint8_t*)calloc(1, TEB_SIZE);
    blocks = (void**)calloc(TLS_SLOT_COUNT, sizeof(void*));

    if ((block  == NULL) ||
        (blocks == NULL))
    {
      free(block);
      free(blocks);
      return -1;
    }

    // StackLimit is the lowest usable address: a probe below it hits the guard page of the thread

    if (pthread_getattr_np(pthread_self(), &attributes) == 0)
    {
      if (pthread_attr_getstack(&attributes, &address, &size) == 0)
      {
        WRITE64(block + TEB_STACK_BASE,  (uint64_t)address + size);
        WRITE64(block + TEB_STACK_LIMIT, (uint64_t)address);
      }

      pthread_attr_destroy(&attributes);
    }

    WRITE64(block + TEB_SELF,        (uint64_t)block);
    WRITE64(block + TEB_PROCESS_ID,  (uint64_t)getpid());
    WRITE64(block + TEB_THREAD_ID,   (uint64_t)syscall(SYS_gettid));
    WRITE64(block + TEB_TLS_POINTER, (uint64_t)blocks);
    WRITE64(block + TEB_PEB,         (uint64_t)LibraryPEB);

    if (pthread_setspecific(LibraryKey, block) != 0)
    {
      free(block);
      free(blocks);
      return -1;
    }

    if (syscall(SYS_arch_prctl, ARCH_SET_GS, block) < 0)
    {
      pthread_setspecific(LibraryKey, NULL);
      free(block);
      free(blocks);
      return -1;
    }

    LibraryTEB = block;
  }

  pthread_mutex_lock(&LibraryLock);
  SynchronizeThread();
  pthread_mutex_unlock(&LibraryLock);

  return 0;
}

// Bumps the generation: every thread synchronizes on its next PrepareLibraryThread()

static void ChangeEnvironment(void)
{
  __atomic_add_fetch(&Generation, 1, __ATOMIC_RELEASE);
}

// Target of all unresolved imports, ms_abi since it is called from the Windows code
// The thunk passes the name of the function (or its ordinal), the name of the DLL and the importing module

static void LIBRARY_ABI __attribute__((noreturn, used)) HandleUnresolvedImport(const char* name, const char* module, struct Module* image)
{
  char buffer[32];

  if (IS_ORDINAL(name))
  {
    snprintf(buffer, sizeof(buffer), "#%u", (unsigned int)(uintptr_t)name);
    name = buffer;
  }

  if (image->report != NULL)
    image->report(LOG_CRIT, "PE image %s called unsupported import %s!%s, aborting\n", image->name, module, name);
  else
    dprintf(STDERR_FILENO, "PE image %s called unsupported import %s!%s, aborting\n", image->name, module, name);

  abort();
}

char* CopyLibraryString(const char* string)
{
  size_t length;
  char* result;

  length = strlen(string) + 1;
  result = (char*)malloc(length);

  if (result != NULL)
    memcpy(result, string, length);

  return result;
}

void RegisterLibraryProvider(struct LibraryProvider* provider)
{
  pthread_mutex_lock(&LibraryLock);
  provider->next = Providers;
  Providers      = provider;
  pthread_mutex_unlock(&LibraryLock);
}

void UnregisterLibraryProvider(struct LibraryProvider* provider)
{
  struct LibraryProvider** pointer;

  pthread_mutex_lock(&LibraryLock);

  for (pointer = &Providers; *pointer != NULL; pointer = &(*pointer)->next)
  {
    if (*pointer == provider)
    {
      *pointer = provider->next;
      break;
    }
  }

  pthread_mutex_unlock(&LibraryLock);
}

// Called with LibraryLock

static void PublishModule(struct Module* image, int event)
{
  struct LibraryObserver* observer;

  if (image->published != (event == LIBRARY_EVENT_UNLOADING))
    return;

  for (observer = Observers; observer != NULL; observer = observer->next)
    observer->function(image, event);

  image->published = (event == LIBRARY_EVENT_LOADED);
}

void RegisterLibraryObserver(struct LibraryObserver* observer)
{
  struct Module* image;

  pthread_mutex_lock(&LibraryLock);

  observer->next = Observers;
  Observers      = observer;

  for (image = Modules; image != NULL; image = image->next)
    if (image->published != 0)
      observer->function(image, LIBRARY_EVENT_LOADED);

  pthread_mutex_unlock(&LibraryLock);
}

void UnregisterLibraryObserver(struct LibraryObserver* observer)
{
  struct LibraryObserver** pointer;
  struct Module* image;

  pthread_mutex_lock(&LibraryLock);

  for (pointer = &Observers; *pointer != NULL; pointer = &(*pointer)->next)
  {
    if (*pointer == observer)
    {
      *pointer = observer->next;

      for (image = Modules; image != NULL; image = image->next)
        if (image->published != 0)
          observer->function(image, LIBRARY_EVENT_UNLOADING);

      break;
    }
  }

  pthread_mutex_unlock(&LibraryLock);
}

static const struct LibraryImport* FindInTable(const struct LibraryImport* table, const char* name)
{
  if (IS_ORDINAL(name))
  {
    // Providers know names only
    return NULL;
  }

  for (; (table != NULL) && (table->name != NULL); table ++)
    if (strcmp(table->name, name) == 0)
      return table;

  return NULL;
}

// Steps 1 and 2 of the resolution, emulated is set when a provider for exactly this module exists (used only to keep
// quiet about emulated DLLs that are not on disk)

static const struct LibraryImport* FindProvidedImport(const struct LibraryProvider* providers, const char* module, const char* name, int* emulated)
{
  const struct LibraryImport* entry;
  const struct LibraryProvider* provider;

  *emulated = 0;

  for (provider = providers; (provider != NULL) && (provider->imports != NULL); provider ++)
  {
    if ((provider->module != NULL) &&
        (strcasecmp(provider->module, module) != 0))
      continue;

    *emulated |= (provider->module != NULL);

    if ((entry = FindInTable(provider->imports, name)) != NULL)
      return entry;
  }

  for (provider = Providers; provider != NULL; provider = provider->next)
  {
    if (strcasecmp(provider->module, module) != 0)
      continue;

    *emulated = 1;

    if ((entry = FindInTable(provider->imports, name)) != NULL)
      return entry;
  }

  return NULL;
}

const struct LibraryImport* FindLibraryImport(const char* module, const char* name)
{
  const struct LibraryImport* entry;
  int emulated;

  pthread_mutex_lock(&LibraryLock);
  entry = FindProvidedImport(NULL, module, name, &emulated);
  pthread_mutex_unlock(&LibraryLock);

  return entry;
}

// Imports refer to modules by name: the first loaded module of the name wins, as in Windows

static struct Module* FindModuleByName(const char* name)
{
  struct Module* image;

  for (image = Modules; image != NULL; image = image->next)
    if (strcasecmp(image->name, name) == 0)
      return image;

  return NULL;
}

static struct Module* FindModuleByFile(uint64_t device, uint64_t inode)
{
  struct Module* image;

  for (image = Modules; image != NULL; image = image->next)
    if ((image->device == device) &&
        (image->inode  == inode))
      return image;

  return NULL;
}

// Step 3: a PE module the importer depends on, shared or loaded from the directory of the importer
// The reference is owned by the importer and released by FreeLibrary() of the importer

static struct Module* LoadDependency(struct Module* importer, const char* name, const struct LibraryProvider* providers)
{
  struct Module* image;
  struct Module** list;
  char path[PATH_MAX];
  char lower[NAME_MAX + 1];
  size_t index;

  // Already a dependency of the importer (forwards are resolved on every GetProcAddress): one reference is enough

  for (index = 0; index < importer->number; index ++)
    if (strcasecmp(importer->dependencies[index]->name, name) == 0)
      return importer->dependencies[index];

  if ((image = FindModuleByName(name)) != NULL)
  {
    image->count ++;
  }
  else
  {
    // Windows names are case-insensitive, files on Linux are not: try the name as is and in lower case

    for (index = 0; (name[index] != '\0') && (index < NAME_MAX); index ++)
      lower[index] = tolower((unsigned char)name[index]);
    lower[index] = '\0';

    snprintf(path, sizeof(path), "%s/%s", importer->directory, name);

    if (access(path, R_OK) < 0)
      snprintf(path, sizeof(path), "%s/%s", importer->directory, lower);

    if (access(path, R_OK) < 0)
      return NULL;

    if ((image = LoadLibrary(path, providers, importer->report)) == NULL)
      return NULL;
  }

  list = (struct Module**)realloc(importer->dependencies, (importer->number + 1) * sizeof(struct Module*));
  list[importer->number ++] = image;
  importer->dependencies    = list;

  return image;
}

static void* GetExport(struct Module* image, const char* name, int depth);

// Steps 1-3 for MODULE!name of the importer (name may be an ordinal), NULL goes to the thunk (step 4)
// missing is set when MODULE has no provider and is not found on disk

static void* ResolveSymbol(struct Module* importer, const char* module, const char* name, const struct LibraryProvider* providers, int depth, int* missing)
{
  const struct LibraryImport* entry;
  struct Module* dependency;
  int emulated;

  *missing = 0;

  if ((entry = FindProvidedImport(providers, module, name, &emulated)) != NULL)
  {
    // Implemented or explicitly forbidden (function == NULL)
    return entry->function;
  }

  // Providers overlay the real DLL: what they do not have comes from the PE module, if it exists

  if ((dependency = LoadDependency(importer, module, providers)) == NULL)
  {
    // KERNEL32.dll is never on disk, only DLLs without providers are missing
    *missing = (emulated == 0);
    return NULL;
  }

  return GetExport(dependency, name, depth);
}

// Forwarded export "MODULE.Function" or "MODULE.#ordinal" of the image

static void* ResolveForward(struct Module* image, const char* forward, int depth)
{
  const char* dot;
  const char* name;
  char module[NAME_MAX + 1];
  long number;
  int missing;
  size_t length;

  dot = strchr(forward, '.');

  if ((dot == NULL) ||
      (depth >= FORWARD_DEPTH) ||
      ((length = dot - forward) + 4 > NAME_MAX))
  {
    // No module or a loop
    return NULL;
  }

  memcpy(module, forward, length);
  strcpy(module + length, ".dll");

  name = dot + 1;

  if (*name == '#')
  {
    number = strtol(name + 1, NULL, 10);

    if ((number <= 0) ||
        (number > 0xffff))
      return NULL;

    name = LIBRARY_ORDINAL(number);
  }

  return ResolveSymbol(image, module, name, image->providers, depth, &missing);
}

static void* GetExport(struct Module* image, const char* name, int depth)
{
  struct Layout layout;
  uint8_t* directory;
  uint8_t* names;
  uint8_t* ordinals;
  uint8_t* functions;
  uint8_t* string;
  char* forward;
  uint32_t address;
  uint32_t size;
  uint32_t count;
  uint32_t total;
  uint32_t number;
  uint32_t target;
  size_t length;

  if (GetLayout(image->base, image->size, &layout) < 0)
    return NULL;

  GetDirectory(&layout, IMAGE_DIRECTORY_ENTRY_EXPORT, &address, &size);

  if ((directory = GetAddress(image, address, 40)) == NULL)
    return NULL;

  count     = READ32(directory + 24);
  total     = READ32(directory + 20);
  functions = GetAddress(image, READ32(directory + 28), 4ULL * total);
  names     = GetAddress(image, READ32(directory + 32), 4ULL * count);
  ordinals  = GetAddress(image, READ32(directory + 36), 2ULL * count);

  if (functions == NULL)
    return NULL;

  if (IS_ORDINAL(name))
  {
    // Ordinals are biased by Base of the export directory
    number = (uint32_t)(uintptr_t)name - READ32(directory + 16);
  }
  else
  {
    if ((names    == NULL) ||
        (ordinals == NULL))
      return NULL;

    length = strlen(name) + 1;
    number = total;

    for (uint32_t index = 0; index < count; index ++)
    {
      string = GetAddress(image, READ32(names + 4 * index), length);

      if ((string != NULL) &&
          (memcmp(string, name, length) == 0))
      {
        number = READ16(ordinals + 2 * index);
        break;
      }
    }
  }

  if ((number >= total) ||
      ((target = READ32(functions + 4 * number)) == 0))
    return NULL;

  if ((target >= address) &&
      (target <  address + size))
  {
    if ((forward = GetString(image, target)) == NULL)
      return NULL;

    return ResolveForward(image, forward, depth + 1);
  }

  return GetAddress(image, target, 1);
}

void* GetProcAddress(struct Module* image, const char* name)
{
  void* function;

  // Forwarded exports may load dependencies

  pthread_mutex_lock(&LibraryLock);
  function = GetExport(image, name, 0);
  pthread_mutex_unlock(&LibraryLock);

  return function;
}

static int ApplyRelocations(struct Module* image, struct Layout* layout, LibraryReport report)
{
  uint8_t* block;
  uint8_t* limit;
  uint8_t* place;
  uint32_t address;
  uint32_t size;
  uint32_t page;
  uint32_t length;
  uint16_t entry;
  uint64_t delta;

  GetDirectory(layout, IMAGE_DIRECTORY_ENTRY_BASERELOC, &address, &size);

  delta = (uint64_t)image->base - READ64(layout->optional + 24);
  block = GetAddress(image, address, size);

  if ((delta != 0) &&
      (READ16(layout->header + 22) & IMAGE_FILE_RELOCS_STRIPPED))
  {
    // Such image is mapped at its ImageBase, this is a guard
    LibraryError = LIBRARY_ERROR_UNSUPPORTED;
    report(LOG_ERR, "PE image %s has stripped relocations\n", image->name);
    return -1;
  }

  if (block == NULL)
    return 0;

  limit = block + size;

  while (block + 8 <= limit)
  {
    page   = READ32(block + 0);
    length = READ32(block + 4);

    if ((length < 8) ||
        (block + length > limit))
    {
      LibraryError = LIBRARY_ERROR_BROKEN;
      report(LOG_ERR, "PE image %s has broken relocation block\n", image->name);
      return -1;
    }

    for (uint8_t* pointer = block + 8; pointer + 2 <= block + length; pointer += 2)
    {
      entry = READ16(pointer);

      switch (entry >> 12)
      {
        case IMAGE_REL_BASED_ABSOLUTE:
          break;

        case IMAGE_REL_BASED_DIR64:
          place = GetAddress(image, (uint64_t)page + (entry & 0xfff), sizeof(uint64_t));
          if (place == NULL)
          {
            LibraryError = LIBRARY_ERROR_BROKEN;
            report(LOG_ERR, "PE image %s has relocation out of image\n", image->name);
            return -1;
          }
          WRITE64(place, READ64(place) + delta);
          break;

        default:
          LibraryError = LIBRARY_ERROR_UNSUPPORTED;
          report(LOG_ERR, "PE image %s has unsupported relocation type %d\n", image->name, entry >> 12);
          return -1;
      }
    }

    block += length;
  }

  return 0;
}

// Both import tables, regular and delayed, are walked by one function: pass 0 counts entries, pass 1 binds them

struct Binding
{
  int pass;
  size_t count;
  uint8_t* thunk;
  const struct LibraryProvider* providers;
};

static int BindEntry(struct Module* image, struct Binding* binding, char* module, uint64_t value, uint8_t* slot, int* reported)
{
  const char* name;
  void* function;
  int missing;

  if (binding->pass == 0)
  {
    binding->count ++;
    return 0;
  }

  if (value & IMAGE_ORDINAL_FLAG64)
  {
    name = LIBRARY_ORDINAL(value & 0xffff);
  }
  else if ((name = GetString(image, (value & 0x7fffffff) + 2)) == NULL)
  {
    LibraryError = LIBRARY_ERROR_BROKEN;
    image->report(LOG_ERR, "PE image %s has broken import name\n", image->name);
    return -1;
  }

  function = ResolveSymbol(image, module, name, binding->providers, 0, &missing);

  if ((missing   != 0) &&
      (*reported == 0))
  {
    *reported = 1;
    image->report(LOG_WARNING, "PE image %s imports from %s, which is not found, its functions abort when called\n", image->name, module);
  }

  if (function == NULL)
  {
    // mov rcx, name ; mov rdx, module ; mov r8, image ; jmp [rip + 0] ; HandleUnresolvedImport

    uint8_t* thunk = binding->thunk;

    thunk[0]  = 0x48;
    thunk[1]  = 0xb9;
    WRITE64(thunk + 2, (uint64_t)name);
    thunk[10] = 0x48;
    thunk[11] = 0xba;
    WRITE64(thunk + 12, (uint64_t)module);
    thunk[20] = 0x49;
    thunk[21] = 0xb8;
    WRITE64(thunk + 22, (uint64_t)image);
    thunk[30] = 0xff;
    thunk[31] = 0x25;
    memset(thunk + 32, 0, 4);
    WRITE64(thunk + 36, (uint64_t)HandleUnresolvedImport);

    function        = thunk;
    binding->thunk += THUNK_SIZE;
  }

  WRITE64(slot, (uint64_t)function);
  return 0;
}

static int WalkImports(struct Module* image, struct Layout* layout, struct Binding* binding)
{
  char* module;
  uint8_t* descriptor;
  uint8_t* lookup;
  uint8_t* table;
  uint8_t* handle;
  uint32_t address;
  uint32_t size;
  uint64_t value;
  int reported;

  // Regular imports: OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk

  GetDirectory(layout, IMAGE_DIRECTORY_ENTRY_IMPORT, &address, &size);

  for (descriptor = size ? GetAddress(image, address, 20) : NULL;
       (descriptor != NULL) && ((READ32(descriptor + 12) != 0) || (READ32(descriptor + 16) != 0));
       descriptor = GetAddress(image, (descriptor - image->base) + 20, 20))
  {
    lookup   = GetAddress(image, READ32(descriptor + 0) ? READ32(descriptor + 0) : READ32(descriptor + 16), 8);
    table    = GetAddress(image, READ32(descriptor + 16), 8);
    module   = GetString(image, READ32(descriptor + 12));
    reported = 0;

    if ((lookup == NULL) ||
        (table  == NULL) ||
        (module == NULL))
    {
      LibraryError = LIBRARY_ERROR_BROKEN;
      image->report(LOG_ERR, "PE image %s has broken import descriptor\n", image->name);
      return -1;
    }

    while ((lookup != NULL) &&
           (table  != NULL) &&
           ((value = READ64(lookup)) != 0))
    {
      if (BindEntry(image, binding, module, value, table, &reported) < 0)
        return -1;

      lookup = GetAddress(image, (lookup - image->base) + 8, 8);
      table  = GetAddress(image, (table  - image->base) + 8, 8);
    }
  }

  // Delayed imports are bound at once: Attributes, DllName, ModuleHandle, IAT, INT, BoundIAT, UnloadIAT, TimeDateStamp
  // With the IAT bound the helper of the DLL (__delayLoadHelper2) is never called

  GetDirectory(layout, IMAGE_DIRECTORY_ENTRY_DELAY, &address, &size);

  for (descriptor = size ? GetAddress(image, address, 32) : NULL;
       (descriptor != NULL) && (READ32(descriptor + 4) != 0);
       descriptor = GetAddress(image, (descriptor - image->base) + 32, 32))
  {
    if ((READ32(descriptor + 0) & DELAY_ATTRIBUTE_RVA) == 0)
    {
      LibraryError = LIBRARY_ERROR_UNSUPPORTED;
      image->report(LOG_ERR, "PE image %s has delayed imports in the old format (VA), not supported\n", image->name);
      return -1;
    }

    module   = GetString(image, READ32(descriptor + 4));
    handle   = READ32(descriptor + 8) ? GetAddress(image, READ32(descriptor + 8), 8) : NULL;
    table    = GetAddress(image, READ32(descriptor + 12), 8);
    lookup   = GetAddress(image, READ32(descriptor + 16), 8);
    reported = 0;

    if ((lookup == NULL) ||
        (table  == NULL) ||
        (module == NULL))
    {
      LibraryError = LIBRARY_ERROR_BROKEN;
      image->report(LOG_ERR, "PE image %s has broken delayed import descriptor\n", image->name);
      return -1;
    }

    if ((handle != NULL) &&
        (binding->pass == 1))
    {
      // The helper checks the handle of the DLL first, a non-zero one means it is loaded
      WRITE64(handle, (uint64_t)image->base);
    }

    while ((lookup != NULL) &&
           (table  != NULL) &&
           ((value = READ64(lookup)) != 0))
    {
      if (BindEntry(image, binding, module, value, table, &reported) < 0)
        return -1;

      lookup = GetAddress(image, (lookup - image->base) + 8, 8);
      table  = GetAddress(image, (table  - image->base) + 8, 8);
    }
  }

  return 0;
}

static int BindImports(struct Module* image, struct Layout* layout, const struct LibraryProvider* providers)
{
  struct Binding binding;
  size_t page;

  memset(&binding, 0, sizeof(binding));
  binding.providers = providers;

  if (WalkImports(image, layout, &binding) < 0)
    return -1;

  if (binding.count == 0)
    return 0;

  page          = getpagesize();
  image->length = (binding.count * THUNK_SIZE + page - 1) & ~(page - 1);
  image->thunks = (uint8_t*)mmap(NULL, image->length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (image->thunks == MAP_FAILED)
  {
    image->thunks = NULL;
    LibraryError = LIBRARY_ERROR_SYSTEM;
    image->report(LOG_ERR, "Error allocating thunks of PE image %s\n", image->name);
    return -1;
  }

  binding.pass  = 1;
  binding.thunk = image->thunks;

  if (WalkImports(image, layout, &binding) < 0)
    return -1;

  image->unresolved = (binding.thunk - image->thunks) / THUNK_SIZE;

  if (mprotect(image->thunks, image->length, PROT_READ | PROT_EXEC) < 0)
  {
    LibraryError = LIBRARY_ERROR_SYSTEM;
    image->report(LOG_ERR, "Error protecting thunks of PE image %s\n", image->name);
    return -1;
  }

  return 0;
}

static int GetSectionProtection(struct Module* image, const uint8_t* section)
{
  uint32_t characteristics = READ32(section + 36);

  if (image->flat)
  {
    // Sections share pages
    return PROT_READ | PROT_WRITE | PROT_EXEC;
  }

  return
    ((characteristics & IMAGE_SCN_MEM_READ)    ? PROT_READ  : 0) |
    ((characteristics & IMAGE_SCN_MEM_WRITE)   ? PROT_WRITE : 0) |
    ((characteristics & IMAGE_SCN_MEM_EXECUTE) ? PROT_EXEC  : 0);
}

static int ProtectModule(struct Module* image)
{
  struct Layout layout;
  const uint8_t* section;
  uint32_t address;
  uint32_t size;
  size_t page;

  page = getpagesize();

  if (image->flat)
    return mprotect(image->base, image->size, PROT_READ | PROT_WRITE | PROT_EXEC);

  // Copy of headers is a part of the image, so the layout stays valid after protection

  if ((GetLayout(image->base, image->size, &layout) < 0) ||
      (mprotect(image->base, image->size, PROT_READ) < 0))
    return -1;

  for (section = layout.sections; section < layout.sections + 40 * layout.count; section += 40)
  {
    size    = READ32(section + 8);
    address = READ32(section + 12);
    size    = (size + page - 1) & ~(page - 1);

    if ((size != 0) &&
        (mprotect(image->base + address, size, GetSectionProtection(image, section)) < 0))
      return -1;
  }

  return 0;
}

// A virtual address inside the image (TLS directory keeps VAs, already relocated), NULL when outside

static uint8_t* GetVirtualAddress(struct Module* image, uint64_t address, uint64_t length)
{
  if (address < (uint64_t)image->base)
    return NULL;

  return GetAddress(image, address - (uint64_t)image->base, length);
}

// TLS directory: StartAddressOfRawData, EndAddressOfRawData, AddressOfIndex, AddressOfCallBacks (VAs),
// SizeOfZeroFill, Characteristics. The index is written into the image, blocks are made per thread

static int SetUpTLS(struct Module* image, struct Layout* layout)
{
  uint8_t* directory;
  uint8_t* index;
  uint64_t start;
  uint64_t end;
  uint64_t* callback;
  uint32_t address;
  uint32_t size;
  int slot;

  GetDirectory(layout, IMAGE_DIRECTORY_ENTRY_TLS, &address, &size);

  if (size == 0)
    return 0;

  if ((directory = GetAddress(image, address, 40)) == NULL)
  {
    LibraryError = LIBRARY_ERROR_BROKEN;
    image->report(LOG_ERR, "PE image %s has broken TLS directory\n", image->name);
    return -1;
  }

  start = READ64(directory + 0);
  end   = READ64(directory + 8);

  if ((end < start) ||
      ((start != end) && (GetVirtualAddress(image, start, end - start) == NULL)) ||
      ((index = GetVirtualAddress(image, READ64(directory + 16), 4)) == NULL))
  {
    LibraryError = LIBRARY_ERROR_BROKEN;
    image->report(LOG_ERR, "PE image %s has broken TLS directory\n", image->name);
    return -1;
  }

  if (READ64(directory + 24) != 0)
  {
    // Callbacks: VAs terminated by zero, all inside the image
    for (callback = (uint64_t*)GetVirtualAddress(image, READ64(directory + 24), 8);
         (callback != NULL) && (*callback != 0) && (GetVirtualAddress(image, *callback, 1) != NULL);
         callback = (uint64_t*)GetVirtualAddress(image, (uint64_t)(callback + 1), 8));

    if ((callback == NULL) ||
        (*callback != 0))
    {
      LibraryError = LIBRARY_ERROR_BROKEN;
      image->report(LOG_ERR, "PE image %s has broken TLS callbacks\n", image->name);
      return -1;
    }

    image->callbacks = (uint64_t*)GetVirtualAddress(image, READ64(directory + 24), 8);
  }

  for (slot = 0; (slot < TLS_SLOT_COUNT) && (Slots[slot] != NULL); slot ++);

  if (slot == TLS_SLOT_COUNT)
  {
    LibraryError = LIBRARY_ERROR_TLS_INDEXES;
    image->report(LOG_ERR, "PE image %s has TLS, but all %d indexes are taken\n", image->name, TLS_SLOT_COUNT);
    return -1;
  }

  *(uint32_t*)index = slot;

  image->slot    = slot;
  image->data    = start ? GetVirtualAddress(image, start, 1) : NULL;
  image->initial = end - start;
  image->zero    = READ32(directory + 32);
  Slots[slot]    = image;

  ChangeEnvironment();
  return 0;
}

int AttachLibrary(struct Module* image)
{
  int result;

  pthread_mutex_lock(&LibraryLock);

  LibraryError = LIBRARY_ERROR_NONE;

  if (image->attached != 0)
  {
    pthread_mutex_unlock(&LibraryLock);
    return 0;
  }

  // Windows initializes dependencies first

  for (size_t index = 0; index < image->number; index ++)
  {
    if (AttachLibrary(image->dependencies[index]) < 0)
    {
      pthread_mutex_unlock(&LibraryLock);
      return -1;
    }
  }

  if (PrepareLibraryThread() < 0)
  {
    LibraryError = LIBRARY_ERROR_SYSTEM;
    image->report(LOG_ERR, "Error preparing a thread for PE image %s\n", image->name);
    pthread_mutex_unlock(&LibraryLock);
    return -1;
  }

  CallTLSCallbacks(image, DLL_PROCESS_ATTACH);

  result = (image->entry == NULL) || ((EntryPoint)image->entry)(image->base, DLL_PROCESS_ATTACH, NULL);

  if (result == 0)
  {
    LibraryError = LIBRARY_ERROR_ENTRY;
    image->report(LOG_ERR, "DllMain of PE image %s failed\n", image->name);
    CallTLSCallbacks(image, DLL_PROCESS_DETACH);
    pthread_mutex_unlock(&LibraryLock);
    return -1;
  }

  // The attaching thread got DLL_PROCESS_ATTACH, other threads get DLL_THREAD_ATTACH on their next synchronization

  image->attached = 1;
  image->stamp    = ++ Serial;
  ThreadSerial    = Serial;
  ChangeEnvironment();

  pthread_mutex_unlock(&LibraryLock);
  return 0;
}

int SetLibraryThreadCalls(const void* base, int enabled)
{
  struct Module* image;

  if ((image = GetLibraryByAddress(base)) == NULL)
    return -1;

  image->threads = enabled;
  return 0;
}

struct Module* GetLibraryByAddress(const void* address)
{
  struct Module* image;

  pthread_mutex_lock(&LibraryLock);

  for (image = Modules; image != NULL; image = image->next)
    if (((uintptr_t)address >= (uintptr_t)image->base) &&
        ((uintptr_t)address <  (uintptr_t)image->base + image->size))
      break;

  pthread_mutex_unlock(&LibraryLock);
  return image;
}

struct Module* GetLibraryByName(const char* name)
{
  struct Module* image;
  char buffer[NAME_MAX + 1];

  pthread_mutex_lock(&LibraryLock);

  if ((image = FindModuleByName(name)) == NULL)
  {
    // Windows adds .dll when the name has no extension
    snprintf(buffer, sizeof(buffer), "%s.dll", name);
    image = (strchr(name, '.') == NULL) ? FindModuleByName(buffer) : NULL;
  }

  pthread_mutex_unlock(&LibraryLock);
  return image;
}

size_t GetLibraryUnresolvedImports(struct Module* image, LibraryImportCallback callback, void* context)
{
  size_t number;
  uint8_t* thunk;

  // Every unresolved import has a thunk: mov rcx, name ; mov rdx, module ; mov r8, image ; jmp [rip] ; handler

  for (number = 0; number < image->unresolved; number ++)
  {
    thunk = image->thunks + number * THUNK_SIZE;

    if (callback != NULL)
      callback((const char*)READ64(thunk + 12), (const char*)READ64(thunk + 2), context);
  }

  return number;
}

struct Module* LoadLibrary(const char* path, const struct LibraryProvider* providers, LibraryReport report)
{
  int handle;
  struct stat status;
  uint8_t* data;
  uint8_t* base;
  struct Layout layout;
  struct Module* image;
  struct Module* other;
  const uint8_t* section;
  char buffer[PATH_MAX];
  const char* name;
  uint64_t preferred;
  uint32_t alignment;
  uint32_t address;
  uint32_t length;
  uint32_t offset;
  uint32_t size;
  int flags;

  handle = -1;
  data   = MAP_FAILED;
  image  = NULL;

  LibraryError = LIBRARY_ERROR_NONE;

  pthread_mutex_lock(&LibraryLock);

  name = strrchr(path, '/');
  name = name ? name + 1 : path;

  if (((handle = open(path, O_RDONLY | O_CLOEXEC)) < 0) ||
      (fstat(handle, &status) < 0))
  {
    LibraryError = LIBRARY_ERROR_OPEN;
    report(LOG_ERR, "Error opening PE image %s\n", path);
    goto Failure;
  }

  if ((image = FindModuleByFile(status.st_dev, status.st_ino)) != NULL)
  {
    // Shared module: the same file is the same DLL

    if ((providers != NULL) &&
        (providers != image->providers))
      report(LOG_WARNING, "PE image %s is already loaded, providers of this call are not applied\n", path);

    image->count ++;
    close(handle);
    pthread_mutex_unlock(&LibraryLock);
    return image;
  }

  if ((other = FindModuleByName(name)) != NULL)
  {
    // Imports by name keep resolving to the first one
    report(LOG_WARNING, "PE image %s has the same name as the loaded %s/%s\n", path, other->directory, other->name);
  }

  if ((data = (uint8_t*)mmap(NULL, status.st_size, PROT_READ, MAP_PRIVATE, handle, 0)) == MAP_FAILED)
  {
    LibraryError = LIBRARY_ERROR_OPEN;
    report(LOG_ERR, "Error reading PE image %s\n", path);
    goto Failure;
  }

  if (GetLayout(data, status.st_size, &layout) < 0)
  {
    LibraryError = LIBRARY_ERROR_FORMAT;
    report(LOG_ERR, "File %s is not a PE32+ x86-64 image\n", path);
    goto Failure;
  }

  if ((READ16(layout.header + 22) & IMAGE_FILE_LARGE_ADDRESS_AWARE) == 0)
  {
    // Such image may truncate pointers to 32 bits, but mappings and malloc of Linux are above 4 GB
    LibraryError = LIBRARY_ERROR_ADDRESS_AWARE;
    report(LOG_ERR, "PE image %s is not large address aware, not supported\n", path);
    goto Failure;
  }

  alignment = READ32(layout.optional + 32);

  if (alignment == 0)
  {
    LibraryError = LIBRARY_ERROR_BROKEN;
    report(LOG_ERR, "PE image %s has no section alignment\n", path);
    goto Failure;
  }

  // Registered from the beginning: a dependency that imports from this module back finds it (cycles)

  strncpy(buffer, path, sizeof(buffer) - 1);
  buffer[sizeof(buffer) - 1] = '\0';

  image            = (struct Module*)calloc(1, sizeof(struct Module));
  image->name      = CopyLibraryString(name);
  image->directory = CopyLibraryString(dirname(buffer));
  image->device    = status.st_dev;
  image->inode     = status.st_ino;
  image->flat      = (alignment % getpagesize()) != 0;
  image->count     = 1;
  image->providers = providers;
  image->report    = report;
  image->serial    = ++ Serial;
  image->threads   = 1;
  image->slot      = -1;
  image->next      = Modules;
  Modules          = image;

  image->size = READ32(layout.optional + 56);
  preferred   = READ64(layout.optional + 24);
  flags       = MAP_PRIVATE | MAP_ANONYMOUS;

  if (READ16(layout.header + 22) & IMAGE_FILE_RELOCS_STRIPPED)
  {
    // No relocations: the image works at its ImageBase only, an address taken by something else is a failure
    flags |= MAP_FIXED_NOREPLACE;
  }

  base = (uint8_t*)mmap((flags & MAP_FIXED_NOREPLACE) ? (void*)preferred : NULL, image->size, PROT_READ | PROT_WRITE, flags, -1, 0);

  if ((base != MAP_FAILED) &&
      (flags & MAP_FIXED_NOREPLACE) &&
      (base != (uint8_t*)preferred))
  {
    // Kernels before 4.17 take MAP_FIXED_NOREPLACE as a hint
    munmap(base, image->size);
    base = MAP_FAILED;
  }

  if (base == MAP_FAILED)
  {
    if (flags & MAP_FIXED_NOREPLACE)
    {
      LibraryError = LIBRARY_ERROR_IMAGE_BASE;
      report(LOG_ERR, "PE image %s has stripped relocations and its ImageBase 0x%llx is taken\n", path, (unsigned long long)preferred);
    }
    else
    {
      LibraryError = LIBRARY_ERROR_SYSTEM;
      report(LOG_ERR, "Error allocating memory for PE image %s\n", path);
    }

    goto Failure;
  }

  image->base = base;
  size        = READ32(layout.optional + 60);

  if ((size > status.st_size) ||
      (size > image->size))
  {
    LibraryError = LIBRARY_ERROR_BROKEN;
    report(LOG_ERR, "PE image %s has broken headers\n", path);
    goto Failure;
  }

  memcpy(image->base, data, size);

  for (section = layout.sections; section < layout.sections + 40 * layout.count; section += 40)
  {
    address = READ32(section + 12);
    length  = READ32(section + 16);
    offset  = READ32(section + 20);
    size    = READ32(section + 8);

    if (length > size)
    {
      // Raw data is aligned to FileAlignment and may exceed VirtualSize
      length = size;
    }

    if ((GetAddress(image, address, size) == NULL) ||
        ((uint64_t)offset + length > (uint64_t)status.st_size))
    {
      LibraryError = LIBRARY_ERROR_BROKEN;
      report(LOG_ERR, "PE image %s has section out of bounds\n", path);
      goto Failure;
    }

    memcpy(image->base + address, data + offset, length);
  }

  // From here layout points to the mapped copy of headers

  GetLayout(image->base, image->size, &layout);

  if ((ApplyRelocations(image, &layout, report) < 0) ||
      (BindImports(image, &layout, providers) < 0) ||
      (SetUpTLS(image, &layout) < 0))
    goto Failure;

  if ((address = READ32(layout.optional + 16)) != 0)
    image->entry = GetAddress(image, address, 1);

  if (ProtectModule(image) < 0)
  {
    LibraryError = LIBRARY_ERROR_SYSTEM;
    report(LOG_ERR, "Error protecting PE image %s\n", path);
    goto Failure;
  }

  munmap(data, status.st_size);
  close(handle);
  PublishModule(image, LIBRARY_EVENT_LOADED);
  pthread_mutex_unlock(&LibraryLock);
  return image;

  Failure:

  if (data != MAP_FAILED)
    munmap(data, status.st_size);
  if (handle >= 0)
    close(handle);

  FreeLibrary(image);
  pthread_mutex_unlock(&LibraryLock);
  return NULL;
}

static void DestroyModule(struct Module* image)
{
  if (image->thunks != NULL)
    munmap(image->thunks, image->length);
  if (image->base != NULL)
    munmap(image->base, image->size);

  free(image->dependencies);
  free(image->directory);
  free(image->name);
  free(image);
}

// The counter of a module is the sum of references from outside (LoadLibrary() calls) and from dependency lists
// of other modules. A module is alive when it has outside references or an alive module depends on it.
// The rest goes away at once, cycles of dependencies included

static void CollectModules(void)
{
  struct Module* image;
  struct Module* garbage;
  struct Module** pointer;
  int changed;

  for (image = Modules; image != NULL; image = image->next)
  {
    image->internal = 0;
    image->alive    = 0;
  }

  for (image = Modules; image != NULL; image = image->next)
    for (size_t index = 0; index < image->number; index ++)
      image->dependencies[index]->internal ++;

  for (image = Modules; image != NULL; image = image->next)
    image->alive = (image->count > image->internal);

  do
  {
    changed = 0;

    for (image = Modules; image != NULL; image = image->next)
    {
      for (size_t index = 0; (image->alive != 0) && (index < image->number); index ++)
      {
        if (image->dependencies[index]->alive == 0)
        {
          image->dependencies[index]->alive = 1;
          changed = 1;
        }
      }
    }
  }
  while (changed != 0);

  garbage = NULL;
  pointer = &Modules;

  while (*pointer != NULL)
  {
    image = *pointer;

    if (image->alive != 0)
    {
      pointer = &image->next;
      continue;
    }

    *pointer    = image->next;
    image->next = garbage;
    garbage     = image;
  }

  // Attached modules get DLL_PROCESS_DETACH in the reverse order of attachment, while all of them are mapped

  for ( ; ; )
  {
    struct Module* last = NULL;

    for (image = garbage; image != NULL; image = image->next)
      if ((image->attached != 0) &&
          ((last == NULL) || (image->stamp > last->stamp)))
        last = image;

    if (last == NULL)
      break;

    if (PrepareLibraryThread() == 0)
      NotifyModule(last, DLL_PROCESS_DETACH);

    last->attached = 0;
  }

  for (image = garbage; image != NULL; image = image->next)
    PublishModule(image, LIBRARY_EVENT_UNLOADING);

  for (image = garbage; image != NULL; image = image->next)
  {
    if (image->slot >= 0)
    {
      // Blocks of the index are freed by threads on their next synchronization or at exit
      Slots[image->slot] = NULL;
      ChangeEnvironment();
    }
  }

  // References of dead modules to alive ones are dropped, references between dead ones die with them

  for (image = garbage; image != NULL; image = image->next)
    for (size_t index = 0; index < image->number; index ++)
      image->dependencies[index]->count -= image->dependencies[index]->alive;

  while (garbage != NULL)
  {
    image   = garbage;
    garbage = garbage->next;
    DestroyModule(image);
  }
}

void FreeLibrary(struct Module* image)
{
  if (image == NULL)
    return;

  pthread_mutex_lock(&LibraryLock);

  image->count --;
  CollectModules();

  pthread_mutex_unlock(&LibraryLock);
}

int PatchLibrary(struct Module* image, const uint8_t* pattern, const uint8_t* replacement, size_t length)
{
  struct Layout layout;
  const uint8_t* section;
  const uint8_t* owner;
  uint8_t* found;
  uint8_t* pointer;
  uint8_t* limit;
  uintptr_t first;
  uintptr_t last;
  size_t page;
  int count;

  count = 0;
  found = NULL;
  owner = NULL;
  page  = getpagesize();

  if (GetLayout(image->base, image->size, &layout) < 0)
    return -1;

  for (section = layout.sections; section < layout.sections + 40 * layout.count; section += 40)
  {
    if ((READ32(section + 36) & IMAGE_SCN_MEM_EXECUTE) == 0)
      continue;

    pointer = image->base + READ32(section + 12);
    limit   = pointer + READ32(section + 8);

    while ((pointer + length <= limit) &&
           (pointer = memmem(pointer, limit - pointer, pattern, length)))
    {
      found = pointer;
      owner = section;
      pointer ++;
      count ++;
    }
  }

  if (count != 1)
    return count;

  first = (uintptr_t)found & ~(page - 1);
  last  = ((uintptr_t)found + length + page - 1) & ~(page - 1);

  if (mprotect((void*)first, last - first, PROT_READ | PROT_WRITE) < 0)
    return -1;

  memcpy(found, replacement, length);

  if (mprotect((void*)first, last - first, GetSectionProtection(image, owner)) < 0)
    return -1;

  return count;
}

// The nearest export at or below the RVA, names only (an export by ordinal has no name to show)

static const char* FindNearestExport(struct Module* image, uint32_t rva, uint32_t* start)
{
  struct Layout layout;
  uint8_t* directory;
  uint8_t* names;
  uint8_t* ordinals;
  uint8_t* functions;
  const char* result;
  char* string;
  uint32_t address;
  uint32_t size;
  uint32_t count;
  uint32_t total;
  uint32_t number;
  uint32_t target;

  result = NULL;
  *start = 0;

  if (GetLayout(image->base, image->size, &layout) < 0)
    return NULL;

  GetDirectory(&layout, IMAGE_DIRECTORY_ENTRY_EXPORT, &address, &size);

  if ((directory = GetAddress(image, address, 40)) == NULL)
    return NULL;

  count     = READ32(directory + 24);
  total     = READ32(directory + 20);
  functions = GetAddress(image, READ32(directory + 28), 4ULL * total);
  names     = GetAddress(image, READ32(directory + 32), 4ULL * count);
  ordinals  = GetAddress(image, READ32(directory + 36), 2ULL * count);

  if ((functions == NULL) ||
      (names     == NULL) ||
      (ordinals  == NULL))
    return NULL;

  for (uint32_t index = 0; index < count; index ++)
  {
    number = READ16(ordinals + 2 * index);

    if ((number >= total) ||
        ((target = READ32(functions + 4 * number)) == 0) ||
        ((target >= address) && (target < address + size)) ||
        (target > rva) ||
        (target < *start) ||
        ((string = GetString(image, READ32(names + 4 * index))) == NULL))
      continue;

    result = string;
    *start = target;
  }

  return result;
}

int GetLibraryAddressName(const void* address, char* buffer, size_t length)
{
  struct Module* image;
  const char* name;
  uintptr_t value;
  uint32_t start;
  int result;

  value  = (uintptr_t)address;
  result = -1;

  // Called from fault handlers: no allocation, the lock is taken only when it is free

  if (pthread_mutex_trylock(&LibraryLock) != 0)
    return -1;

  for (image = Modules; (image != NULL) && (result < 0); image = image->next)
  {
    if ((value >= (uintptr_t)image->base) &&
        (value <  (uintptr_t)image->base + image->size))
    {
      if ((name = FindNearestExport(image, value - (uintptr_t)image->base, &start)) != NULL)
        snprintf(buffer, length, "%s+0x%lx (%s+0x%lx)", image->name, (unsigned long)(value - (uintptr_t)image->base), name, (unsigned long)(value - (uintptr_t)image->base - start));
      else
        snprintf(buffer, length, "%s+0x%lx", image->name, (unsigned long)(value - (uintptr_t)image->base));

      result = 0;
    }

    if ((image->thunks != NULL) &&
        (value >= (uintptr_t)image->thunks) &&
        (value <  (uintptr_t)image->thunks + image->length))
    {
      snprintf(buffer, length, "%s import thunk", image->name);
      result = 0;
    }
  }

  pthread_mutex_unlock(&LibraryLock);
  return result;
}
