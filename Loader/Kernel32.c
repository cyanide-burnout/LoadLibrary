#define _GNU_SOURCE

#include "LoadLibrary.h"

#include <time.h>
#include <sched.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <pthread.h>
#include <fcntl.h>
#include <limits.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/syscall.h>

// KERNEL32.dll functions implemented for LoadLibrary on top of Linux, see LoadLibrary.md
// Every function is called from Windows code, so it has to be LIBRARY_ABI (ms_abi)
// Win32 types: BOOL = int32_t, DWORD = uint32_t, SIZE_T = size_t, HANDLE = void*

#define HEAP_ZERO_MEMORY             0x00000008
#define HEAP_REALLOC_IN_PLACE_ONLY   0x00000010

#define PROCESS_HEAP                 ((void*)0x48454150)  // 'HEAP', any non-NULL value

// Errors: in the TEB (LastErrorValue) as in Windows, code may read it there directly; a thread without a TEB keeps
// it in a thread-local variable

static __thread uint32_t LastError = 0;

static uint32_t LIBRARY_ABI GetLastError()
{
  uint8_t* block = GetLibraryTEB();
  return block ? *(uint32_t*)(block + LIBRARY_TEB_LAST_ERROR) : LastError;
}

static void LIBRARY_ABI SetLastError(uint32_t value)
{
  uint8_t* block = GetLibraryTEB();

  if (block != NULL)
    *(uint32_t*)(block + LIBRARY_TEB_LAST_ERROR) = value;
  else
    LastError = value;
}

#define ERROR_INVALID_HANDLE         6
#define ERROR_INSUFFICIENT_BUFFER    122
#define ERROR_MOD_NOT_FOUND          126
#define ERROR_PROC_NOT_FOUND         127

// Identifiers

static uint32_t LIBRARY_ABI GetCurrentThreadId()
{
  return (uint32_t)syscall(SYS_gettid);
}

static uint32_t LIBRARY_ABI GetCurrentProcessId()
{
  return (uint32_t)getpid();
}

// Time

static uint32_t LIBRARY_ABI GetTickCount()
{
  struct timespec time;
  clock_gettime(CLOCK_MONOTONIC, &time);
  return (uint32_t)(time.tv_sec * 1000ULL + time.tv_nsec / 1000000);
}

static int32_t LIBRARY_ABI QueryPerformanceCounter(int64_t* value)
{
  struct timespec time;
  clock_gettime(CLOCK_MONOTONIC, &time);
  *value = time.tv_sec * 1000000000LL + time.tv_nsec;
  return 1;
}

static int32_t LIBRARY_ABI QueryPerformanceFrequency(int64_t* value)
{
  *value = 1000000000LL;
  return 1;
}

static void LIBRARY_ABI Sleep(uint32_t milliseconds)
{
  struct timespec time;

  if (milliseconds == 0)
  {
    // Sleep(0) gives up the rest of the time slice
    sched_yield();
    return;
  }

  time.tv_sec  = milliseconds / 1000;
  time.tv_nsec = (milliseconds % 1000) * 1000000L;

  while ((nanosleep(&time, &time) < 0) &&
         (errno == EINTR));
}

// Critical sections: CRITICAL_SECTION of x64 is 40 bytes, exactly the size of pthread_mutex_t of glibc x86-64
// Windows critical sections are recursive

_Static_assert(sizeof(pthread_mutex_t) <= 40, "pthread_mutex_t does not fit into CRITICAL_SECTION");

static void LIBRARY_ABI InitializeCriticalSection(void* section)
{
  pthread_mutexattr_t attributes;

  pthread_mutexattr_init(&attributes);
  pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init((pthread_mutex_t*)section, &attributes);
  pthread_mutexattr_destroy(&attributes);
}

static int32_t LIBRARY_ABI InitializeCriticalSectionAndSpinCount(void* section, uint32_t count)
{
  InitializeCriticalSection(section);
  return 1;
}

static void LIBRARY_ABI EnterCriticalSection(void* section)
{
  pthread_mutex_lock((pthread_mutex_t*)section);
}

static void LIBRARY_ABI LeaveCriticalSection(void* section)
{
  pthread_mutex_unlock((pthread_mutex_t*)section);
}

static void LIBRARY_ABI DeleteCriticalSection(void* section)
{
  pthread_mutex_destroy((pthread_mutex_t*)section);
}

// Heap: one process heap on top of malloc. Every block starts with a header of 16 bytes that keeps the requested
// size: HeapSize returns it as Windows does, HEAP_ZERO_MEMORY of HeapReAlloc zeroes exactly the new tail, and the
// alignment of 16 that Windows gives on x64 is kept

#define HEAP_HEADER  16

static void* LIBRARY_ABI GetProcessHeap()
{
  return PROCESS_HEAP;
}

static void* LIBRARY_ABI HeapAlloc(void* heap, uint32_t flags, size_t size)
{
  uint8_t* block;

  if (size > SIZE_MAX - HEAP_HEADER)
    return NULL;

  block = (uint8_t*)((flags & HEAP_ZERO_MEMORY) ? calloc(1, size + HEAP_HEADER) : malloc(size + HEAP_HEADER));

  if (block == NULL)
    return NULL;

  *(size_t*)block = size;
  return block + HEAP_HEADER;
}

static int32_t LIBRARY_ABI HeapFree(void* heap, uint32_t flags, void* pointer)
{
  if (pointer != NULL)
    free((uint8_t*)pointer - HEAP_HEADER);

  return 1;
}

static void* LIBRARY_ABI HeapReAlloc(void* heap, uint32_t flags, void* pointer, size_t size)
{
  uint8_t* block;
  size_t length;

  if ((pointer == NULL) ||
      (size > SIZE_MAX - HEAP_HEADER))
    return NULL;

  block  = (uint8_t*)pointer - HEAP_HEADER;
  length = *(size_t*)block;

  if (flags & HEAP_REALLOC_IN_PLACE_ONLY)
  {
    if (size + HEAP_HEADER > malloc_usable_size(block))
      return NULL;
  }
  else if ((block = (uint8_t*)realloc(block, size + HEAP_HEADER)) == NULL)
  {
    return NULL;
  }

  if ((flags & HEAP_ZERO_MEMORY) &&
      (size  > length))
    memset(block + HEAP_HEADER + length, 0, size - length);

  *(size_t*)block = size;
  return block + HEAP_HEADER;
}

static void* LIBRARY_ABI HeapCreate(uint32_t options, size_t initial, size_t maximum)
{
  // All heaps are the one of the process, HeapDestroy() leaves their blocks as they are
  return PROCESS_HEAP;
}

static int32_t LIBRARY_ABI HeapDestroy(void* heap)
{
  return 1;
}

static int32_t LIBRARY_ABI HeapSetInformation(void* heap, uint32_t type, void* information, size_t length)
{
  return 1;
}

static size_t LIBRARY_ABI HeapSize(void* heap, uint32_t flags, const void* pointer)
{
  if (pointer == NULL)
    return (size_t)-1;

  return *(const size_t*)((const uint8_t*)pointer - HEAP_HEADER);
}

// Dynamic TLS (TlsAlloc): slots of the TEB, as in Windows, code may read them there directly; a thread without a TEB
// keeps them in a thread-local array. FLS (FlsAlloc) lives in a thread-local array, its callbacks run at the exit of
// a prepared thread for values that are still set, and in FlsFree() for the value of the calling thread

#define TLS_OUT_OF_INDEXES           0xffffffff
#define FLS_SLOT_COUNT               128

static pthread_mutex_t SlotLock = PTHREAD_MUTEX_INITIALIZER;
static uint8_t TlsTaken[LIBRARY_TEB_TLS_SLOT_COUNT];
static uint8_t FlsTaken[FLS_SLOT_COUNT];
static __thread void* TlsValues[LIBRARY_TEB_TLS_SLOT_COUNT];
static __thread void* FlsValues[FLS_SLOT_COUNT];
static void* FlsCallbacks[FLS_SLOT_COUNT];

typedef void (LIBRARY_ABI *FlsCallback)(void* value);

static void CallFlsCallback(uint32_t index)
{
  void* value = FlsValues[index];

  if ((value != NULL) &&
      (FlsCallbacks[index] != NULL))
  {
    FlsValues[index] = NULL;
    ((FlsCallback)FlsCallbacks[index])(value);
  }
}

static void ReleaseFlsValues()
{
  for (uint32_t index = 0; index < FLS_SLOT_COUNT; index ++)
    CallFlsCallback(index);
}

static uint32_t AllocateSlot(uint8_t* taken, uint32_t count)
{
  uint32_t index;

  pthread_mutex_lock(&SlotLock);
  for (index = 0; (index < count) && (taken[index] != 0); index ++);
  if (index < count)
    taken[index] = 1;
  pthread_mutex_unlock(&SlotLock);

  return (index < count) ? index : TLS_OUT_OF_INDEXES;
}

static void** GetTlsSlot(uint32_t index)
{
  uint8_t* block = GetLibraryTEB();
  return block ? (void**)(block + LIBRARY_TEB_TLS_SLOTS) + index : TlsValues + index;
}

static uint32_t LIBRARY_ABI TlsAlloc()
{
  return AllocateSlot(TlsTaken, LIBRARY_TEB_TLS_SLOT_COUNT);
}

static void* LIBRARY_ABI TlsGetValue(uint32_t index)
{
  if (index >= LIBRARY_TEB_TLS_SLOT_COUNT)
    return NULL;

  // Windows clears the last error on success
  SetLastError(0);
  return *GetTlsSlot(index);
}

static int32_t LIBRARY_ABI TlsSetValue(uint32_t index, void* value)
{
  if (index >= LIBRARY_TEB_TLS_SLOT_COUNT)
    return 0;

  *GetTlsSlot(index) = value;
  return 1;
}

static int32_t LIBRARY_ABI TlsFree(uint32_t index)
{
  if (index >= LIBRARY_TEB_TLS_SLOT_COUNT)
    return 0;

  *GetTlsSlot(index) = NULL;
  TlsTaken[index]    = 0;
  return 1;
}

static uint32_t LIBRARY_ABI FlsAlloc(void* callback)
{
  uint32_t index = AllocateSlot(FlsTaken, FLS_SLOT_COUNT);

  if (index != TLS_OUT_OF_INDEXES)
    FlsCallbacks[index] = callback;

  return index;
}

static void* LIBRARY_ABI FlsGetValue(uint32_t index)
{
  return (index < FLS_SLOT_COUNT) ? FlsValues[index] : NULL;
}

static int32_t LIBRARY_ABI FlsSetValue(uint32_t index, void* value)
{
  if (index >= FLS_SLOT_COUNT)
    return 0;

  FlsValues[index] = value;
  return 1;
}

static int32_t LIBRARY_ABI FlsFree(uint32_t index)
{
  if (index >= FLS_SLOT_COUNT)
    return 0;

  CallFlsCallback(index);

  FlsValues[index]    = NULL;
  FlsCallbacks[index] = NULL;
  FlsTaken[index]     = 0;
  return 1;
}

// Modules: KERNEL32.dll is a handle of its own, other handles are bases of images loaded by LoadLibrary

static const char Kernel32Module[] = "KERNEL32.dll";
static const char ProcessModule[]  = "process";

static int IsKernel32(const char* name)
{
  return (strcasecmp(name, "KERNEL32.dll") == 0) || (strcasecmp(name, "KERNEL32") == 0);
}

static const void* FindModuleHandle(const char* name)
{
  struct Module* image;

  if (name == NULL)
    return ProcessModule;

  if (IsKernel32(name))
    return Kernel32Module;

  if ((image = GetLibraryByName(name)) != NULL)
    return image->base;

  SetLastError(ERROR_MOD_NOT_FOUND);
  return NULL;
}

static const void* LIBRARY_ABI GetModuleHandleA(const char* name)
{
  return FindModuleHandle(name);
}

static const void* LIBRARY_ABI GetModuleHandleW(const uint16_t* name)
{
  char buffer[256];
  size_t index;

  if (name == NULL)
    return FindModuleHandle(NULL);

  // Names of modules are ASCII
  for (index = 0; (name[index] != 0) && (index < sizeof(buffer) - 1); index ++)
    buffer[index] = (name[index] < 0x80) ? (char)name[index] : '?';
  buffer[index] = '\0';

  return FindModuleHandle(buffer);
}

static void* LIBRARY_ABI WinGetProcAddress(const void* module, const char* name)
{
  const struct LibraryImport* entry;
  struct Module* image;
  void* function;

  function = NULL;

  if (module == Kernel32Module)
  {
    if ((uintptr_t)name >= 0x10000)
    {
      entry    = FindLibraryImport(Kernel32Module, name);
      function = entry ? entry->function : NULL;
    }
  }
  else if ((image = GetLibraryByAddress(module)) != NULL)
  {
    function = GetProcAddress(image, name);
  }

  if (function == NULL)
    SetLastError(ERROR_PROC_NOT_FOUND);

  return function;
}

static uint32_t LIBRARY_ABI GetModuleFileNameA(const void* module, char* buffer, uint32_t size)
{
  struct Module* image;
  char path[PATH_MAX];
  ssize_t length;

  if (size == 0)
    return 0;

  if ((module == NULL) ||
      (module == ProcessModule))
  {
    length = readlink("/proc/self/exe", path, sizeof(path) - 1);
    path[(length > 0) ? length : 0] = '\0';
  }
  else if (module == Kernel32Module)
  {
    snprintf(path, sizeof(path), "%s", Kernel32Module);
  }
  else if ((image = GetLibraryByAddress(module)) != NULL)
  {
    snprintf(path, sizeof(path), "%s/%s", image->directory, image->name);
  }
  else
  {
    SetLastError(ERROR_MOD_NOT_FOUND);
    return 0;
  }

  length = strlen(path);

  if ((size_t)length >= size)
  {
    // Truncated as Windows does: size - 1 characters, the result is size
    memcpy(buffer, path, size - 1);
    buffer[size - 1] = '\0';
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return size;
  }

  memcpy(buffer, path, length + 1);
  return (uint32_t)length;
}

static int32_t LIBRARY_ABI DisableThreadLibraryCalls(const void* module)
{
  return SetLibraryThreadCalls(module, 0) == 0;
}

// Process: what the startup code of the CRT asks for

static int32_t LIBRARY_ABI IsDebuggerPresent()
{
  return 0;
}

static void* LIBRARY_ABI GetCurrentProcess()
{
  return (void*)(intptr_t)-1;
}

static const char* LIBRARY_ABI GetCommandLineA()
{
  return program_invocation_name;
}

static void LIBRARY_ABI GetStartupInfoA(uint8_t* information)
{
  // STARTUPINFOA of x64 is 104 bytes, cb first; no redirected handles
  memset(information, 0, 104);
  *(uint32_t*)information = 104;
}

static const char EmptyEnvironment[2]      = { 0, 0 };
static const uint16_t EmptyEnvironmentW[2] = { 0, 0 };

static const char* LIBRARY_ABI GetEnvironmentStrings()
{
  // The environment of the process stays out of the DLL
  return EmptyEnvironment;
}

static const uint16_t* LIBRARY_ABI GetEnvironmentStringsW()
{
  return EmptyEnvironmentW;
}

static int32_t LIBRARY_ABI FreeEnvironmentStringsA(const char* strings)
{
  return 1;
}

static int32_t LIBRARY_ABI FreeEnvironmentStringsW(const uint16_t* strings)
{
  return 1;
}

static void* LIBRARY_ABI EncodePointer(void* pointer)
{
  return pointer;
}

static void* LIBRARY_ABI DecodePointer(void* pointer)
{
  return pointer;
}

static void* ExceptionFilter = NULL;

static void* LIBRARY_ABI SetUnhandledExceptionFilter(void* filter)
{
  void* previous  = ExceptionFilter;
  ExceptionFilter = filter;
  return previous;
}

static int32_t LIBRARY_ABI UnhandledExceptionFilter(void* information)
{
  // EXCEPTION_CONTINUE_SEARCH
  return 0;
}

static void LIBRARY_ABI __attribute__((noreturn)) ExitProcess(uint32_t code)
{
  // The CRT calls it on a fatal error: the DLL must not end the host process quietly
  dprintf(STDERR_FILENO, "PE image called ExitProcess(%u), aborting\n", code);
  abort();
}

static int32_t LIBRARY_ABI TerminateProcess(void* process, uint32_t code)
{
  if (process != GetCurrentProcess())
    return 0;

  dprintf(STDERR_FILENO, "PE image called TerminateProcess(%u), aborting\n", code);
  abort();
}

static void LIBRARY_ABI GetSystemTimeAsFileTime(uint64_t* value)
{
  struct timespec time;

  // 100 ns since 1601-01-01
  clock_gettime(CLOCK_REALTIME, &time);
  *value = (uint64_t)time.tv_sec * 10000000ULL + time.tv_nsec / 100 + 116444736000000000ULL;
}

// Handles of standard streams: file descriptors behind small values, as Windows handles are

#define STD_INPUT_HANDLE             ((uint32_t)-10)
#define STD_OUTPUT_HANDLE            ((uint32_t)-11)
#define STD_ERROR_HANDLE             ((uint32_t)-12)
#define HANDLE_BASE                  0x100
#define FILE_TYPE_UNKNOWN            0
#define FILE_TYPE_DISK               1
#define FILE_TYPE_CHAR               2
#define FILE_TYPE_PIPE               3

static int GetDescriptor(const void* handle)
{
  intptr_t value = (intptr_t)handle - HANDLE_BASE;
  return ((value >= 0) && (value <= 2)) ? (int)value : -1;
}

static void* LIBRARY_ABI GetStdHandle(uint32_t number)
{
  switch (number)
  {
    case STD_INPUT_HANDLE:   return (void*)(intptr_t)(HANDLE_BASE + STDIN_FILENO);
    case STD_OUTPUT_HANDLE:  return (void*)(intptr_t)(HANDLE_BASE + STDOUT_FILENO);
    case STD_ERROR_HANDLE:   return (void*)(intptr_t)(HANDLE_BASE + STDERR_FILENO);
  }

  SetLastError(ERROR_INVALID_HANDLE);
  return (void*)(intptr_t)-1;
}

static uint32_t LIBRARY_ABI GetFileType(void* handle)
{
  struct stat status;
  int descriptor;

  if (((descriptor = GetDescriptor(handle)) < 0) ||
      (fstat(descriptor, &status) < 0))
    return FILE_TYPE_UNKNOWN;

  if (S_ISREG(status.st_mode))
    return FILE_TYPE_DISK;
  if (S_ISCHR(status.st_mode))
    return FILE_TYPE_CHAR;
  if (S_ISFIFO(status.st_mode) || S_ISSOCK(status.st_mode))
    return FILE_TYPE_PIPE;

  return FILE_TYPE_UNKNOWN;
}

static uint32_t LIBRARY_ABI SetHandleCount(uint32_t count)
{
  return count;
}

static int32_t LIBRARY_ABI WriteFile(void* handle, const void* data, uint32_t length, uint32_t* written, void* overlapped)
{
  ssize_t result;
  int descriptor;

  if ((descriptor = GetDescriptor(handle)) < 0)
  {
    SetLastError(ERROR_INVALID_HANDLE);
    return 0;
  }

  result = write(descriptor, data, length);

  if (written != NULL)
    *written = (result > 0) ? (uint32_t)result : 0;

  return result >= 0;
}

// Code pages: Windows-1252 as the ANSI page, 437 as the OEM page, UTF-8 (65001); characters above 0xff become
// the default character outside UTF-8

#define CP_UTF8                      65001

static uint32_t LIBRARY_ABI GetACP()
{
  return 1252;
}

static uint32_t LIBRARY_ABI GetOEMCP()
{
  return 437;
}

static uint32_t LIBRARY_ABI GetThreadLocale()
{
  // en-US
  return 0x0409;
}

static int32_t LIBRARY_ABI IsValidCodePage(uint32_t page)
{
  return (page == 1252) || (page == 437) || (page == CP_UTF8);
}

static int32_t LIBRARY_ABI GetCPInfo(uint32_t page, uint8_t* information)
{
  // CPINFO: MaxCharSize, DefaultChar[2], LeadByte[12]
  memset(information, 0, 20);
  *(uint32_t*)information = (page == CP_UTF8) ? 4 : 1;
  information[4] = '?';
  return 1;
}

static int32_t LIBRARY_ABI WideCharToMultiByte(uint32_t page, uint32_t flags, const uint16_t* input, int32_t length, char* output, int32_t size, const char* fallback, int32_t* used)
{
  char buffer[4];
  uint32_t code;
  int32_t count;
  int32_t width;

  if (length < 0)
  {
    // A terminated string, the terminator is a part of the result
    for (length = 0; input[length] != 0; length ++);
    length ++;
  }

  count = 0;

  for (int32_t index = 0; index < length; index ++)
  {
    code  = input[index];
    width = 1;

    if (page == CP_UTF8)
    {
      if ((code >= 0xd800) && (code < 0xdc00) && (index + 1 < length) && (input[index + 1] >= 0xdc00) && (input[index + 1] < 0xe000))
      {
        code = 0x10000 + ((code - 0xd800) << 10) + (input[index + 1] - 0xdc00);
        index ++;
      }

      if (code < 0x80)
      {
        buffer[0] = code;
      }
      else if (code < 0x800)
      {
        width     = 2;
        buffer[0] = 0xc0 | (code >> 6);
        buffer[1] = 0x80 | (code & 0x3f);
      }
      else if (code < 0x10000)
      {
        width     = 3;
        buffer[0] = 0xe0 | (code >> 12);
        buffer[1] = 0x80 | ((code >> 6) & 0x3f);
        buffer[2] = 0x80 | (code & 0x3f);
      }
      else
      {
        width     = 4;
        buffer[0] = 0xf0 | (code >> 18);
        buffer[1] = 0x80 | ((code >> 12) & 0x3f);
        buffer[2] = 0x80 | ((code >> 6) & 0x3f);
        buffer[3] = 0x80 | (code & 0x3f);
      }
    }
    else
    {
      buffer[0] = (code < 0x100) ? (char)code : (fallback ? *fallback : '?');

      if ((code >= 0x100) && (used != NULL))
        *used = 1;
    }

    if (size != 0)
    {
      if (count + width > size)
      {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
      }

      memcpy(output + count, buffer, width);
    }

    count += width;
  }

  return count;
}

static int32_t LIBRARY_ABI MultiByteToWideChar(uint32_t page, uint32_t flags, const uint8_t* input, int32_t length, uint16_t* output, int32_t size)
{
  uint32_t code;
  int32_t count;
  int32_t extra;
  int32_t width;

  if (length < 0)
  {
    for (length = 0; input[length] != 0; length ++);
    length ++;
  }

  count = 0;

  for (int32_t index = 0; index < length; index ++)
  {
    code = input[index];

    if ((page == CP_UTF8) && (code >= 0xc0))
    {
      extra = (code >= 0xf0) ? 3 : (code >= 0xe0) ? 2 : 1;
      code &= 0x3f >> extra;

      for (int32_t part = 0; (part < extra) && (index + 1 < length); part ++)
        code = (code << 6) | (input[++ index] & 0x3f);
    }

    width = (code >= 0x10000) ? 2 : 1;

    if (size != 0)
    {
      if (count + width > size)
      {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
      }

      if (width == 2)
      {
        output[count]     = 0xd800 + ((code - 0x10000) >> 10);
        output[count + 1] = 0xdc00 + ((code - 0x10000) & 0x3ff);
      }
      else
      {
        output[count] = (uint16_t)code;
      }
    }

    count += width;
  }

  return count;
}

// Character types and case mapping of Latin-1 (Windows-1252 below 0x80 and 0xa0-0xff), what the CRT builds its
// tables of with; characters above 0xff have no type and map to themselves

#define CT_CTYPE1                    1
#define C1_UPPER                     0x0001
#define C1_LOWER                     0x0002
#define C1_DIGIT                     0x0004
#define C1_SPACE                     0x0008
#define C1_PUNCT                     0x0010
#define C1_CNTRL                     0x0020
#define C1_BLANK                     0x0040
#define C1_XDIGIT                    0x0080
#define C1_ALPHA                     0x0100
#define C1_DEFINED                   0x0200
#define LCMAP_LOWERCASE              0x00000100
#define LCMAP_UPPERCASE              0x00000200

static uint16_t GetCharacterType(uint32_t code)
{
  uint16_t type;

  if (code >= 0x100)
    return 0;

  type = C1_DEFINED;

  if (((code >= 'A') && (code <= 'Z')) || ((code >= 0xc0) && (code <= 0xde) && (code != 0xd7)))
    type |= C1_UPPER | C1_ALPHA;
  if (((code >= 'a') && (code <= 'z')) || ((code >= 0xdf) && (code != 0xf7)))
    type |= C1_LOWER | C1_ALPHA;
  if ((code >= '0') && (code <= '9'))
    type |= C1_DIGIT;
  if (((code >= '0') && (code <= '9')) || ((code >= 'A') && (code <= 'F')) || ((code >= 'a') && (code <= 'f')))
    type |= C1_XDIGIT;
  if (((code >= 0x09) && (code <= 0x0d)) || (code == ' ') || (code == 0xa0))
    type |= C1_SPACE;
  if ((code == ' ') || (code == '\t') || (code == 0xa0))
    type |= C1_BLANK;
  if ((code < 0x20) || (code == 0x7f) || ((code >= 0x80) && (code < 0xa0)))
    type |= C1_CNTRL;
  if ((((code >= 0x21) && (code <= 0x7e)) || ((code >= 0xa1) && (code <= 0xbf)) || (code == 0xd7) || (code == 0xf7)) && !(type & (C1_ALPHA | C1_DIGIT)))
    type |= C1_PUNCT;

  return type;
}

static uint32_t MapCharacter(uint32_t code, uint32_t flags)
{
  if ((flags & LCMAP_LOWERCASE) && (GetCharacterType(code) & C1_UPPER))
    return code + 0x20;
  if ((flags & LCMAP_UPPERCASE) && (GetCharacterType(code) & C1_LOWER) && (code != 0xdf) && (code != 0xff))
    return code - 0x20;

  return code;
}

static int32_t LIBRARY_ABI GetStringTypeW(uint32_t kind, const uint16_t* input, int32_t length, uint16_t* types)
{
  if (length < 0)
    for (length = 0; input[length] != 0; length ++);

  for (int32_t index = 0; index < length; index ++)
    types[index] = (kind == CT_CTYPE1) ? GetCharacterType(input[index]) : 0;

  return 1;
}

static int32_t LIBRARY_ABI GetStringTypeA(uint32_t locale, uint32_t kind, const uint8_t* input, int32_t length, uint16_t* types)
{
  if (length < 0)
    for (length = 0; input[length] != 0; length ++);

  for (int32_t index = 0; index < length; index ++)
    types[index] = (kind == CT_CTYPE1) ? GetCharacterType(input[index]) : 0;

  return 1;
}

static int32_t LIBRARY_ABI LCMapStringW(uint32_t locale, uint32_t flags, const uint16_t* input, int32_t length, uint16_t* output, int32_t size)
{
  if (length < 0)
  {
    for (length = 0; input[length] != 0; length ++);
    length ++;
  }

  if (size == 0)
    return length;

  if (size < length)
  {
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return 0;
  }

  for (int32_t index = 0; index < length; index ++)
    output[index] = (uint16_t)MapCharacter(input[index], flags);

  return length;
}

static int32_t LIBRARY_ABI LCMapStringA(uint32_t locale, uint32_t flags, const uint8_t* input, int32_t length, uint8_t* output, int32_t size)
{
  if (length < 0)
  {
    for (length = 0; input[length] != 0; length ++);
    length ++;
  }

  if (size == 0)
    return length;

  if (size < length)
  {
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return 0;
  }

  for (int32_t index = 0; index < length; index ++)
    output[index] = (uint8_t)MapCharacter(input[index], flags);

  return length;
}

// Locale: en-US with the code pages above, other items are empty strings

#define LOCALE_IDEFAULTCODEPAGE      0x0000000b
#define LOCALE_IDEFAULTANSICODEPAGE  0x00001004
#define LOCALE_RETURN_NUMBER         0x20000000

static int32_t LIBRARY_ABI GetLocaleInfoA(uint32_t locale, uint32_t type, char* output, int32_t size)
{
  const char* value;
  int32_t length;

  switch (type & ~LOCALE_RETURN_NUMBER)
  {
    case LOCALE_IDEFAULTCODEPAGE:      value = "437";  break;
    case LOCALE_IDEFAULTANSICODEPAGE:  value = "1252"; break;
    default:                           value = "";     break;
  }

  if (type & LOCALE_RETURN_NUMBER)
  {
    // A DWORD instead of a string, its length is counted in characters
    if (size == 0)
      return sizeof(uint32_t);
    if (size < (int32_t)sizeof(uint32_t))
      return 0;
    *(uint32_t*)output = (uint32_t)strtoul(value, NULL, 10);
    return sizeof(uint32_t);
  }

  length = strlen(value) + 1;

  if (size == 0)
    return length;

  if (size < length)
  {
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return 0;
  }

  memcpy(output, value, length);
  return length;
}

// Nothing outside refers to the table: the provider registers it when the object is loaded

static const struct LibraryImport Kernel32Imports[] =
{
  LIBRARY_IMPORT(GetLastError),
  LIBRARY_IMPORT(SetLastError),
  LIBRARY_IMPORT(GetCurrentThreadId),
  LIBRARY_IMPORT(GetCurrentProcessId),
  LIBRARY_IMPORT(GetTickCount),
  LIBRARY_IMPORT(QueryPerformanceCounter),
  LIBRARY_IMPORT(QueryPerformanceFrequency),
  LIBRARY_IMPORT(Sleep),
  LIBRARY_IMPORT(InitializeCriticalSection),
  LIBRARY_IMPORT(InitializeCriticalSectionAndSpinCount),
  LIBRARY_IMPORT(EnterCriticalSection),
  LIBRARY_IMPORT(LeaveCriticalSection),
  LIBRARY_IMPORT(DeleteCriticalSection),
  LIBRARY_IMPORT(GetProcessHeap),
  LIBRARY_IMPORT(HeapAlloc),
  LIBRARY_IMPORT(HeapFree),
  LIBRARY_IMPORT(HeapReAlloc),
  LIBRARY_IMPORT(HeapSize),
  LIBRARY_IMPORT(HeapCreate),
  LIBRARY_IMPORT(HeapDestroy),
  LIBRARY_IMPORT(HeapSetInformation),
  LIBRARY_IMPORT(TlsAlloc),
  LIBRARY_IMPORT(TlsGetValue),
  LIBRARY_IMPORT(TlsSetValue),
  LIBRARY_IMPORT(TlsFree),
  LIBRARY_IMPORT(FlsAlloc),
  LIBRARY_IMPORT(FlsGetValue),
  LIBRARY_IMPORT(FlsSetValue),
  LIBRARY_IMPORT(FlsFree),
  LIBRARY_IMPORT(GetModuleHandleA),
  LIBRARY_IMPORT(GetModuleHandleW),
  { "GetProcAddress", (void*)WinGetProcAddress },
  LIBRARY_IMPORT(GetModuleFileNameA),
  LIBRARY_IMPORT(DisableThreadLibraryCalls),
  LIBRARY_IMPORT(IsDebuggerPresent),
  LIBRARY_IMPORT(GetCurrentProcess),
  LIBRARY_IMPORT(GetCommandLineA),
  LIBRARY_IMPORT(GetStartupInfoA),
  LIBRARY_IMPORT(GetEnvironmentStrings),
  LIBRARY_IMPORT(GetEnvironmentStringsW),
  LIBRARY_IMPORT(FreeEnvironmentStringsA),
  LIBRARY_IMPORT(FreeEnvironmentStringsW),
  LIBRARY_IMPORT(EncodePointer),
  LIBRARY_IMPORT(DecodePointer),
  LIBRARY_IMPORT(SetUnhandledExceptionFilter),
  LIBRARY_IMPORT(UnhandledExceptionFilter),
  LIBRARY_IMPORT(ExitProcess),
  LIBRARY_IMPORT(TerminateProcess),
  LIBRARY_IMPORT(GetSystemTimeAsFileTime),
  LIBRARY_IMPORT(GetStdHandle),
  LIBRARY_IMPORT(GetFileType),
  LIBRARY_IMPORT(SetHandleCount),
  LIBRARY_IMPORT(WriteFile),
  LIBRARY_IMPORT(GetACP),
  LIBRARY_IMPORT(GetOEMCP),
  LIBRARY_IMPORT(GetThreadLocale),
  LIBRARY_IMPORT(IsValidCodePage),
  LIBRARY_IMPORT(GetCPInfo),
  LIBRARY_IMPORT(WideCharToMultiByte),
  LIBRARY_IMPORT(MultiByteToWideChar),
  LIBRARY_IMPORT(GetStringTypeW),
  LIBRARY_IMPORT(GetStringTypeA),
  LIBRARY_IMPORT(LCMapStringW),
  LIBRARY_IMPORT(LCMapStringA),
  LIBRARY_IMPORT(GetLocaleInfoA),
  { NULL, NULL }
};

LIBRARY_PROVIDER(Kernel32Provider, "KERNEL32.dll", Kernel32Imports)

// The heap of the process in the PEB, as GetProcessHeap() returns it, and FLS callbacks at the exit of threads

static void __attribute__((constructor)) InitializeKernel32()
{
  *(void**)(GetLibraryPEB() + LIBRARY_PEB_PROCESS_HEAP) = PROCESS_HEAP;
  RegisterLibraryThreadExit(ReleaseFlsValues);
}
