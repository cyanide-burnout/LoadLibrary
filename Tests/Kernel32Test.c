#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "LoadLibrary.h"

// Calls functions of the KERNEL32.dll provider through ms_abi pointers, as Windows code would

// Through the registry: Kernel32.c registered itself as the provider of KERNEL32.dll in its constructor

static void* Find(const char* name)
{
  const struct LibraryImport* entry = FindLibraryImport("kernel32.DLL", name);

  if ((entry == NULL) ||
      (entry->function == NULL))
  {
    fprintf(stderr, "missing %s\n", name);
    exit(EXIT_FAILURE);
  }

  return entry->function;
}

#define CHECK(condition)  do { if (!(condition)) { fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #condition); failures ++; } } while (0)

static int failures = 0;
static uint8_t section[40] __attribute__((aligned(8)));
static int counter = 0;

static void* Worker(void* argument)
{
  void (LIBRARY_ABI *enter)(void*) = Find("EnterCriticalSection");
  void (LIBRARY_ABI *leave)(void*) = Find("LeaveCriticalSection");

  for (int index = 0; index < 100000; index ++)
  {
    enter(section);
    enter(section);  // recursive
    counter ++;
    leave(section);
    leave(section);
  }

  return NULL;
}

// FLS callbacks: at the exit of a prepared thread for values still set, and in FlsFree()

static uint32_t FlsIndex;
static void* FlsCalled[4];
static int FlsCount = 0;
static int32_t (LIBRARY_ABI *FlsSet)(uint32_t, void*);

static void LIBRARY_ABI FlsCallbackFunction(void* value)
{
  if (FlsCount < 4)
    FlsCalled[FlsCount ++] = value;
}

static void* FlsThread(void* argument)
{
  PrepareLibraryThread();
  FlsSet(FlsIndex, argument);
  return NULL;
}

int main()
{
  uint32_t (LIBRARY_ABI *getError)() = Find("GetLastError");
  void (LIBRARY_ABI *setError)(uint32_t) = Find("SetLastError");
  uint32_t (LIBRARY_ABI *thread)() = Find("GetCurrentThreadId");
  uint32_t (LIBRARY_ABI *process)() = Find("GetCurrentProcessId");
  uint32_t (LIBRARY_ABI *ticks)() = Find("GetTickCount");
  int32_t (LIBRARY_ABI *counterValue)(int64_t*) = Find("QueryPerformanceCounter");
  int32_t (LIBRARY_ABI *frequency)(int64_t*) = Find("QueryPerformanceFrequency");
  void (LIBRARY_ABI *sleep)(uint32_t) = Find("Sleep");
  int32_t (LIBRARY_ABI *initialize)(void*, uint32_t) = Find("InitializeCriticalSectionAndSpinCount");
  void (LIBRARY_ABI *destroy)(void*) = Find("DeleteCriticalSection");
  void* (LIBRARY_ABI *heap)() = Find("GetProcessHeap");
  void* (LIBRARY_ABI *allocate)(void*, uint32_t, size_t) = Find("HeapAlloc");
  void* (LIBRARY_ABI *reallocate)(void*, uint32_t, void*, size_t) = Find("HeapReAlloc");
  size_t (LIBRARY_ABI *measure)(void*, uint32_t, const void*) = Find("HeapSize");
  int32_t (LIBRARY_ABI *release)(void*, uint32_t, void*) = Find("HeapFree");

  setError(1234);
  CHECK(getError() == 1234);
  CHECK(thread() != 0);
  CHECK(process() != 0);

  int64_t value1, value2, rate;
  uint32_t tick1 = ticks();
  CHECK(counterValue(&value1) == 1);
  sleep(0);  // yields, returns at once
  sleep(50);
  CHECK(counterValue(&value2) == 1);
  CHECK(frequency(&rate) == 1);
  CHECK((value2 - value1) * 1000 / rate >= 50);
  CHECK(ticks() - tick1 >= 49);

  CHECK(initialize(section, 4000) == 1);
  pthread_t threads[4];
  for (int index = 0; index < 4; index ++)
    pthread_create(threads + index, NULL, Worker, NULL);
  for (int index = 0; index < 4; index ++)
    pthread_join(threads[index], NULL);
  CHECK(counter == 400000);
  destroy(section);

  void* handle = heap();
  CHECK(handle != NULL);
  uint8_t* block = allocate(handle, 0x08, 100);
  int zero = 1;
  for (int index = 0; index < 100; index ++)
    zero &= block[index] == 0;
  CHECK(zero);
  memset(block, 0xaa, 100);
  block = reallocate(handle, 0x08, block, 100000);
  CHECK(block != NULL);
  CHECK(block[99] == 0xaa);
  CHECK(block[99999] == 0);
  CHECK(reallocate(handle, 0x10, block, 1 << 30) == NULL);
  CHECK(measure(handle, 0, block) == 100000);
  CHECK(((uintptr_t)block & 15) == 0);
  CHECK(release(handle, 0, block) == 1);

  // HEAP_ZERO_MEMORY zeroes exactly from the old requested size, HeapSize returns the requested size

  block = allocate(handle, 0, 10);
  memset(block, 0xaa, 10);
  CHECK(measure(handle, 0, block) == 10);
  memset(block + 10, 0x55, 6);                                 // the slack of malloc beyond the requested size
  block = reallocate(handle, 0x08, block, 16);
  zero = 1;
  for (int index = 10; index < 16; index ++)
    zero &= block[index] == 0;
  CHECK(zero && (block[9] == 0xaa) && (measure(handle, 0, block) == 16));
  CHECK(reallocate(handle, 0, NULL, 10) == NULL);
  CHECK(measure(handle, 0, NULL) == (size_t)-1);
  CHECK(release(handle, 0, NULL) == 1);
  CHECK(release(handle, 0, block) == 1);

  uint32_t (LIBRARY_ABI *flsAllocate)(void*) = Find("FlsAlloc");
  int32_t (LIBRARY_ABI *flsFree)(uint32_t) = Find("FlsFree");
  FlsSet   = Find("FlsSetValue");
  FlsIndex = flsAllocate((void*)FlsCallbackFunction);
  CHECK(FlsIndex != 0xffffffff);

  pthread_t worker;
  pthread_create(&worker, NULL, FlsThread, (void*)0x1234);
  pthread_join(worker, NULL);
  CHECK((FlsCount == 1) && (FlsCalled[0] == (void*)0x1234));          // at the exit of the thread
  pthread_create(&worker, NULL, FlsThread, NULL);
  pthread_join(worker, NULL);
  CHECK(FlsCount == 1);                                                // not for NULL values

  CHECK(FlsSet(FlsIndex, (void*)0x5678) == 1);
  CHECK(flsFree(FlsIndex) == 1);
  CHECK((FlsCount == 2) && (FlsCalled[1] == (void*)0x5678));          // FlsFree of the calling thread

  printf("Kernel32: %s\n", failures ? "FAILED" : "ok");
  return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
