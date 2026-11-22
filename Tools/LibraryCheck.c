// loadlibrary-check: whether a DLL fits LoadLibrary, and why not
//
//   loadlibrary-check [--attach] <dll>
//
// The DLL is loaded by the real loader with the registered providers (Kernel32.c), so the verdict about loading is
// what a module would get. Unresolved imports are grouped: beyond the line (Wine) or candidates for a provider.
// --attach also runs DllMain (AttachLibrary) in a child process and tells how it ended; the exit status is 1 when
// the DLL does not load or DllMain does not pass, 2 on wrong arguments, 0 otherwise.
// Which unresolved imports the needed exports can actually reach is told by LibraryCheck.py

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include "LoadLibrary.h"

#define CATEGORY_DYNAMIC_CRT  0
#define CATEGORY_SUBSYSTEM    1
#define CATEGORY_EXCEPTIONS   2
#define CATEGORY_FILES        3
#define CATEGORY_PROVIDER     4
#define CATEGORY_COUNT        5

static const char* CategoryNames[CATEGORY_COUNT] =
{
  "dynamic CRT (beyond the line: Wine)",
  "Windows subsystems (beyond the line: Wine)",
  "exceptions and unwinding (beyond the line: Wine, unless only __report_gsfailure reaches them)",
  "files, consoles, registry (beyond the line: Wine, unless a few are worth a provider)",
  "missing in providers (can be added to Kernel32.c or a provider of its own)"
};

static const char* DynamicCRT[] = { "vcruntime", "msvcp", "msvcr", "ucrtbase", "api-ms-win-crt-", "concrt", NULL };
static const char* Subsystems[] = { "user32", "gdi32", "advapi32", "ole32", "oleaut32", "shell32", "ws2_32", "winmm", "comdlg32", "comctl32", "shlwapi", "crypt32", "bcrypt", "ntdll", NULL };
static const char* Exceptions[] = { "RaiseException", "RtlUnwind", "RtlUnwindEx", "RtlVirtualUnwind", "RtlLookupFunctionEntry", "RtlCaptureContext", "RtlRestoreContext", "_CxxThrowException", "__CxxFrameHandler", "__C_specific_handler", NULL };
static const char* Files[] = { "CreateFile", "ReadFile", "WriteConsole", "GetConsole", "SetConsole", "SetFilePointer", "FlushFileBuffers", "CloseHandle", "FindFirstFile", "FindNextFile", "FindClose", "DeleteFile", "GetFileAttributes", "SetStdHandle", "Reg", "GetFileSize", "CreateDirectory", NULL };

struct Entry
{
  char module[64];
  char name[96];
  int category;
};

static struct Entry Entries[4096];
static int EntryCount = 0;

static char Messages[16384];
static size_t MessageLength = 0;
static int Direct = 0;

static void Report(int priority, const char* format, ...)
{
  va_list arguments;
  int length;

  if (Direct)
  {
    // In the child of --attach: an abort of a thunk must not lose its message
    va_start(arguments, format);
    vdprintf(STDERR_FILENO, format, arguments);
    va_end(arguments);
    return;
  }

  va_start(arguments, format);
  length = vsnprintf(Messages + MessageLength, sizeof(Messages) - MessageLength, format, arguments);
  va_end(arguments);

  if ((length > 0) &&
      (MessageLength + length < sizeof(Messages)))
    MessageLength += length;
}

static int StartsWith(const char* string, const char* const* prefixes)
{
  for (; *prefixes != NULL; prefixes ++)
    if (strncasecmp(string, *prefixes, strlen(*prefixes)) == 0)
      return 1;

  return 0;
}

static void CollectImport(const char* module, const char* name, void* context)
{
  struct Entry* entry;

  if (EntryCount >= (int)(sizeof(Entries) / sizeof(Entries[0])))
    return;

  entry = Entries + EntryCount ++;
  snprintf(entry->module, sizeof(entry->module), "%s", module);

  if ((uintptr_t)name < 0x10000)
    snprintf(entry->name, sizeof(entry->name), "#%u", (unsigned int)(uintptr_t)name);
  else
    snprintf(entry->name, sizeof(entry->name), "%s", name);

  if (StartsWith(entry->module, DynamicCRT))
    entry->category = CATEGORY_DYNAMIC_CRT;
  else if (StartsWith(entry->module, Subsystems))
    entry->category = CATEGORY_SUBSYSTEM;
  else if (StartsWith(entry->name, Exceptions))
    entry->category = CATEGORY_EXCEPTIONS;
  else if (StartsWith(entry->name, Files))
    entry->category = CATEGORY_FILES;
  else
    entry->category = CATEGORY_PROVIDER;
}

#define MODULE_COUNT  256

static void CollectModule(struct Module* image, struct Module** visited, int* count, int* skipped)
{
  for (int index = 0; index < *count; index ++)
    if (visited[index] == image)
      return;

  if (*count >= MODULE_COUNT)
  {
    (*skipped) ++;
    return;
  }

  visited[(*count) ++] = image;
  GetLibraryUnresolvedImports(image, CollectImport, NULL);

  for (size_t index = 0; index < image->number; index ++)
    CollectModule(image->dependencies[index], visited, count, skipped);
}

// DllMain in a child: the exit code tells the result, aborts of thunks come through stderr.
// The pipe is read to the end, so a child that writes more than the buffer does not block; the rest is dropped

static int Attach(struct Module* image)
{
  char output[8192];
  char rest[4096];
  int pipes[2];
  pid_t process;
  ssize_t length;
  size_t dropped;
  size_t total;
  int status;

  fflush(stdout);

  if ((pipe(pipes) < 0) ||
      ((process = fork()) < 0))
  {
    printf("DllMain:      not checked, %s\n", strerror(errno));
    return -1;
  }

  if (process == 0)
  {
    dup2(pipes[1], STDERR_FILENO);
    Direct = 1;
    _exit((AttachLibrary(image) == 0) ? 0 : 2);
  }

  close(pipes[1]);
  total   = 0;
  dropped = 0;
  while ((total + 1 < sizeof(output)) && ((length = read(pipes[0], output + total, sizeof(output) - total - 1)) > 0))
    total += length;
  while ((length = read(pipes[0], rest, sizeof(rest))) > 0)
    dropped += length;
  output[total] = '\0';
  close(pipes[0]);

  if (waitpid(process, &status, 0) < 0)
  {
    printf("DllMain:      not checked, %s\n", strerror(errno));
    return -1;
  }

  if (WIFEXITED(status) && (WEXITSTATUS(status) == 0))
    printf("DllMain:      OK (TLS callbacks and DllMain with DLL_PROCESS_ATTACH passed)\n");
  else if (WIFEXITED(status))
    printf("DllMain:      returned FALSE\n");
  else
    printf("DllMain:      killed by signal %d (%s)\n", WTERMSIG(status), strsignal(WTERMSIG(status)));

  if (total > 0)
    printf("%s", output);
  if (dropped > 0)
    printf("              (%zu more bytes of output dropped)\n", dropped);

  return (WIFEXITED(status) && (WEXITSTATUS(status) == 0)) ? 0 : -1;
}

int main(int argc, char** argv)
{
  struct Module* image;
  struct Module* visited[256];
  const char* path;
  int attach;
  int result;
  int count;
  int skipped;
  int totals[CATEGORY_COUNT] = { 0 };

  attach = (argc > 2) && (strcmp(argv[1], "--attach") == 0);
  path   = argv[1 + attach];

  if ((argc < 2) ||
      (path == NULL))
  {
    fprintf(stderr, "usage: loadlibrary-check [--attach] <dll>\n");
    return 2;
  }

  printf("DLL:          %s\n", path);

  if ((image = LoadLibrary(path, NULL, Report)) == NULL)
  {
    int error = GetLibraryLastError();

    printf("Load:         FAILED, %s\n", GetLibraryErrorText(error));
    if (MessageLength > 0)
      printf("%s", Messages);
    printf("Verdict:      does not fit%s\n", (error == LIBRARY_ERROR_ADDRESS_AWARE) ? ", use Wine" : "");
    return 1;
  }

  printf("Load:         OK at %p, %zu bytes\n", (void*)image->base, image->size);
  printf("DllMain:      %s\n", image->entry ? "present (AttachLibrary runs it with the startup of its CRT)" : "none");
  printf("Static TLS:   %s\n", (image->slot >= 0) ? "yes" : "no");

  if (MessageLength > 0)
    printf("%s", Messages);

  count   = 0;
  skipped = 0;
  CollectModule(image, visited, &count, &skipped);

  if (count > 1)
  {
    printf("Dependencies:");
    for (int index = 1; index < count; index ++)
      printf(" %s", visited[index]->name);
    if (skipped > 0)
      printf(" and %d more, not checked", skipped);
    printf("\n");
  }

  printf("Unresolved:   %d imports (they abort with their name when called)\n", EntryCount);

  for (int category = 0; category < CATEGORY_COUNT; category ++)
  {
    for (int index = 0; index < EntryCount; index ++)
    {
      if (Entries[index].category != category)
        continue;

      if (totals[category] ++ == 0)
        printf("  %s:\n", CategoryNames[category]);

      printf("    %s!%s\n", Entries[index].module, Entries[index].name);
    }
  }

  result = 0;
  if (attach &&
      (Attach(image) < 0))
    result = 1;

  if (result != 0)
    printf("Verdict:      loads, but DllMain does not pass (see above)\n");
  else if (totals[CATEGORY_DYNAMIC_CRT] + totals[CATEGORY_SUBSYSTEM] > 0)
    printf("Verdict:      beyond the line, use Wine (imports of the dynamic CRT or of Windows subsystems)\n");
  else if (EntryCount > 0)
    printf("Verdict:      loads; unresolved imports abort only when called. Check which ones the exports you need reach:\n"
           "              LibraryCheck.py %s <export>...\n", path);
  else
    printf("Verdict:      fits, every import is resolved\n");

  FreeLibrary(image);
  return result;
}
