// The smallest use of LoadLibrary: load a DLL, prepare the thread, call an export int (int, int)
//
//   call [--attach] <dll> <export> <value1> <value2>
//
// Messages of the loader go to syslog(3), which has the signature of LibraryReportFunction; LOG_PERROR copies them to stderr

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "LoadLibrary.h"

typedef int (LIBRARY_ABI *Function)(int value1, int value2);

int main(int argc, char** argv)
{
  struct Module* image;
  Function function;
  int attach;

  attach = (argc > 1) && (strcmp(argv[1], "--attach") == 0);

  if (argc < 5 + attach)
  {
    fprintf(stderr, "usage: call [--attach] <dll> <export> <value1> <value2>\n");
    return 2;
  }

  openlog("call", LOG_PERROR, LOG_USER);
  SetLibraryReport(syslog);

  if ((image = LoadLibrary(argv[1 + attach], NULL)) == NULL)
  {
    fprintf(stderr, "LoadLibrary: %s\n", GetLibraryErrorText(GetLibraryLastError()));
    return 1;
  }

  // Every thread that calls into a DLL needs a TEB; DllMain runs only when asked for

  if ((PrepareLibraryThread() < 0) ||
      (attach && (AttachLibrary(image) < 0)))
  {
    fprintf(stderr, "Preparation: %s\n", GetLibraryErrorText(GetLibraryLastError()));
    FreeLibrary(image);
    return 1;
  }

  if ((function = (Function)GetProcAddress(image, argv[2 + attach])) == NULL)
  {
    fprintf(stderr, "No export %s\n", argv[2 + attach]);
    FreeLibrary(image);
    return 1;
  }

  printf("%d\n", function(atoi(argv[3 + attach]), atoi(argv[4 + attach])));

  FreeLibrary(image);
  return 0;
}
