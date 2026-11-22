# The loader is two files to compile into a project: Loader/LoadLibrary.c and Loader/Kernel32.c (or a provider of
# its own). Kernel32.c registers itself in a constructor and nothing refers to it, so link its object directly:
# from a static archive the linker would drop it

CC     ?= cc
CFLAGS ?= -O2 -g

override CFLAGS += -std=gnu99 -Wall -fPIC -ILoader

OBJECTS = Loader/LoadLibrary.o Loader/Kernel32.o
TOOLS   = Tools/loadlibrary-check Examples/call
TESTS   = Tests/loadlibrary-test Tests/kernel32-test
DLLS    = Tests/DLL

all: $(OBJECTS) $(TOOLS)

Loader/%.o: Loader/%.c Loader/LoadLibrary.h
	$(CC) $(CFLAGS) -c $< -o $@

Tools/loadlibrary-check: Tools/LibraryCheck.c $(OBJECTS)
	$(CC) $(CFLAGS) $^ -lpthread -o $@

Examples/call: Examples/Call.c $(OBJECTS)
	$(CC) $(CFLAGS) $^ -lpthread -o $@

Tests/loadlibrary-test: Tests/LoadLibraryTest.c $(OBJECTS)
	$(CC) $(CFLAGS) $^ -lpthread -o $@

Tests/kernel32-test: Tests/Kernel32Test.c $(OBJECTS)
	$(CC) $(CFLAGS) $^ -lpthread -o $@

# Test DLLs are generated, no Windows toolchain is needed

check: all $(TESTS)
	python3 Tests/LoadLibraryTest.py $(DLLS)
	Tests/kernel32-test
	Tests/loadlibrary-test $(DLLS)
	test "$$(Examples/call $(DLLS)/B.dll Add 2 3)" = 5
	Tools/loadlibrary-check $(DLLS)/A.dll
	! Tools/loadlibrary-check --attach $(DLLS)/V.dll
	python3 Tools/LibraryCheck.py $(DLLS)/A.dll Twice Missing

clean:
	rm -f $(OBJECTS) $(TOOLS) $(TESTS)
	rm -f $(DLLS)/*.dll
	-rmdir $(DLLS)

.PHONY: all check clean
