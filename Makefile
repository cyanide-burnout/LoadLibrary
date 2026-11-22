# The loader is two files to compile into a project: Loader/LoadLibrary.c and Loader/Kernel32.c (or a provider of
# its own). Kernel32.c registers itself in a constructor and nothing refers to it, so link its object directly:
# from a static archive the linker would drop it

CC     ?= cc
CFLAGS ?= -O2 -g

override CFLAGS += -std=gnu99 -Wall -fPIC -ILoader

OBJECTS = Loader/LoadLibrary.o Loader/Kernel32.o
BRIDGES = Loader/FrameBridge.o Loader/SymbolBridge.o
TOOLS   = Tools/loadlibrary-check Examples/call
TESTS   = Tests/loadlibrary-test Tests/kernel32-test Tests/framebridge-test Tests/framebridge-baseline Tests/symbolbridge-test Tests/symbolbridge-names
DLLS    = Tests/DLL

# FrameBridge.o (unwinding) and SymbolBridge.o (names for dladdr) are optional, linked like Kernel32.o. FrameBridge
# feeds libunwind too when the system has its headers; then its test is also built against libunwind

HASH      := \#
LIBUNWIND := $(shell printf '$(HASH)include <libunwind-dynamic.h>\n' | $(CC) -E -x c - >/dev/null 2>&1 && echo yes)
TESTS     += $(if $(LIBUNWIND),Tests/framebridge-libunwind)

all: $(OBJECTS) $(BRIDGES) $(TOOLS)

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

Tests/framebridge-test: Tests/FrameBridgeTest.c $(OBJECTS) Loader/FrameBridge.o
	$(CC) $(CFLAGS) -rdynamic $^ -ldl -lpthread -o $@

Tests/framebridge-baseline: Tests/FrameBridgeTest.c $(OBJECTS)
	$(CC) $(CFLAGS) -rdynamic -DBASELINE $^ -ldl -lpthread -o $@

Tests/framebridge-libunwind: Tests/FrameBridgeTest.c $(OBJECTS) Loader/FrameBridge.o
	$(CC) $(CFLAGS) -rdynamic -DWITH_LIBUNWIND $^ -lunwind -ldl -lpthread -o $@

Tests/symbolbridge-test: Tests/SymbolBridgeTest.c $(OBJECTS) $(BRIDGES)
	$(CC) $(CFLAGS) -rdynamic $^ -ldl -lpthread -o $@

Tests/symbolbridge-names: Tests/SymbolBridgeTest.c $(OBJECTS) Loader/SymbolBridge.o
	$(CC) $(CFLAGS) -rdynamic -DNAMES_ONLY $^ -ldl -lpthread -o $@

# Test DLLs are generated, no Windows toolchain is needed

check: all $(TESTS)
	python3 Tests/LoadLibraryTest.py $(DLLS)
	Tests/kernel32-test
	Tests/loadlibrary-test $(DLLS)
	test "$$(Examples/call $(DLLS)/B.dll Add 2 3)" = 5
	Tools/loadlibrary-check $(DLLS)/A.dll
	! Tools/loadlibrary-check --attach $(DLLS)/V.dll
	python3 Tools/LibraryCheck.py $(DLLS)/A.dll Twice Missing
	Tests/framebridge-baseline $(DLLS)
	Tests/framebridge-test $(DLLS)
	$(if $(LIBUNWIND),Tests/framebridge-libunwind $(DLLS))
	Tests/symbolbridge-test $(DLLS)
	Tests/symbolbridge-names $(DLLS)

clean:
	rm -f $(OBJECTS) $(BRIDGES) $(TOOLS) $(TESTS) Tests/framebridge-libunwind
	rm -f $(DLLS)/*.dll
	-rmdir $(DLLS)

.PHONY: all check clean
