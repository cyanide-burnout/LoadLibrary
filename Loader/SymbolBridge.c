// SymbolBridge: PE images as ELF objects of ld.so, so dladdr(), dlsym(), dl_iterate_phdr(), gdb and perf know them
//
// An observer of LoadLibrary (LIBRARY_OBSERVER), nothing refers to it: link the object and it works, as Kernel32.c.
// At LIBRARY_EVENT_MAPPING it makes a small ELF object in a memfd and opens it with dlopen():
//   - the first PT_LOAD is the image: SizeOfImage of zeroes, readable and writable; the loader puts the PE there and
//     sets protections of its sections as usual;
//   - the second PT_LOAD has .dynamic, .hash, .dynsym and .dynstr: exports of the DLL and the functions of .pdata
//     without a name (as "dll+0x1040"), with sizes from .pdata, since dladdr() of glibc matches a symbol of size 0
//     at its exact address only; a chained fragment of a function carries the name of the function;
//   - PT_GNU_STACK keeps stacks of the process not executable.
// ld.so runs nothing of it: no DT_NEEDED, no initializers. At LIBRARY_EVENT_UNMAPPING the object is closed.
//
// Unwinding through DLL frames is FrameBridge.c: the two are independent, link either or both.
//
// The object is opened as /proc/self/fd/N of its memfd, which stays open while the image lives: that is dli_fname of
// dladdr(), and a reader of that file finds a valid ELF there. The handle of dlopen() is the link_map of the object
// (glibc), so dladdr1(RTLD_DL_LINKMAP) gives a handle for dlsym() too.
// Images with stripped relocations are mapped by the loader at their ImageBase, SymbolBridge cannot wrap them.
// dlopen() runs with the lock of the loader held: a shared object that registers providers or observers in its
// constructors must not be dlopen()ed while another thread loads DLLs (that is the lock of ld.so, then the lock of
// the loader, in the opposite order)

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <sys/mman.h>

#include "LoadLibrary.h"

#define READ16(pointer)  (*(const uint16_t*)(pointer))
#define READ32(pointer)  (*(const uint32_t*)(pointer))

#define IMAGE_SCN_MEM_EXECUTE  0x20000000
#define UNW_FLAG_CHAININFO     4
#define CHAIN_DEPTH            32
#define PAGE_SIZE_ELF          0x1000

struct File
{
  const uint8_t* data;
  size_t length;
  const uint8_t* optional;
  const uint8_t* sections;
  int count;
};

struct Function
{
  uint32_t begin;
  uint32_t end;
  uint32_t root;     // Start of the function a chained fragment belongs to
};

struct Export
{
  const char* name;
  uint32_t address;
};

struct Symbol
{
  uint32_t name;     // Offset in .dynstr
  uint32_t value;
  uint32_t size;
  uint8_t type;
};

struct Wrapper
{
  struct Module* image;
  void* handle;
  int descriptor;
  struct Wrapper* next;
};

// Observers are called with the lock of the loader held, so it guards the list too

static struct Wrapper* Wrappers = NULL;

static const uint8_t* GetFileAddress(struct File* file, uint32_t address, uint32_t length)
{
  const uint8_t* section;
  uint32_t start;
  uint32_t size;
  uint32_t raw;

  for (section = file->sections; section < file->sections + 40 * file->count; section += 40)
  {
    start = READ32(section + 12);
    size  = READ32(section + 16);
    raw   = READ32(section + 20);

    if ((address >= start) &&
        ((uint64_t)address - start + length <= size) &&
        ((uint64_t)raw + address - start + length <= file->length))
      return file->data + raw + address - start;
  }

  if (((uint64_t)address + length <= READ32(file->optional + 60)) &&
      ((uint64_t)address + length <= file->length))
    return file->data + address;

  return NULL;
}

static const char* GetFileString(struct File* file, uint32_t address)
{
  const uint8_t* start;
  const uint8_t* end;

  if ((start = GetFileAddress(file, address, 1)) == NULL)
    return NULL;

  end = memchr(start, 0, file->data + file->length - start);
  return (end != NULL) ? (const char*)start : NULL;
}

static int IsExecutable(struct File* file, uint32_t address)
{
  const uint8_t* section;

  for (section = file->sections; section < file->sections + 40 * file->count; section += 40)
    if ((address >= READ32(section + 12)) &&
        (address - READ32(section + 12) < READ32(section + 8)))
      return (READ32(section + 36) & IMAGE_SCN_MEM_EXECUTE) != 0;

  return 0;
}

// End of the executable section that holds the address, or the address itself

static uint32_t GetSectionEnd(struct File* file, uint32_t address)
{
  const uint8_t* section;

  for (section = file->sections; section < file->sections + 40 * file->count; section += 40)
    if ((address >= READ32(section + 12)) &&
        (address - READ32(section + 12) < READ32(section + 8)))
      return READ32(section + 12) + READ32(section + 8);

  return address;
}

static int CompareFunctions(const void* first, const void* second)
{
  const struct Function* function1 = (const struct Function*)first;
  const struct Function* function2 = (const struct Function*)second;
  return (function1->begin > function2->begin) - (function1->begin < function2->begin);
}

static int CompareExports(const void* first, const void* second)
{
  const struct Export* export1 = (const struct Export*)first;
  const struct Export* export2 = (const struct Export*)second;
  return (export1->address > export2->address) - (export1->address < export2->address);
}

// Function of .pdata that holds the address, NULL when none

static const struct Function* FindFunction(const struct Function* functions, size_t count, uint32_t address)
{
  size_t low  = 0;
  size_t high = count;

  while (low < high)
  {
    size_t middle = (low + high) / 2;

    if (functions[middle].end <= address)
      low = middle + 1;
    else if (functions[middle].begin > address)
      high = middle;
    else
      return functions + middle;
  }

  return NULL;
}

static const struct Export* FindExport(const struct Export* exports, size_t count, uint32_t address)
{
  size_t low  = 0;
  size_t high = count;

  while (low < high)
  {
    size_t middle = (low + high) / 2;

    if (exports[middle].address < address)
      low = middle + 1;
    else if (exports[middle].address > address)
      high = middle;
    else
      return exports + middle;
  }

  return NULL;
}

// Functions of .pdata, a chained fragment knows the start of its function

static struct Function* ReadFunctions(struct File* file, uint32_t address, uint32_t length, size_t* count)
{
  struct Function* functions;
  const uint8_t* table;
  const uint8_t* information;
  uint32_t unwind;
  size_t number;
  int depth;

  *count = 0;

  if ((length < 12) ||
      ((table = GetFileAddress(file, address, length)) == NULL) ||
      ((functions = (struct Function*)calloc(length / 12, sizeof(struct Function))) == NULL))
    return NULL;

  number = 0;

  for (size_t index = 0; index < length / 12; index ++)
  {
    functions[number].begin = READ32(table + 12 * index);
    functions[number].end   = READ32(table + 12 * index + 4);
    functions[number].root  = functions[number].begin;
    unwind                  = READ32(table + 12 * index + 8);

    for (depth = 0; depth < CHAIN_DEPTH; depth ++)
    {
      if (((information = GetFileAddress(file, unwind, 4)) == NULL) ||
          (((information[0] >> 3) & UNW_FLAG_CHAININFO) == 0) ||
          ((information = GetFileAddress(file, unwind + 4 + 2 * ((information[2] + 1) & ~1), 12)) == NULL))
        break;

      functions[number].root = READ32(information);
      unwind                 = READ32(information + 8);
    }

    number += (functions[number].begin < functions[number].end);
  }

  qsort(functions, number, sizeof(struct Function), CompareFunctions);
  *count = number;
  return functions;
}

static struct Export* ReadExports(struct File* file, uint32_t address, uint32_t length, size_t* count)
{
  struct Export* exports;
  const uint8_t* directory;
  const uint8_t* functions;
  const uint8_t* names;
  const uint8_t* ordinals;
  uint32_t total;
  uint32_t named;
  uint32_t target;
  uint16_t ordinal;
  size_t number;

  *count = 0;

  if ((length < 40) ||
      ((directory = GetFileAddress(file, address, 40)) == NULL))
    return NULL;

  total = READ32(directory + 20);
  named = READ32(directory + 24);

  if (((functions = GetFileAddress(file, READ32(directory + 28), 4 * total)) == NULL) ||
      ((names = GetFileAddress(file, READ32(directory + 32), 4 * named)) == NULL) ||
      ((ordinals = GetFileAddress(file, READ32(directory + 36), 2 * named)) == NULL) ||
      ((exports = (struct Export*)calloc(named + 1, sizeof(struct Export))) == NULL))
    return NULL;

  number = 0;

  for (uint32_t index = 0; index < named; index ++)
  {
    ordinal = READ16(ordinals + 2 * index);

    if (ordinal >= total)
      continue;

    target = READ32(functions + 4 * ordinal);

    // Forwards point into the export directory
    if ((target == 0) ||
        ((target >= address) && (target < address + length)) ||
        ((exports[number].name = GetFileString(file, READ32(names + 4 * index))) == NULL))
      continue;

    exports[number ++].address = target;
  }

  qsort(exports, number, sizeof(struct Export), CompareExports);
  *count = number;
  return exports;
}

struct Strings
{
  char* data;
  size_t length;
  size_t capacity;
};

static uint32_t AddString(struct Strings* strings, const char* string)
{
  size_t length = strlen(string) + 1;
  size_t offset = strings->length;
  char* data;

  if (strings->length + length > strings->capacity)
  {
    strings->capacity = strings->capacity * 2 + length + 4096;
    if ((data = (char*)realloc(strings->data, strings->capacity)) == NULL)
      return 0;
    strings->data = data;
  }

  memcpy(strings->data + offset, string, length);
  strings->length += length;
  return offset;
}

static uint32_t HashName(const char* name)
{
  uint32_t hash = 0;
  uint32_t high;

  for (; *name != '\0'; name ++)
  {
    hash = (hash << 4) + (uint8_t)*name;
    high = hash & 0xf0000000;
    hash ^= high >> 24;
    hash &= ~high;
  }

  return hash;
}

// Symbols: exports with the sizes of their functions, then functions of .pdata without a name of their own

static struct Symbol* MakeSymbols(struct File* file, struct Module* image, struct Strings* strings, size_t* count)
{
  struct Function* functions;
  struct Export* exports;
  struct Symbol* symbols;
  const struct Function* function;
  const struct Export* export;
  uint32_t address;
  uint32_t length;
  size_t number;
  size_t total;
  size_t named;
  char name[256];

  address   = READ32(file->optional + 112);
  length    = READ32(file->optional + 116);
  exports   = ReadExports(file, address, length, &named);
  address   = READ32(file->optional + 112 + 8 * 3);
  length    = READ32(file->optional + 112 + 8 * 3 + 4);
  functions = ReadFunctions(file, address, length, &total);
  symbols   = (struct Symbol*)calloc(named + total + 1, sizeof(struct Symbol));

  if (symbols == NULL)
  {
    free(exports);
    free(functions);
    return NULL;
  }

  number = 1;                                                     // Symbol 0 is the null symbol

  for (size_t index = 0; index < named; index ++)
  {
    symbols[number].name  = AddString(strings, exports[index].name);
    symbols[number].value = exports[index].address;
    symbols[number].type  = IsExecutable(file, exports[index].address) ? STT_FUNC : STT_OBJECT;

    if ((symbols[number].type == STT_FUNC) &&
        ((function = FindFunction(functions, total, exports[index].address)) != NULL))
      symbols[number].size = function->end - exports[index].address;
    else if (symbols[number].type == STT_FUNC)
    {
      // A leaf without .pdata: up to the next function, export or the end of the section
      uint32_t end = GetSectionEnd(file, exports[index].address);

      if ((index + 1 < named) && (exports[index + 1].address > exports[index].address) && (exports[index + 1].address < end))
        end = exports[index + 1].address;

      for (size_t other = 0; other < total; other ++)
        if ((functions[other].begin > exports[index].address) && (functions[other].begin < end))
          end = functions[other].begin;

      symbols[number].size = end - exports[index].address;
    }

    number ++;
  }

  for (size_t index = 0; index < total; index ++)
  {
    if (((export = FindExport(exports, named, functions[index].begin)) != NULL) &&
        (functions[index].root == functions[index].begin))
      continue;

    if ((export = FindExport(exports, named, functions[index].root)) != NULL)
      snprintf(name, sizeof(name), "%s", export->name);
    else
      snprintf(name, sizeof(name), "%s+0x%x", image->name, functions[index].root);

    symbols[number].name  = AddString(strings, name);
    symbols[number].value = functions[index].begin;
    symbols[number].size  = functions[index].end - functions[index].begin;
    symbols[number].type  = STT_FUNC;
    number ++;
  }

  free(exports);
  free(functions);

  *count = number;
  return symbols;
}

// ELF object: headers, then at a page the second PT_LOAD at the page after the image: .dynamic, .hash, .dynsym, .dynstr

static int MakeObject(struct Module* image, struct File* file)
{
  struct Strings strings;
  struct Symbol* symbols;
  Elf64_Ehdr* header;
  Elf64_Phdr* programs;
  Elf64_Dyn* dynamic;
  Elf64_Sym* table;
  uint32_t* hash;
  uint8_t* buffer;
  uint64_t memory;
  size_t offset;
  size_t length;
  size_t count;
  size_t buckets;
  size_t sizes[4];
  uint32_t soname;
  int descriptor;

  memset(&strings, 0, sizeof(strings));
  AddString(&strings, "");
  soname = AddString(&strings, image->name);

  if ((symbols = MakeSymbols(file, image, &strings, &count)) == NULL)
  {
    free(strings.data);
    return -1;
  }

  buckets  = count / 2 + 1;
  memory   = ((uint64_t)image->size + PAGE_SIZE_ELF - 1) & ~(uint64_t)(PAGE_SIZE_ELF - 1);
  sizes[0] = 7 * sizeof(Elf64_Dyn);
  sizes[1] = (2 + buckets + count) * sizeof(uint32_t);
  sizes[2] = count * sizeof(Elf64_Sym);
  sizes[3] = strings.length;
  sizes[1] = (sizes[1] + 7) & ~7;
  length   = PAGE_SIZE_ELF + sizes[0] + sizes[1] + sizes[2] + sizes[3];

  if ((buffer = (uint8_t*)calloc(1, length)) == NULL)
  {
    free(symbols);
    free(strings.data);
    return -1;
  }

  header   = (Elf64_Ehdr*)buffer;
  programs = (Elf64_Phdr*)(buffer + sizeof(Elf64_Ehdr));
  offset   = PAGE_SIZE_ELF;
  dynamic  = (Elf64_Dyn*)(buffer + offset);
  hash     = (uint32_t*)(buffer + offset + sizes[0]);
  table    = (Elf64_Sym*)(buffer + offset + sizes[0] + sizes[1]);

  memcpy(header->e_ident, ELFMAG, SELFMAG);
  header->e_ident[EI_CLASS]   = ELFCLASS64;
  header->e_ident[EI_DATA]    = ELFDATA2LSB;
  header->e_ident[EI_VERSION] = EV_CURRENT;
  header->e_type              = ET_DYN;
  header->e_machine           = EM_X86_64;
  header->e_version           = EV_CURRENT;
  header->e_phoff             = sizeof(Elf64_Ehdr);
  header->e_ehsize            = sizeof(Elf64_Ehdr);
  header->e_phentsize         = sizeof(Elf64_Phdr);
  header->e_phnum             = 4;

  // The image: zeroes, writable until the loader protects its sections

  programs[0].p_type   = PT_LOAD;
  programs[0].p_flags  = PF_R | PF_W;
  programs[0].p_memsz  = memory;
  programs[0].p_align  = PAGE_SIZE_ELF;

  programs[1].p_type   = PT_LOAD;
  programs[1].p_flags  = PF_R | PF_W;                             // ld.so adjusts .dynamic in place
  programs[1].p_offset = offset;
  programs[1].p_vaddr  = memory;
  programs[1].p_paddr  = memory;
  programs[1].p_filesz = length - offset;
  programs[1].p_memsz  = length - offset;
  programs[1].p_align  = PAGE_SIZE_ELF;

  programs[2].p_type   = PT_DYNAMIC;
  programs[2].p_flags  = PF_R | PF_W;
  programs[2].p_offset = offset;
  programs[2].p_vaddr  = memory;
  programs[2].p_paddr  = memory;
  programs[2].p_filesz = sizes[0];
  programs[2].p_memsz  = sizes[0];
  programs[2].p_align  = 8;

  programs[3].p_type   = PT_GNU_STACK;
  programs[3].p_flags  = PF_R | PF_W;
  programs[3].p_align  = 16;

  dynamic[0].d_tag = DT_HASH;    dynamic[0].d_un.d_ptr = memory + sizes[0];
  dynamic[1].d_tag = DT_SYMTAB;  dynamic[1].d_un.d_ptr = memory + sizes[0] + sizes[1];
  dynamic[2].d_tag = DT_STRTAB;  dynamic[2].d_un.d_ptr = memory + sizes[0] + sizes[1] + sizes[2];
  dynamic[3].d_tag = DT_STRSZ;   dynamic[3].d_un.d_val = sizes[3];
  dynamic[4].d_tag = DT_SYMENT;  dynamic[4].d_un.d_val = sizeof(Elf64_Sym);
  dynamic[5].d_tag = DT_SONAME;  dynamic[5].d_un.d_val = soname;
  dynamic[6].d_tag = DT_NULL;

  // Symbols and their SysV hash table (DT_HASH is enough for dlsym(), and gives dladdr() the count of symbols)

  hash[0] = buckets;
  hash[1] = count;

  for (size_t index = 1; index < count; index ++)
  {
    uint32_t bucket = HashName(strings.data + symbols[index].name) % buckets;

    table[index].st_name  = symbols[index].name;
    table[index].st_info  = ELF64_ST_INFO(STB_GLOBAL, symbols[index].type);
    table[index].st_shndx = 1;                                    // Defined, relative to the base (not SHN_ABS)
    table[index].st_value = symbols[index].value;
    table[index].st_size  = symbols[index].size;

    hash[2 + buckets + index] = hash[2 + bucket];
    hash[2 + bucket]          = index;
  }

  memcpy(buffer + offset + sizes[0] + sizes[1] + sizes[2], strings.data, strings.length);

  free(symbols);
  free(strings.data);

  if ((descriptor = memfd_create(image->name, MFD_CLOEXEC)) < 0)
  {
    free(buffer);
    return -1;
  }

  if (write(descriptor, buffer, length) != (ssize_t)length)
  {
    close(descriptor);
    free(buffer);
    return -1;
  }

  free(buffer);
  return descriptor;
}

static void Map(struct Module* image)
{
  struct Wrapper* wrapper;
  struct link_map* map;
  struct File file;
  char path[64];
  uint32_t lfanew;

  if ((image->file.data == NULL) ||
      (image->base != NULL) ||
      (image->file.length < 0x40) ||
      ((lfanew = READ32(image->file.data + 0x3c)) > image->file.length - 24))
    return;

  file.data     = image->file.data;
  file.length   = image->file.length;
  file.optional = image->file.data + lfanew + 24;
  file.count    = READ16(image->file.data + lfanew + 6);
  file.sections = file.optional + READ16(image->file.data + lfanew + 20);

  if ((READ16(image->file.data + lfanew + 20) < 112 + 8 * 4) ||
      (file.sections + 40 * file.count > file.data + file.length) ||
      ((wrapper = (struct Wrapper*)calloc(1, sizeof(struct Wrapper))) == NULL))
    return;

  if ((wrapper->descriptor = MakeObject(image, &file)) < 0)
  {
    image->report(LOG_WARNING, "SymbolBridge could not make an ELF object for PE image %s\n", image->name);
    free(wrapper);
    return;
  }

  snprintf(path, sizeof(path), "/proc/self/fd/%d", wrapper->descriptor);

  if (((wrapper->handle = dlopen(path, RTLD_NOW | RTLD_LOCAL)) == NULL) ||
      (dlinfo(wrapper->handle, RTLD_DI_LINKMAP, &map) != 0))
  {
    image->report(LOG_WARNING, "SymbolBridge could not open the ELF object of PE image %s: %s\n", image->name, dlerror());

    if (wrapper->handle != NULL)
      dlclose(wrapper->handle);

    close(wrapper->descriptor);
    free(wrapper);
    return;
  }

  image->base    = (uint8_t*)map->l_addr;
  wrapper->image = image;
  wrapper->next  = Wrappers;
  Wrappers       = wrapper;
}

static void Unmap(struct Module* image)
{
  struct Wrapper** pointer;
  struct Wrapper* wrapper;

  for (pointer = &Wrappers; *pointer != NULL; pointer = &(*pointer)->next)
  {
    if ((*pointer)->image == image)
    {
      wrapper  = *pointer;
      *pointer = wrapper->next;

      dlclose(wrapper->handle);
      close(wrapper->descriptor);
      free(wrapper);
      return;
    }
  }
}

static void Observe(int event, struct Module* image)
{
  if (event == LIBRARY_EVENT_MAPPING)
    Map(image);

  if (event == LIBRARY_EVENT_UNMAPPING)
    Unmap(image);
}

LIBRARY_OBSERVER(SymbolBridge, Observe)
