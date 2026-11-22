// SymbolBridge: PE images as ELF objects of ld.so, so dladdr(), dlsym(), dl_iterate_phdr(), gdb and perf know them
//
// An observer of LoadLibrary (LIBRARY_OBSERVER), nothing refers to it: link the object and it works, as Kernel32.c.
// At LIBRARY_EVENT_MAPPING it makes a small ELF object in a memfd and opens it with dlopen():
//   - the first PT_LOAD is the image: SizeOfImage of zeroes, readable and writable; the loader puts the PE there and
//     sets protections of its sections as usual;
//   - the second PT_LOAD has .dynamic, .hash, .dynsym and .dynstr: exports of the DLL and the functions of .pdata
//     without a name (as "dll+0x1040"), with sizes from .pdata, since dladdr() of glibc matches a symbol of size 0
//     at its exact address only; a chained fragment of a function carries the name of the function;
//   - with FrameBridge.c linked, the same part also has .eh_frame (MakeLibraryFrames(), from the file) and
//     .eh_frame_hdr with PT_GNU_EH_FRAME: libgcc and libunwind find the CFI through ld.so, as for any object, gdb
//     too, and FrameBridge has nothing to register;
//   - PT_GNU_STACK keeps stacks of the process not executable;
//   - section headers at the end of the file, for gdb and other readers of the file (ld.so needs none).
// ld.so runs nothing of it: no DT_NEEDED, no initializers. At LIBRARY_EVENT_UNMAPPING the object is closed.
//
// Without FrameBridge.c the object has names only: the two are independent, link either or both.
//
// The object is opened as /proc/<pid>/fd/N of its memfd, which stays open while the image lives: that is dli_fname
// of dladdr() and l_name for gdb, which opens it in its own process (so not /proc/self; images are not for forked
// children). The memfd is named after the DLL: readlink() of that path or /proc/<pid>/maps show
// "/memfd:name.dll (deleted)", and DT_SONAME is the name too. The handle of dlopen() is the link_map of the object
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

static const uint8_t* ResolveFile(void* context, uint32_t address, uint32_t length)
{
  return GetFileAddress((struct File*)context, address, length);
}

struct Section
{
  const char* name;
  uint32_t type;
  uint64_t flags;
  uint64_t address;     // RVA, the offset in the file follows from it for the second PT_LOAD
  uint64_t size;
  uint32_t link;
  uint32_t info;
  uint64_t alignment;
  uint64_t entry;
};

// ELF object: headers; at the next page the contents of the second PT_LOAD, which follows the image: .dynamic, .hash,
// .dynsym, .dynstr, then .eh_frame and .eh_frame_hdr when FrameBridge.c is linked; section headers at the end, for
// gdb and other readers of the file (ld.so needs none)

static int MakeObject(struct Module* image, struct File* file)
{
  struct Section sections[10];
  struct Strings strings;
  struct Strings names;
  struct Symbol* symbols;
  Elf64_Ehdr* header;
  Elf64_Phdr* programs;
  Elf64_Shdr* headers;
  Elf64_Dyn* dynamic;
  Elf64_Sym* table;
  uint32_t* hash;
  uint32_t* entries;
  uint8_t* frames;
  uint8_t* buffer;
  uint8_t* summary;
  uint64_t memory;
  size_t places[6];
  size_t length;
  size_t total;
  size_t count;
  size_t number;
  size_t buckets;
  size_t extent;
  uint32_t soname;
  int descriptor;
  int segments;
  int index;

  memset(&strings, 0, sizeof(strings));
  memset(&names, 0, sizeof(names));
  AddString(&strings, "");
  soname = AddString(&strings, image->name);

  if ((symbols = MakeSymbols(file, image, &strings, &count)) == NULL)
  {
    free(strings.data);
    return -1;
  }

  // Places in the second PT_LOAD: .dynamic, .hash, .dynsym, .dynstr, .eh_frame, .eh_frame_hdr, end

  buckets   = count / 2 + 1;
  memory    = ((uint64_t)image->size + PAGE_SIZE_ELF - 1) & ~(uint64_t)(PAGE_SIZE_ELF - 1);
  places[0] = 0;
  places[1] = places[0] + 7 * sizeof(Elf64_Dyn);
  places[2] = (places[1] + (2 + buckets + count) * sizeof(uint32_t) + 7) & ~7;
  places[3] = places[2] + count * sizeof(Elf64_Sym);
  places[4] = (places[3] + strings.length + 7) & ~7;

  frames  = NULL;
  entries = NULL;
  extent  = 0;
  number  = 0;

  if ((MakeLibraryFrames != NULL) &&
      ((frames = MakeLibraryFrames(image, ResolveFile, file, memory + places[4], &extent, &entries, &number)) == NULL))
    image->report(LOG_WARNING, "SymbolBridge could not get unwind information of PE image %s from FrameBridge\n", image->name);

  places[5] = (places[4] + extent + 7) & ~7;
  total     = places[5] + ((frames != NULL) ? 12 + 8 * number : 0);

  // Section headers

  AddString(&names, "");
  index = 1;
  sections[index ++] = (struct Section) { ".text",    SHT_NOBITS,  SHF_ALLOC | SHF_EXECINSTR, 0, image->size, 0, 0, 16, 0 };
  sections[index ++] = (struct Section) { ".dynamic", SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE, memory + places[0], places[1] - places[0], 5, 0, 8, sizeof(Elf64_Dyn) };
  sections[index ++] = (struct Section) { ".hash",    SHT_HASH,    SHF_ALLOC, memory + places[1], (2 + buckets + count) * sizeof(uint32_t), 4, 0, 8, 4 };
  sections[index ++] = (struct Section) { ".dynsym",  SHT_DYNSYM,  SHF_ALLOC, memory + places[2], count * sizeof(Elf64_Sym), 5, 1, 8, sizeof(Elf64_Sym) };
  sections[index ++] = (struct Section) { ".dynstr",  SHT_STRTAB,  SHF_ALLOC, memory + places[3], strings.length, 0, 0, 1, 0 };

  if (frames != NULL)
  {
    sections[index ++] = (struct Section) { ".eh_frame",     SHT_PROGBITS, SHF_ALLOC, memory + places[4], extent, 0, 0, 8, 0 };
    sections[index ++] = (struct Section) { ".eh_frame_hdr", SHT_PROGBITS, SHF_ALLOC, memory + places[5], 12 + 8 * number, 0, 0, 4, 0 };
  }

  sections[index ++] = (struct Section) { ".shstrtab", SHT_STRTAB, 0, 0, 0, 0, 0, 1, 0 };

  for (int position = 1; position < index; position ++)
    AddString(&names, sections[position].name);

  length = PAGE_SIZE_ELF + total + names.length;
  length = (length + 7) & ~7;

  if ((buffer = (uint8_t*)calloc(1, length + index * sizeof(Elf64_Shdr))) == NULL)
  {
    free(symbols);
    free(strings.data);
    free(names.data);
    free(frames);
    free(entries);
    return -1;
  }

  header   = (Elf64_Ehdr*)buffer;
  programs = (Elf64_Phdr*)(buffer + sizeof(Elf64_Ehdr));
  headers  = (Elf64_Shdr*)(buffer + length);
  dynamic  = (Elf64_Dyn*)(buffer + PAGE_SIZE_ELF + places[0]);
  hash     = (uint32_t*)(buffer + PAGE_SIZE_ELF + places[1]);
  table    = (Elf64_Sym*)(buffer + PAGE_SIZE_ELF + places[2]);
  summary  = buffer + PAGE_SIZE_ELF + places[5];
  segments = 4 + (frames != NULL);

  memcpy(header->e_ident, ELFMAG, SELFMAG);
  header->e_ident[EI_CLASS]   = ELFCLASS64;
  header->e_ident[EI_DATA]    = ELFDATA2LSB;
  header->e_ident[EI_VERSION] = EV_CURRENT;
  header->e_type              = ET_DYN;
  header->e_machine           = EM_X86_64;
  header->e_version           = EV_CURRENT;
  header->e_phoff             = sizeof(Elf64_Ehdr);
  header->e_shoff             = length;
  header->e_ehsize            = sizeof(Elf64_Ehdr);
  header->e_phentsize         = sizeof(Elf64_Phdr);
  header->e_phnum             = segments;
  header->e_shentsize         = sizeof(Elf64_Shdr);
  header->e_shnum             = index;
  header->e_shstrndx          = index - 1;

  // The image: zeroes, writable until the loader protects its sections

  programs[0].p_type   = PT_LOAD;
  programs[0].p_flags  = PF_R | PF_W;
  programs[0].p_memsz  = memory;
  programs[0].p_align  = PAGE_SIZE_ELF;

  programs[1].p_type   = PT_LOAD;
  programs[1].p_flags  = PF_R | PF_W;                             // ld.so adjusts .dynamic in place
  programs[1].p_offset = PAGE_SIZE_ELF;
  programs[1].p_vaddr  = memory;
  programs[1].p_paddr  = memory;
  programs[1].p_filesz = total;
  programs[1].p_memsz  = total;
  programs[1].p_align  = PAGE_SIZE_ELF;

  programs[2].p_type   = PT_DYNAMIC;
  programs[2].p_flags  = PF_R | PF_W;
  programs[2].p_offset = PAGE_SIZE_ELF + places[0];
  programs[2].p_vaddr  = memory + places[0];
  programs[2].p_paddr  = memory + places[0];
  programs[2].p_filesz = places[1] - places[0];
  programs[2].p_memsz  = places[1] - places[0];
  programs[2].p_align  = 8;

  programs[3].p_type   = PT_GNU_STACK;
  programs[3].p_flags  = PF_R | PF_W;
  programs[3].p_align  = 16;

  if (frames != NULL)
  {
    programs[4].p_type   = PT_GNU_EH_FRAME;
    programs[4].p_flags  = PF_R;
    programs[4].p_offset = PAGE_SIZE_ELF + places[5];
    programs[4].p_vaddr  = memory + places[5];
    programs[4].p_paddr  = memory + places[5];
    programs[4].p_filesz = 12 + 8 * number;
    programs[4].p_memsz  = 12 + 8 * number;
    programs[4].p_align  = 4;
  }

  dynamic[0].d_tag = DT_HASH;    dynamic[0].d_un.d_ptr = memory + places[1];
  dynamic[1].d_tag = DT_SYMTAB;  dynamic[1].d_un.d_ptr = memory + places[2];
  dynamic[2].d_tag = DT_STRTAB;  dynamic[2].d_un.d_ptr = memory + places[3];
  dynamic[3].d_tag = DT_STRSZ;   dynamic[3].d_un.d_val = strings.length;
  dynamic[4].d_tag = DT_SYMENT;  dynamic[4].d_un.d_val = sizeof(Elf64_Sym);
  dynamic[5].d_tag = DT_SONAME;  dynamic[5].d_un.d_val = soname;
  dynamic[6].d_tag = DT_NULL;

  // Symbols and their SysV hash table (DT_HASH is enough for dlsym(), and gives dladdr() the count of symbols)

  hash[0] = buckets;
  hash[1] = count;

  for (size_t position = 1; position < count; position ++)
  {
    uint32_t bucket = HashName(strings.data + symbols[position].name) % buckets;

    table[position].st_name  = symbols[position].name;
    table[position].st_info  = ELF64_ST_INFO(STB_GLOBAL, symbols[position].type);
    table[position].st_shndx = 1;                                 // .text, relative to the base (not SHN_ABS)
    table[position].st_value = symbols[position].value;
    table[position].st_size  = symbols[position].size;

    hash[2 + buckets + position] = hash[2 + bucket];
    hash[2 + bucket]             = position;
  }

  memcpy(buffer + PAGE_SIZE_ELF + places[3], strings.data, strings.length);

  // .eh_frame and .eh_frame_hdr: version 1, pointer to .eh_frame (pcrel, sdata4), count (udata4), sorted table of
  // (start of a function, its FDE) relative to .eh_frame_hdr (datarel, sdata4)

  if (frames != NULL)
  {
    int32_t value;

    memcpy(buffer + PAGE_SIZE_ELF + places[4], frames, extent);
    summary[0] = 1;
    summary[1] = 0x1b;
    summary[2] = 0x03;
    summary[3] = 0x3b;
    value      = (int32_t)(places[4] - (places[5] + 4));
    memcpy(summary + 4, &value, 4);
    memcpy(summary + 8, &number, 4);

    for (size_t position = 0; position < number; position ++)
    {
      value = (int32_t)(entries[2 * position] - (memory + places[5]));
      memcpy(summary + 12 + 8 * position, &value, 4);
      value = (int32_t)(places[4] + entries[2 * position + 1] - places[5]);
      memcpy(summary + 16 + 8 * position, &value, 4);
    }
  }

  // Section headers and their names

  memcpy(buffer + PAGE_SIZE_ELF + total, names.data, names.length);

  for (int position = 1; position < index; position ++)
  {
    headers[position].sh_name      = (position == 1) ? 1 : (headers[position - 1].sh_name + strlen(sections[position - 1].name) + 1);
    headers[position].sh_type      = sections[position].type;
    headers[position].sh_flags     = sections[position].flags;
    headers[position].sh_addr      = sections[position].address;
    headers[position].sh_offset    = (sections[position].address >= memory) ? PAGE_SIZE_ELF + sections[position].address - memory : 0;
    headers[position].sh_size      = sections[position].size;
    headers[position].sh_link      = sections[position].link;
    headers[position].sh_info      = sections[position].info;
    headers[position].sh_addralign = sections[position].alignment;
    headers[position].sh_entsize   = sections[position].entry;
  }

  headers[index - 1].sh_offset = PAGE_SIZE_ELF + total;
  headers[index - 1].sh_size   = names.length;

  free(symbols);
  free(strings.data);
  free(names.data);
  free(frames);
  free(entries);

  if ((descriptor = memfd_create(image->name, MFD_CLOEXEC)) < 0)
  {
    free(buffer);
    return -1;
  }

  length += index * sizeof(Elf64_Shdr);

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

  // By the number of the process, not /proc/self: gdb opens this name in its own process
  snprintf(path, sizeof(path), "/proc/%d/fd/%d", getpid(), wrapper->descriptor);

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
