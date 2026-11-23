// FrameBridge: unwind information of PE images for the unwinders of Linux
//
// An observer of LoadLibrary (LIBRARY_OBSERVER), nothing refers to it: link the object and it works, as Kernel32.c.
// For every loaded image it translates the exception directory (.pdata and UNWIND_INFO of x64) into DWARF CFI
// (.eh_frame) and registers it:
//   - in the unwinder of libgcc (__register_frame): backtrace(), _Unwind_Backtrace() and C++ exceptions of the host
//     pass through frames of DLLs,
//   - in libunwind (the nongnu one, _U_dyn_register) when the process has it: unw_step() of fault handlers.
// Both are weak references: an unwinder the process does not have is skipped. An image ld.so already knows the CFI
// of (inside an object of SymbolBridge.c with PT_GNU_EH_FRAME) is left to ld.so.
//
// The translation is also MakeLibraryFrames(), for SymbolBridge.c: it reads the PE through a function, so it works
// on a mapped image and on a file alike.
//
// Gaps of executable sections not covered by .pdata are leaf functions, as for the unwinder of Windows: the return
// address is at [rsp]. Epilogues are not in UNWIND_INFO (Windows recognizes them by code, they are canonical):
// FrameBridge finds them the same way and gives each one rows of its own, so a fault inside an epilogue unwinds too.
//
// Limits: nonvolatile XMM registers are not described: the System V caller does not keep them anyway, and libunwind
// refuses DWARF registers above 16; UWOP_PUSH_MACHFRAME (interrupt frames of drivers) leaves its function without an
// FDE, a warning names it

#define _GNU_SOURCE
#define LIBRARY_PRIVATE

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <link.h>
#include <sys/mman.h>

#include "LoadLibrary.h"

#if defined(__has_include)
#if __has_include(<libunwind-dynamic.h>)
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#define HAVE_LIBUNWIND
#pragma weak _U_dyn_register
#pragma weak _U_dyn_cancel
#endif
#endif

extern void __register_frame(void* begin) __attribute__((weak));
extern void __deregister_frame(void* begin) __attribute__((weak));
extern void* _Unwind_Find_FDE(void* address, void* bases) __attribute__((weak));

#define READ16(pointer)  (*(const uint16_t*)(pointer))
#define READ32(pointer)  (*(const uint32_t*)(pointer))

#define IMAGE_SCN_MEM_EXECUTE   0x20000000
#define UNW_FLAG_CHAININFO      4

#define UWOP_PUSH_NONVOL        0
#define UWOP_ALLOC_LARGE        1
#define UWOP_ALLOC_SMALL        2
#define UWOP_SET_FPREG          3
#define UWOP_SAVE_NONVOL        4
#define UWOP_SAVE_NONVOL_FAR    5
#define UWOP_EPILOG             6
#define UWOP_SPARE_CODE         7
#define UWOP_SAVE_XMM128        8
#define UWOP_SAVE_XMM128_FAR    9
#define UWOP_PUSH_MACHFRAME     10

#define DW_CFA_advance_loc          0x40
#define DW_CFA_offset               0x80
#define DW_CFA_advance_loc1         0x02
#define DW_CFA_advance_loc2         0x03
#define DW_CFA_advance_loc4         0x04
#define DW_CFA_remember_state       0x0a
#define DW_CFA_restore_state        0x0b
#define DW_CFA_restore_extended     0x06
#define DW_CFA_def_cfa              0x0c
#define DW_CFA_def_cfa_offset       0x0e
#define DW_CFA_offset_extended_sf   0x11

#define DWARF_RSP                   7
#define DWARF_RETURN_ADDRESS        16

#define OPERATION_COUNT  1024
#define CHAIN_DEPTH      32

// Numbers of registers in UNWIND_CODE (RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8..R15) and in DWARF of x86-64

static const uint8_t Registers[16] = { 0, 2, 1, 3, 7, 6, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15 };

struct Operation
{
  uint32_t offset;  // End of the instruction in the prolog, 0 for operations of a chained parent
  uint8_t code;
  uint8_t info;
  uint8_t frame;    // FrameRegister and FrameOffset of the UNWIND_INFO, for UWOP_SET_FPREG
  uint32_t value;   // Size of an allocation, offset of a save
};

struct Range
{
  uint32_t begin;
  uint32_t end;
  uint32_t unwind;  // RVA of UNWIND_INFO, 0 for a leaf
};

struct Buffer
{
  uint8_t* data;
  size_t length;
  size_t capacity;
  int failed;
};

// Entry of the search table of libunwind (as in .eh_frame_hdr), offsets from the image base

struct Entry
{
  int32_t start;
  int32_t frame;
};

struct Bridge
{
  struct Module* image;
  uint8_t* frame;   // .eh_frame and the search table, read only
  size_t size;      // Length of the mapping
  int registered;   // In libgcc
#ifdef HAVE_LIBUNWIND
  unw_dyn_info_t information;
  int dynamic;      // In libunwind
#endif
  struct Bridge* next;
};

// Observers are called with the lock of the loader held, so it guards the list too

static struct Bridge* Bridges = NULL;

// The PE as the translation sees it: a mapped image or a file

struct Source
{
  struct Module* image;              // Name and report
  LibraryResolveFunction resolve;
  void* context;
  uint32_t size;                     // SizeOfImage
};

static const uint8_t* Resolve(struct Source* source, uint64_t address, uint64_t length)
{
  return ((address <= source->size) && (length <= source->size - address)) ? source->resolve(source->context, address, length) : NULL;
}

static const uint8_t* ResolveImage(void* context, uint32_t address, uint32_t length)
{
  struct Module* image = (struct Module*)context;
  return ((address <= image->size) && (length <= image->size - address)) ? image->base + address : NULL;
}

static void Put(struct Buffer* buffer, const void* data, size_t length)
{
  uint8_t* pointer;
  size_t capacity;

  if (buffer->length + length > buffer->capacity)
  {
    capacity = buffer->capacity * 2 + length + 4096;

    if ((pointer = (uint8_t*)realloc(buffer->data, capacity)) == NULL)
    {
      buffer->failed = 1;
      return;
    }

    buffer->data     = pointer;
    buffer->capacity = capacity;
  }

  memcpy(buffer->data + buffer->length, data, length);
  buffer->length += length;
}

static void PutByte(struct Buffer* buffer, uint8_t value)
{
  Put(buffer, &value, 1);
}

static void PutUnsigned(struct Buffer* buffer, uint64_t value)
{
  do
  {
    PutByte(buffer, (value & 0x7f) | ((value >= 0x80) << 7));
    value >>= 7;
  }
  while (value != 0);
}

static void PutSigned(struct Buffer* buffer, int64_t value)
{
  int more;

  do
  {
    uint8_t byte = value & 0x7f;
    value >>= 7;
    more  = !(((value == 0) && !(byte & 0x40)) || ((value == -1) && (byte & 0x40)));
    PutByte(buffer, byte | (more << 7));
  }
  while (more);
}

// Length of an entry (CIE or FDE) at start, the entry is padded to 8 bytes with DW_CFA_nop

static void CloseEntry(struct Buffer* buffer, size_t start)
{
  uint32_t length;

  while ((buffer->length - start) % 8)
    PutByte(buffer, 0);

  if (buffer->failed == 0)
  {
    length = buffer->length - start - 4;
    memcpy(buffer->data + start, &length, 4);
  }
}

// Operations of an UNWIND_INFO in the order of the prolog. A chained one (UNW_FLAG_CHAININFO) continues the function
// of its parent: the operations of the parent come first and are in effect from the start of the fragment

static int ReadUnwindInfo(struct Source* source, uint32_t address, struct Operation* list, int* count, int depth, int chained)
{
  struct Operation operations[256];
  const uint8_t* information;
  const uint8_t* codes;
  int number;
  int total;
  int index;
  int size;
  uint8_t code;
  uint8_t info;

  if ((depth > CHAIN_DEPTH) ||
      ((information = Resolve(source, address, 4)) == NULL) ||
      (((information[0] & 7) != 1) && ((information[0] & 7) != 2)))
    return -1;

  total = information[2];
  codes = information + 4;

  if (Resolve(source, address, 4 + 2 * ((total + 1) & ~1) + ((information[0] >> 3) & UNW_FLAG_CHAININFO) * 3) == NULL)
    return -1;

  if (((information[0] >> 3) & UNW_FLAG_CHAININFO) &&
      (ReadUnwindInfo(source, READ32(codes + 2 * ((total + 1) & ~1) + 8), list, count, depth + 1, 1) < 0))
    return -1;

  number = 0;

  for (index = 0; index < total; index += size)
  {
    code = codes[2 * index + 1] & 15;
    info = codes[2 * index + 1] >> 4;
    size = 1;

    operations[number].offset = chained ? 0 : codes[2 * index];
    operations[number].code   = code;
    operations[number].info   = info;
    operations[number].frame  = information[3];
    operations[number].value  = 0;

    switch (code)
    {
      case UWOP_PUSH_NONVOL:
      case UWOP_SET_FPREG:
        break;

      case UWOP_ALLOC_SMALL:
        operations[number].value = info * 8 + 8;
        break;

      case UWOP_ALLOC_LARGE:
        size = (info == 0) ? 2 : 3;
        if (index + size > total)
          return -1;
        operations[number].value = (info == 0) ? READ16(codes + 2 * index + 2) * 8 : READ32(codes + 2 * index + 2);
        break;

      case UWOP_SAVE_NONVOL:
      case UWOP_EPILOG:
      case UWOP_SAVE_XMM128:
        size = 2;
        if (index + size > total)
          return -1;
        operations[number].value = READ16(codes + 2 * index + 2) * ((code == UWOP_SAVE_XMM128) ? 16 : 8);
        break;

      case UWOP_SAVE_NONVOL_FAR:
      case UWOP_SPARE_CODE:
      case UWOP_SAVE_XMM128_FAR:
        size = 3;
        if (index + size > total)
          return -1;
        operations[number].value = READ32(codes + 2 * index + 2);
        break;

      default:
        // UWOP_PUSH_MACHFRAME and unknown codes
        return -1;
    }

    // Descriptions of epilogues (version 2) keep sizes of epilogues instead of offsets in the prolog, XMM saves are
    // not described (see above)
    number += (code != UWOP_EPILOG) && (code != UWOP_SPARE_CODE) && (code != UWOP_SAVE_XMM128) && (code != UWOP_SAVE_XMM128_FAR);
  }

  if (*count + number > OPERATION_COUNT)
    return -1;

  // Codes are stored from the end of the prolog

  while (number > 0)
    list[(*count) ++] = operations[-- number];

  return 0;
}

static void Advance(struct Buffer* buffer, uint32_t* location, uint32_t target)
{
  uint32_t delta = target - *location;

  if (delta == 0)
    return;

  if (delta < 64)
    PutByte(buffer, DW_CFA_advance_loc | delta);
  else if (delta < 0x100)
  {
    PutByte(buffer, DW_CFA_advance_loc1);
    PutByte(buffer, delta);
  }
  else if (delta < 0x10000)
  {
    PutByte(buffer, DW_CFA_advance_loc2);
    Put(buffer, &delta, 2);
  }
  else
  {
    PutByte(buffer, DW_CFA_advance_loc4);
    Put(buffer, &delta, 4);
  }

  *location = target;
}

// What the prolog made, as an epilogue has to undo it

struct Shape
{
  uint8_t pushes[16];  // Registers pushed (numbers of UNWIND_CODE), in the order of the prolog
  int count;
  uint8_t saves[16];   // Registers saved by MOV
  int stored;
  int64_t allocated;   // Fixed allocation
  int64_t pushed;      // CFA - RSP at the end of the prolog
  int framed;
  uint8_t frame;       // FrameRegister
  int64_t anchor;      // CFA = FrameRegister + anchor
};

// A row of an epilogue: after the instruction ending at offset, CFA = RSP + value, and register (DWARF) is restored

struct Step
{
  uint32_t offset;
  int64_t value;
  int register_;
};

// Epilogues of x64 are canonical, that is how the unwinder of Windows recognizes them by code:
//   [add rsp, N | lea rsp, [FrameRegister + D]] pop (the pushes of the prolog in reverse) ret | jmp out of the function
// The pattern is strict (sizes and registers come from the prolog), so a match inside other instructions is not a
// concern. Returns the length of the epilogue at position, 0 when there is none

static uint32_t MatchEpilogue(const uint8_t* code, uint32_t length, uint32_t position, const struct Shape* shape, struct Step* steps, int* number)
{
  uint32_t cursor;
  int64_t released;
  int64_t value;
  uint8_t prefix;
  int register_;
  int index;

  cursor  = position;
  *number = 0;

  if ((shape->allocated > 0) ||
      (shape->framed != 0))
  {
    released = -1;

    if ((cursor + 4 <= length) && (memcmp(code + cursor, "\x48\x83\xc4", 3) == 0))
    {
      // add rsp, imm8
      released = code[cursor + 3];
      cursor  += 4;
    }
    else if ((cursor + 7 <= length) && (memcmp(code + cursor, "\x48\x81\xc4", 3) == 0))
    {
      // add rsp, imm32
      released = READ32(code + cursor + 3);
      cursor  += 7;
    }
    else if ((shape->framed != 0) &&
             ((shape->frame & 7) != 4) &&
             (cursor + 4 <= length) &&
             (code[cursor] == (0x48 | (shape->frame >> 3))) &&
             (code[cursor + 1] == 0x8d) &&
             ((code[cursor + 2] & 0x3f) == (0x20 | (shape->frame & 7))))
    {
      // lea rsp, [FrameRegister + disp8 / disp32]
      if ((code[cursor + 2] >> 6) == 1)
      {
        value   = (int8_t)code[cursor + 3];
        cursor += 4;
      }
      else if (((code[cursor + 2] >> 6) == 2) && (cursor + 7 <= length))
      {
        value   = (int32_t)READ32(code + cursor + 3);
        cursor += 7;
      }
      else
        return 0;

      // RSP = FrameRegister + value, CFA = FrameRegister + anchor: what is left must be the pushes and the return
      released = 0;
      if (shape->anchor - value != 8 + 8 * shape->count)
        return 0;
    }

    if ((released < 0) ||
        ((released > 0) && (released != shape->allocated)))
      return 0;

    steps[*number].offset    = cursor;
    steps[*number].value     = 8 + 8 * shape->count;
    steps[*number].register_ = -1;
    (*number) ++;
  }

  for (index = shape->count - 1; index >= 0; index --)
  {
    register_ = shape->pushes[index];
    prefix    = (register_ >= 8);

    if ((cursor + prefix + 1 > length) ||
        (prefix && (code[cursor] != 0x41)) ||
        (code[cursor + prefix] != 0x58 + (register_ & 7)))
      return 0;

    cursor += prefix + 1;

    steps[*number].offset    = cursor;
    steps[*number].value     = 8 + 8 * index;
    steps[*number].register_ = Registers[register_];
    (*number) ++;
  }

  if ((cursor < length) && (code[cursor] == 0xc3))
    cursor += 1;
  else if ((cursor + 2 <= length) && (memcmp(code + cursor, "\xf3\xc3", 2) == 0))
    cursor += 2;
  else if ((cursor + 5 <= length) && (code[cursor] == 0xe9))
  {
    // A tail call leaves the function
    value = (int64_t)cursor + 5 + (int32_t)READ32(code + cursor + 1);
    if ((value >= 0) && (value < length))
      return 0;
    cursor += 5;
  }
  else if ((cursor + 6 <= length) && (memcmp(code + cursor, "\xff\x25", 2) == 0))
    cursor += 6;
  else if ((cursor + 7 <= length) && (memcmp(code + cursor, "\x48\xff\x25", 3) == 0))
    cursor += 7;
  else
    return 0;

  // Nothing to describe: the state of the body is already the state at the entry
  if (*number == 0)
    return 0;

  return cursor - position;
}

// CFI of one function. CFA is RSP before the call, the CIE starts with CFA = RSP + 8 and the return address at CFA - 8.
// Saves (UWOP_SAVE_NONVOL) are relative to the frame base of Windows: RSP at UWOP_SET_FPREG when there is a frame
// register, RSP after the whole prolog otherwise. Epilogues get rows of their own

static int PutInstructions(struct Buffer* buffer, struct Source* source, const struct Range* range, const struct Operation* list, int count)
{
  struct Step steps[24];
  struct Shape shape;
  const uint8_t* code;
  uint32_t location;
  uint32_t position;
  uint32_t length;
  uint32_t size;
  int64_t distance;
  int64_t pushed;
  int64_t base;
  int framed;
  int number;
  int index;

  memset(&shape, 0, sizeof(shape));

  pushed = 8;
  base   = -1;

  for (index = 0; index < count; index ++)
  {
    switch (list[index].code)
    {
      case UWOP_PUSH_NONVOL:
        pushed += 8;
        if (shape.count < 16)
          shape.pushes[shape.count] = list[index].info;
        shape.count ++;
        break;

      case UWOP_ALLOC_SMALL:
      case UWOP_ALLOC_LARGE:
        pushed          += list[index].value;
        shape.allocated += list[index].value;
        break;

      case UWOP_SET_FPREG:
        if (shape.framed == 0)
        {
          base         = pushed;
          shape.framed = 1;
          shape.frame  = list[index].frame & 15;
          shape.anchor = pushed - (list[index].frame >> 4) * 16;
        }
        break;

      case UWOP_SAVE_NONVOL:
      case UWOP_SAVE_NONVOL_FAR:
        if (shape.stored < 16)
          shape.saves[shape.stored ++] = list[index].info;
        break;
    }
  }

  shape.pushed = pushed;

  if (base < 0)
    base = pushed;

  location = 0;
  pushed   = 8;
  framed   = 0;

  for (index = 0; index < count; index ++)
  {
    const struct Operation* operation = list + index;

    if (operation->offset < location)
      return -1;

    Advance(buffer, &location, operation->offset);

    switch (operation->code)
    {
      case UWOP_PUSH_NONVOL:
        pushed += 8;
        distance = pushed;
        break;

      case UWOP_ALLOC_SMALL:
      case UWOP_ALLOC_LARGE:
        pushed  += operation->value;
        distance = -1;
        break;

      case UWOP_SET_FPREG:
        // FrameRegister = RSP + FrameOffset * 16 = CFA - pushed + FrameOffset * 16
        if (pushed < (operation->frame >> 4) * 16)
          return -1;
        framed = 1;
        PutByte(buffer, DW_CFA_def_cfa);
        PutUnsigned(buffer, Registers[operation->frame & 15]);
        PutUnsigned(buffer, pushed - (operation->frame >> 4) * 16);
        continue;

      case UWOP_SAVE_NONVOL:
      case UWOP_SAVE_NONVOL_FAR:
        distance = base - operation->value;
        if (distance % 8)
          return -1;
        break;

      default:
        continue;
    }

    if ((framed == 0) &&
        ((operation->code == UWOP_PUSH_NONVOL) || (distance < 0)))
    {
      PutByte(buffer, DW_CFA_def_cfa_offset);
      PutUnsigned(buffer, pushed);
    }

    if (distance >= 0)
    {
      // The register is at CFA - distance, the data alignment of the CIE is -8
      PutByte(buffer, DW_CFA_offset_extended_sf);
      PutUnsigned(buffer, Registers[operation->info]);
      PutSigned(buffer, distance / 8);
    }
  }

  // Epilogues, after the prolog. More pushes than a pattern can hold: no rows, as before

  length = range->end - range->begin;
  code   = Resolve(source, range->begin, length);

  for (position = location; (code != NULL) && (shape.count <= 16) && (position < length); position += (size > 0) ? size : 1)
  {
    if ((size = MatchEpilogue(code, length, position, &shape, steps, &number)) == 0)
      continue;

    Advance(buffer, &location, position);
    PutByte(buffer, DW_CFA_remember_state);

    // Registers saved by MOV are loaded back before the epilogue, the stack below RSP is not theirs any more
    for (index = 0; index < shape.stored; index ++)
    {
      PutByte(buffer, DW_CFA_restore_extended);
      PutUnsigned(buffer, Registers[shape.saves[index]]);
    }

    for (index = 0; index < number; index ++)
    {
      Advance(buffer, &location, steps[index].offset);

      if ((index == 0) &&
          (framed != 0))
      {
        PutByte(buffer, DW_CFA_def_cfa);
        PutUnsigned(buffer, DWARF_RSP);
        PutUnsigned(buffer, steps[index].value);
      }
      else
      {
        PutByte(buffer, DW_CFA_def_cfa_offset);
        PutUnsigned(buffer, steps[index].value);
      }

      if (steps[index].register_ >= 0)
      {
        PutByte(buffer, DW_CFA_restore_extended);
        PutUnsigned(buffer, steps[index].register_);
      }
    }

    // After ret (or the jump out) the code that follows belongs to the body again
    Advance(buffer, &location, position + size);
    PutByte(buffer, DW_CFA_restore_state);
  }

  return 0;
}

static int CompareRanges(const void* first, const void* second)
{
  const struct Range* range1 = (const struct Range*)first;
  const struct Range* range2 = (const struct Range*)second;
  return (range1->begin > range2->begin) - (range1->begin < range2->begin);
}

// Functions of .pdata and the gaps of executable sections between them (leaves), sorted

static struct Range* GetRanges(struct Source* source, size_t* count)
{
  const uint8_t* field;
  const uint8_t* header;
  const uint8_t* optional;
  const uint8_t* section;
  const uint8_t* table;
  struct Range* ranges;
  uint32_t address;
  uint32_t length;
  uint32_t cursor;
  uint32_t limit;
  size_t functions;
  size_t number;
  size_t index;
  int sections;

  if (((field = Resolve(source, 0x3c, 4)) == NULL) ||
      ((header = Resolve(source, READ32(field), 24)) == NULL) ||
      ((optional = Resolve(source, READ32(field) + 24, READ16(header + 20))) == NULL) ||
      (READ16(header + 20) < 112 + 8 * 4))
    return NULL;

  sections = READ16(header + 6);

  if (Resolve(source, READ32(field) + 24 + READ16(header + 20), 40 * sections) == NULL)
    return NULL;

  address   = READ32(optional + 112 + 8 * 3);
  length    = READ32(optional + 112 + 8 * 3 + 4);
  functions = length / 12;

  if ((table = Resolve(source, address, length)) == NULL)
    functions = 0;

  // A gap per function at most, and one more per section

  if ((ranges = (struct Range*)calloc(2 * functions + sections + 1, sizeof(struct Range))) == NULL)
    return NULL;

  number = 0;

  for (index = 0; index < functions; index ++)
  {
    ranges[number].begin  = READ32(table + 12 * index);
    ranges[number].end    = READ32(table + 12 * index + 4);
    ranges[number].unwind = READ32(table + 12 * index + 8);

    if ((ranges[number].begin < ranges[number].end) &&
        (ranges[number].end <= source->size))
      number ++;
  }

  qsort(ranges, number, sizeof(struct Range), CompareRanges);
  functions = number;

  for (section = optional + READ16(header + 20); section < optional + READ16(header + 20) + 40 * sections; section += 40)
  {
    if ((READ32(section + 36) & IMAGE_SCN_MEM_EXECUTE) == 0)
      continue;

    cursor = READ32(section + 12);
    limit  = cursor + READ32(section + 8);

    if ((limit < cursor) ||
        (limit > source->size))
      continue;

    for (index = 0; (index < functions) && (cursor < limit); index ++)
    {
      if (ranges[index].end <= cursor)
        continue;

      if (ranges[index].begin > cursor)
      {
        ranges[number].begin = cursor;
        ranges[number].end   = (ranges[index].begin < limit) ? ranges[index].begin : limit;
        number ++;
      }

      cursor = ranges[index].end;
    }

    if (cursor < limit)
    {
      ranges[number].begin = cursor;
      ranges[number].end   = limit;
      number ++;
    }
  }

  qsort(ranges, number, sizeof(struct Range), CompareRanges);
  *count = number;
  return ranges;
}

// .eh_frame: one CIE, an FDE per range, the terminator. Pointers to code are absolute (origin is the address of the
// image) or relative to themselves (origin is the RVA the frames will have, the image and the frames move together).
// The table gets the RVA of each function and the offset of its FDE in the frames

static int BuildFrames(struct Source* source, int relative, uint64_t origin, struct Buffer* buffer, struct Entry** table, size_t* count)
{
  struct Module* image;
  struct Operation* list;
  struct Range* ranges;
  uint64_t value;
  size_t number;
  size_t offset;
  size_t start;
  int operations;

  image  = source->image;
  *count = 0;

  if ((ranges = GetRanges(source, &number)) == NULL)
    return -1;

  list   = (struct Operation*)malloc(OPERATION_COUNT * sizeof(struct Operation));
  *table = (struct Entry*)malloc((number + 1) * sizeof(struct Entry));

  if ((list   == NULL) ||
      (*table == NULL))
  {
    free(ranges);
    free(list);
    free(*table);
    return -1;
  }

  // CIE: version 1, "zR", code alignment 1, data alignment -8, return address in column 16, pointers absolute
  // (DW_EH_PE_absptr) or DW_EH_PE_pcrel | DW_EH_PE_sdata4

  Put(buffer, "\0\0\0\0" "\0\0\0\0" "\1" "zR", 12);        // length, CIE id 0, version, augmentation with its NUL
  PutUnsigned(buffer, 1);
  PutSigned(buffer, -8);
  PutUnsigned(buffer, DWARF_RETURN_ADDRESS);
  PutUnsigned(buffer, 1);
  PutByte(buffer, relative * 0x1b);
  PutByte(buffer, DW_CFA_def_cfa);
  PutUnsigned(buffer, DWARF_RSP);
  PutUnsigned(buffer, 8);
  PutByte(buffer, DW_CFA_offset | DWARF_RETURN_ADDRESS);
  PutUnsigned(buffer, 1);
  CloseEntry(buffer, 0);

  for (size_t index = 0; (index < number) && (buffer->failed == 0); index ++)
  {
    operations = 0;

    if ((ranges[index].unwind != 0) &&
        (ReadUnwindInfo(source, ranges[index].unwind, list, &operations, 0, 0) < 0))
    {
      LibraryReport(LOG_WARNING, "PE image %s has unwind information FrameBridge does not translate at 0x%x, its frames stop unwinding\n", image->name, ranges[index].begin);
      continue;
    }

    start = buffer->length;
    Put(buffer, "\0\0\0\0", 4);
    offset = buffer->length;                                      // CIE pointer: distance back to the CIE
    Put(buffer, &offset, 4);

    if (relative)
    {
      value = (uint64_t)ranges[index].begin - (origin + buffer->length);
      Put(buffer, &value, 4);
      value = ranges[index].end - ranges[index].begin;
      Put(buffer, &value, 4);
    }
    else
    {
      value = origin + ranges[index].begin;
      Put(buffer, &value, 8);
      value = ranges[index].end - ranges[index].begin;
      Put(buffer, &value, 8);
    }

    PutUnsigned(buffer, 0);

    if (PutInstructions(buffer, source, ranges + index, list, operations) < 0)
    {
      LibraryReport(LOG_WARNING, "PE image %s has unwind information FrameBridge does not translate at 0x%x, its frames stop unwinding\n", image->name, ranges[index].begin);
      buffer->length = start;
      continue;
    }

    CloseEntry(buffer, start);

    (*table)[*count].start = ranges[index].begin;
    (*table)[*count].frame = start;
    (*count) ++;
  }

  Put(buffer, "\0\0\0\0", 4);

  free(ranges);
  free(list);

  if (buffer->failed != 0)
  {
    free(buffer->data);
    free(*table);
    return -1;
  }

  return 0;
}

uint8_t* MakeLibraryFrames(struct Module* image, LibraryResolveFunction resolve, void* context, uint32_t origin, size_t* length, uint32_t** table, size_t* count)
{
  struct Source source;
  struct Buffer buffer;
  struct Entry* entries;

  source.image   = image;
  source.resolve = resolve;
  source.context = context;
  source.size    = image->size;

  memset(&buffer, 0, sizeof(buffer));

  if (BuildFrames(&source, 1, origin, &buffer, &entries, count) < 0)
    return NULL;

  *length = buffer.length;
  *table  = (uint32_t*)entries;
  return buffer.data;
}

// .eh_frame with absolute pointers and the search table of libunwind, mapped next to the image

static uint8_t* MakeFrame(struct Module* image, size_t* size, size_t* frames, size_t* entries)
{
  struct Source source;
  struct Buffer buffer;
  struct Entry* table;
  uint8_t* mapping;
  uint8_t* hint;
  size_t count;

  source.image   = image;
  source.resolve = ResolveImage;
  source.context = image;
  source.size    = image->size;

  memset(&buffer, 0, sizeof(buffer));

  if (BuildFrames(&source, 0, (uint64_t)image->base, &buffer, &table, &count) < 0)
    return NULL;

  // Next to the image: the search table of libunwind keeps 32-bit offsets from the image base

  // The place right after the image may be taken (by the ELF object of SymbolBridge.c, for example): steps of 1 MB
  // above it and below it, then anywhere

  *size   = (buffer.length + count * sizeof(struct Entry) + getpagesize() - 1) & ~((size_t)getpagesize() - 1);
  mapping = MAP_FAILED;

  for (int attempt = 0; (attempt < 64) && (mapping == MAP_FAILED); attempt ++)
  {
    uintptr_t step = (uintptr_t)(attempt >> 1) << 20;

    hint    = (attempt & 1) ?
      (uint8_t*)(((uintptr_t)image->base - *size - step) & ~((uintptr_t)getpagesize() - 1)) :
      (uint8_t*)(((uintptr_t)image->base + image->size + 0x10000 + step + getpagesize() - 1) & ~((uintptr_t)getpagesize() - 1));
    mapping = (uint8_t*)mmap(hint, *size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);

    if ((mapping != MAP_FAILED) &&
        (mapping != hint))
    {
      // Kernels before 4.17 take MAP_FIXED_NOREPLACE as a hint
      munmap(mapping, *size);
      mapping = MAP_FAILED;
    }
  }

  if (mapping == MAP_FAILED)
    mapping = (uint8_t*)mmap(NULL, *size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (mapping == MAP_FAILED)
  {
    free(buffer.data);
    free(table);
    return NULL;
  }

  memcpy(mapping, buffer.data, buffer.length);

  for (size_t index = 0; index < count; index ++)
    table[index].frame += (int32_t)(mapping - image->base);

  memcpy(mapping + buffer.length, table, count * sizeof(struct Entry));
  mprotect(mapping, *size, PROT_READ);

  *frames  = buffer.length;
  *entries = count;

  free(buffer.data);
  free(table);
  return mapping;
}

// ld.so knows the CFI of the image already: an object with PT_GNU_EH_FRAME covers it (SymbolBridge.c)

static int FindKnownFrames(struct dl_phdr_info* information, size_t size, void* argument)
{
  uintptr_t address = (uintptr_t)argument;
  int covered = 0;
  int framed  = 0;

  for (int index = 0; index < information->dlpi_phnum; index ++)
  {
    const ElfW(Phdr)* program = information->dlpi_phdr + index;

    covered |= (program->p_type == PT_LOAD) &&
               (address >= information->dlpi_addr + program->p_vaddr) &&
               (address <  information->dlpi_addr + program->p_vaddr + program->p_memsz);
    framed  |= (program->p_type == PT_GNU_EH_FRAME);
  }

  return covered && framed;
}

static void Register(struct Module* image)
{
  struct Bridge* bridge;
  size_t frames;
  size_t entries;
  uint8_t* lowest;
  uint8_t* highest;

  if ((dl_iterate_phdr(FindKnownFrames, image->base) != 0) ||
      ((bridge = (struct Bridge*)calloc(1, sizeof(struct Bridge))) == NULL))
    return;

  if ((bridge->frame = MakeFrame(image, &bridge->size, &frames, &entries)) == NULL)
  {
    LibraryReport(LOG_WARNING, "FrameBridge could not make unwind information of PE image %s\n", image->name);
    free(bridge);
    return;
  }

  bridge->image = image;

  if (__register_frame != NULL)
  {
    __register_frame(bridge->frame);
    bridge->registered = 1;

    // libgcc sorts FDEs of a registered object with malloc() at the first lookup: done here and not in the fault
    // handler that unwinds first, which may have interrupted malloc()

    if ((_Unwind_Find_FDE != NULL) &&
        (entries > 0))
    {
      void* bases[3];
      _Unwind_Find_FDE(image->base + ((struct Entry*)(bridge->frame + frames))->start, bases);
    }
  }

#ifdef HAVE_LIBUNWIND
  lowest  = (bridge->frame < image->base) ? bridge->frame : image->base;
  highest = (bridge->frame + bridge->size > image->base + image->size) ? bridge->frame + bridge->size : image->base + image->size;

  if (_U_dyn_register != NULL)
  {
    if (highest - lowest < INT32_MAX)
    {
      bridge->information.start_ip         = (unw_word_t)image->base;
      bridge->information.end_ip           = (unw_word_t)(image->base + image->size);
      bridge->information.format           = UNW_INFO_FORMAT_REMOTE_TABLE;
      bridge->information.u.rti.name_ptr   = (unw_word_t)image->name;
      bridge->information.u.rti.segbase    = (unw_word_t)image->base;
      bridge->information.u.rti.table_len  = entries * sizeof(struct Entry) / sizeof(unw_word_t);
      bridge->information.u.rti.table_data = (unw_word_t)(bridge->frame + frames);
      _U_dyn_register(&bridge->information);
      bridge->dynamic = 1;
    }
    else
      LibraryReport(LOG_WARNING, "FrameBridge could not place unwind information of PE image %s next to it, libunwind does not get it\n", image->name);
  }
#else
  (void)lowest;
  (void)highest;
#endif

  bridge->next = Bridges;
  Bridges      = bridge;
}

static void Unregister(struct Module* image)
{
  struct Bridge** pointer;
  struct Bridge* bridge;

  for (pointer = &Bridges; *pointer != NULL; pointer = &(*pointer)->next)
  {
    if ((*pointer)->image == image)
    {
      bridge   = *pointer;
      *pointer = bridge->next;

#ifdef HAVE_LIBUNWIND
      if (bridge->dynamic)
        _U_dyn_cancel(&bridge->information);
#endif

      if (bridge->registered)
        __deregister_frame(bridge->frame);

      munmap(bridge->frame, bridge->size);
      free(bridge);
      return;
    }
  }
}

static void Observe(int event, struct Module* image)
{
  if (event == LIBRARY_EVENT_LOADED)
    Register(image);

  if (event == LIBRARY_EVENT_UNLOADING)
    Unregister(image);
}

LIBRARY_OBSERVER(FrameBridge, Observe)
