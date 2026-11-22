#!/usr/bin/env python3
# Generates minimal PE32+ x86-64 DLLs for LoadLibraryTest.c, no Windows toolchain needed
#
#   C.dll  exports Mul(a, b) = a * b
#   B.dll  exports Add(a, b) = a + b, Mul -> forwarded to C.Mul, Pid() -> KERNEL32!GetCurrentProcessId
#   A.dll  imports B!Add, B!Mul, B!Nope (not exported), KERNEL32!GetCurrentProcessId
#          exports Twice(a) = Add(a, a), Square(a) = Mul(a, a), Pid(), Missing() -> B!Nope,
#          Table: 8 bytes, absolute address of Twice (DIR64 relocation)
#   D.dll, E.dll  Loop forwarded to each other (a loop of forwards)
#   B.dll  also exports Mul2 -> forwarded by ordinal to C.#1
#   A.dll  also imports B by ordinal #1 (Add) and #99 (does not exist):
#          TwiceByOrdinal(a) = B#1(a, a), MissingOrdinal() -> B!#99
#   F.dll  delay-imports B!Add: DelayedTwice(a) = Add(a, a), DelayHandle: the module handle slot of B
#   G.dll, H.dll  stripped relocations, both at ImageBase 0x200000000: Answer() = 42, Self: address of Answer
#   S.dll  SectionAlignment 0x200 (below the page size): Seven() = 7
#   T.dll  reads the TEB: GetSelf() = gs:[0x30], GetLimit() = gs:[0x10], GetThread() = gs:[0x48],
#          Big() has a frame of 20 KB and Huge() of 4 MB, both through __chkstk of MSVC (byte for byte),
#          GetLastErrorInline() = gs:[0x68], GetPeb() = gs:[0x60], GetTlsSlot0() = gs:[0x1480]
#   U.dll  static TLS (template 0x1122334455667788, 8 bytes of zero fill): GetTls(), SetTls(v), GetZero(),
#          a TLS callback and DllMain, both report to TEST.dll!Note(who, reason): callback 1, DllMain 2
#   W.dll  imports U!GetTls, DllMain reports as 3
#   V.dll  DllMain reports as 4 and returns FALSE
#   X.dll  unwind information (.pdata/.xdata) for FrameBridgeTest.c: Outer(callback, value) has a frame pointer,
#          pushes, a save by MOV and a dynamic allocation only the frame pointer describes, and calls Middle(),
#          whose body is a chained fragment calling callback(value); Trap() is a leaf without .pdata (ud2)
#
# usage: LoadLibraryTest.py <output directory>

import os
import struct
import sys

SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT    = 0x200
TEXT_RVA          = 0x1000
DATA_RVA          = 0x2000


def align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


class Code:
    # Instructions with RIP-relative references, resolved when the data layout is known

    def __init__(self):
        self.bytes = bytearray()
        self.fixups = []  # (offset of rel32, symbol)
        self.labels = {}

    def label(self, name):
        self.labels[name] = len(self.bytes)

    def emit(self, data):
        self.bytes += bytes(data)

    def rip(self, prefix, symbol, suffix=b''):
        # prefix + rel32 + suffix, rel32 is relative to the end of the instruction
        self.emit(prefix)
        self.fixups.append((len(self.bytes), symbol, len(suffix)))
        self.emit(b'\0\0\0\0')
        self.emit(suffix)


def build(name, base, code, imports, exports, data_items, delayed=None, fixed=False, section_alignment=SECTION_ALIGNMENT, tls=None, entry_point=None, pdata=None):
    # imports:    {dll: [function or ordinal, ...]}, IAT entries are symbols "iat:dll!function" ("iat:dll!#n")
    # delayed:    {dll: [function, ...]}, IAT entries "diat:dll!function", the module handle "dhandle:dll"
    # fixed:      stripped relocations, the image works at its ImageBase only
    # tls:        {'template': bytes, 'zero': n, 'callback': label or None}, the index is the symbol "tls:index"
    # entry_point: label of DllMain
    # pdata:      [{'begin', 'end', 'prolog', 'frame': (register, offset / 16), 'codes': [(offset, op, info, [slots])], 'chain': index}]
    #             codes in the order of the prolog, a chained entry refers to an earlier one
    # exports:    [(name, ("code", label) | ("forward", "C.Mul") | ("data", item))]
    # data_items: {item: ("pointer", label)}, 8 bytes with DIR64 relocation

    data = bytearray()
    symbols = {}
    relocations = []

    def put(blob, alignment=8):
        while len(data) % alignment:
            data.append(0)
        offset = len(data)
        data.extend(blob)
        return DATA_RVA + offset

    # Import directory: descriptors first, then lookup tables, IAT, names

    dlls = list(imports)
    descriptors = put(b'\0' * 20 * (len(dlls) + 1))
    entries = {}
    for dll in dlls:
        lookup = put(b'\0' * 8 * (len(imports[dll]) + 1))
        iat = put(b'\0' * 8 * (len(imports[dll]) + 1))
        dll_name = put(dll.encode() + b'\0', 2)
        entries[dll] = (lookup, iat, dll_name)
        for index, function in enumerate(imports[dll]):
            if isinstance(function, int):
                entry = 0x8000000000000000 | function
                symbols['iat:%s!#%d' % (dll, function)] = iat + 8 * index
            else:
                entry = put(struct.pack('<H', 0) + function.encode() + b'\0', 2)
                symbols['iat:%s!%s' % (dll, function)] = iat + 8 * index
            struct.pack_into('<Q', data, lookup - DATA_RVA + 8 * index, entry)
            struct.pack_into('<Q', data, iat - DATA_RVA + 8 * index, entry)
    for index, dll in enumerate(dlls):
        lookup, iat, dll_name = entries[dll]
        struct.pack_into('<IIIII', data, descriptors - DATA_RVA + 20 * index, lookup, 0, 0, dll_name, iat)
    import_size = 20 * (len(dlls) + 1)

    # Delayed imports (RVA format): Attributes, DllName, ModuleHandle, IAT, INT, BoundIAT, UnloadIAT, TimeDateStamp

    delayed = delayed or {}
    delay_dlls = list(delayed)
    delay_descriptors = put(b'\0' * 32 * (len(delay_dlls) + 1), 4) if delay_dlls else 0
    for index, dll in enumerate(delay_dlls):
        names = put(b'\0' * 8 * (len(delayed[dll]) + 1))
        iat = put(b'\0' * 8 * (len(delayed[dll]) + 1))
        handle = put(b'\0' * 8)
        dll_name = put(dll.encode() + b'\0', 2)
        symbols['dhandle:' + dll] = handle
        for position, function in enumerate(delayed[dll]):
            hint = put(struct.pack('<H', 0) + function.encode() + b'\0', 2)
            struct.pack_into('<Q', data, names - DATA_RVA + 8 * position, hint)
            symbols['diat:%s!%s' % (dll, function)] = iat + 8 * position
        struct.pack_into('<IIIIIIII', data, delay_descriptors - DATA_RVA + 32 * index, 1, dll_name, handle, iat, names, 0, 0, 0)
    delay_size = 32 * (len(delay_dlls) + 1) if delay_dlls else 0

    # Data items

    for item, (kind, label) in data_items.items():
        symbols['data:' + item] = put(b'\0' * (label if kind == 'zero' else 8))

    # Unwind information and the exception directory

    pdata = pdata or []
    unwind = []
    for entry in pdata:
        codes = []
        for offset, op, info, slots in reversed(entry['codes']):
            codes.append(struct.pack('<BB', offset, op | (info << 4)))
            codes += [struct.pack('<H', slot) for slot in slots]
        count = len(codes)
        if count % 2:
            codes.append(b'\0\0')
        register, scaled = entry.get('frame') or (0, 0)
        chained = entry.get('chain') is not None
        blob = struct.pack('<BBBB', 1 | ((4 if chained else 0) << 3), entry['prolog'], count, register | (scaled << 4)) + b''.join(codes)
        if chained:
            parent = pdata[entry['chain']]
            blob += struct.pack('<III', TEXT_RVA + code.labels[parent['begin']], TEXT_RVA + code.labels[parent['end']], unwind[entry['chain']])
        unwind.append(put(blob, 4))
    exception = put(b''.join(struct.pack('<III', TEXT_RVA + code.labels[entry['begin']], TEXT_RVA + code.labels[entry['end']], rva)
                             for entry, rva in zip(pdata, unwind)), 4) if pdata else 0
    exception_size = 12 * len(pdata)

    # TLS: template, index, callbacks, directory (VAs are filled when code is placed)

    if tls:
        tls_start = put(tls['template'], 8)
        tls_end = tls_start + len(tls['template'])
        symbols['tls:index'] = put(b'\0' * 4, 4)
        tls_callbacks = put(b'\0' * 16)
        tls_directory = put(b'\0' * 40)

    # Export directory, names sorted as Windows requires

    exports = sorted(exports)
    directory = put(b'\0' * 40, 4)
    functions = put(b'\0' * 4 * len(exports), 4)
    names = put(b'\0' * 4 * len(exports), 4)
    ordinals = put(b'\0' * 2 * len(exports), 2)
    module_name = put(name.encode() + b'\0', 1)
    forwards = {}
    for index, (export, (kind, value)) in enumerate(exports):
        string = put(export.encode() + b'\0', 1)
        struct.pack_into('<I', data, names - DATA_RVA + 4 * index, string)
        struct.pack_into('<H', data, ordinals - DATA_RVA + 2 * index, index)
        if kind == 'forward':
            forwards[index] = put(value.encode() + b'\0', 1)
    export_size = DATA_RVA + len(data) - directory
    struct.pack_into('<IIHHIIIIIII', data, directory - DATA_RVA,
                     0, 0, 0, 0, module_name, 1, len(exports), len(exports), functions, names, ordinals)

    # Code RVAs are known now: fill exports and data pointers

    def code_rva(label):
        return TEXT_RVA + code.labels[label]

    for index, (export, (kind, value)) in enumerate(exports):
        if kind == 'code':
            target = code_rva(value)
        elif kind == 'forward':
            target = forwards[index]
        elif kind == 'symbol':
            target = symbols[value]
        else:
            target = symbols['data:' + value]
        struct.pack_into('<I', data, functions - DATA_RVA + 4 * index, target)

    for item, (kind, label) in data_items.items():
        if kind != 'pointer':
            continue
        address = symbols['data:' + item]
        struct.pack_into('<Q', data, address - DATA_RVA, base + code_rva(label))
        if not fixed:
            relocations.append(address)

    if tls:
        fields = [base + tls_start, base + tls_end, base + symbols['tls:index'], base + tls_callbacks]
        struct.pack_into('<QQQQII', data, tls_directory - DATA_RVA, *fields, tls['zero'], 0)
        relocations += [tls_directory + 8 * index for index in range(4)]
        if tls.get('callback'):
            struct.pack_into('<Q', data, tls_callbacks - DATA_RVA, base + code_rva(tls['callback']))
            relocations.append(tls_callbacks)

    # Base relocations, one block per page

    blocks = bytearray()
    pages = {}
    for address in relocations:
        pages.setdefault(address & ~0xfff, []).append(address & 0xfff)
    for page, offsets in sorted(pages.items()):
        items = [(10 << 12) | offset for offset in offsets]
        if len(items) % 2:
            items.append(0)
        blocks += struct.pack('<II', page, 8 + 2 * len(items)) + b''.join(struct.pack('<H', item) for item in items)
    reloc = put(bytes(blocks), 4) if blocks else 0
    reloc_size = len(blocks)

    # Code labels are symbols too (calls inside the image)

    for label, offset in code.labels.items():
        symbols['code:' + label] = TEXT_RVA + offset

    # Resolve RIP-relative references in code

    text = bytearray(code.bytes)
    for offset, symbol, tail in code.fixups:
        target = symbols[symbol]
        end = TEXT_RVA + offset + 4 + tail
        struct.pack_into('<i', text, offset, target - end)

    # Headers

    text_raw = align(len(text), FILE_ALIGNMENT)
    data_raw = align(len(data), FILE_ALIGNMENT)
    headers_size = 0x400
    image_size = DATA_RVA + align(len(data), SECTION_ALIGNMENT)

    dos = bytearray(64)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3c, 64)

    coff = struct.pack('<HHIIIHH', 0x8664, 2, 0, 0, 0, 240, 0x2023 if fixed else 0x2022)

    directories = [(0, 0)] * 16
    directories[0] = (directory, export_size)
    directories[1] = (descriptors, import_size)
    directories[3] = (exception, exception_size)
    directories[5] = (reloc, reloc_size)
    directories[13] = (delay_descriptors, delay_size)
    if tls:
        directories[9] = (tls_directory, 40)

    optional = struct.pack('<HBBIIIIIQIIHHHHHHIIIIHHQQQQII',
                           0x20b, 14, 0, text_raw, data_raw, 0, code_rva(entry_point) if entry_point else 0, TEXT_RVA, base,
                           section_alignment, FILE_ALIGNMENT, 6, 0, 0, 0, 6, 0, 0,
                           image_size, headers_size, 0, 3, 0x0140,
                           0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    optional += b''.join(struct.pack('<II', rva, size) for rva, size in directories)
    assert len(optional) == 240

    sections = struct.pack('<8sIIIIIIHHI', b'.text', len(text), TEXT_RVA, text_raw, headers_size, 0, 0, 0, 0, 0x60000020)
    sections += struct.pack('<8sIIIIIIHHI', b'.data', len(data), DATA_RVA, data_raw, headers_size + text_raw, 0, 0, 0, 0, 0xC0000040)

    header = bytes(dos) + b'PE\0\0' + coff + optional + sections
    image = header + b'\0' * (headers_size - len(header))
    image += bytes(text) + b'\0' * (text_raw - len(text))
    image += bytes(data) + b'\0' * (data_raw - len(data))
    return image


def main():
    output = sys.argv[1]
    os.makedirs(output, exist_ok=True)

    # C.dll: Mul(a, b)

    code = Code()
    code.label('Mul')
    code.emit(b'\x89\xc8\x0f\xaf\xc2\xc3')               # mov eax, ecx; imul eax, edx; ret
    images = {'C.dll': build('C.dll', 0x10000000, code, {}, [('Mul', ('code', 'Mul'))], {})}

    # B.dll: Add(a, b), Mul -> C.Mul, Pid() -> KERNEL32!GetCurrentProcessId

    code = Code()
    code.label('Add')
    code.emit(b'\x8d\x04\x11\xc3')                       # lea eax, [rcx + rdx]; ret
    code.label('Pid')
    code.rip(b'\xff\x25', 'iat:KERNEL32.dll!GetCurrentProcessId')  # jmp [rip + iat]
    images['B.dll'] = build('B.dll', 0x10000000, code,
                            {'KERNEL32.dll': ['GetCurrentProcessId']},
                            [('Add', ('code', 'Add')), ('Mul', ('forward', 'C.Mul')), ('Mul2', ('forward', 'C.#1')), ('Pid', ('code', 'Pid'))], {})

    # A.dll

    code = Code()
    code.label('Twice')
    code.emit(b'\x48\x83\xec\x28\x89\xca')               # sub rsp, 40; mov edx, ecx
    code.rip(b'\xff\x15', 'iat:B.dll!Add')               # call [rip + iat]
    code.emit(b'\x48\x83\xc4\x28\xc3')                   # add rsp, 40; ret
    code.label('Square')
    code.emit(b'\x48\x83\xec\x28\x89\xca')
    code.rip(b'\xff\x15', 'iat:B.dll!Mul')
    code.emit(b'\x48\x83\xc4\x28\xc3')
    code.label('Pid')
    code.rip(b'\xff\x25', 'iat:KERNEL32.dll!GetCurrentProcessId')
    code.label('Missing')
    code.rip(b'\xff\x25', 'iat:B.dll!Nope')
    code.label('TwiceByOrdinal')
    code.emit(b'\x48\x83\xec\x28\x89\xca')
    code.rip(b'\xff\x15', 'iat:B.dll!#1')
    code.emit(b'\x48\x83\xc4\x28\xc3')
    code.label('MissingOrdinal')
    code.rip(b'\xff\x25', 'iat:B.dll!#99')
    images['A.dll'] = build('A.dll', 0x10000000, code,
                            {'B.dll': ['Add', 'Mul', 'Nope', 1, 99], 'KERNEL32.dll': ['GetCurrentProcessId']},
                            [('Twice', ('code', 'Twice')), ('Square', ('code', 'Square')), ('Pid', ('code', 'Pid')),
                             ('Missing', ('code', 'Missing')), ('Table', ('data', 'Table')),
                             ('TwiceByOrdinal', ('code', 'TwiceByOrdinal')), ('MissingOrdinal', ('code', 'MissingOrdinal'))],
                            {'Table': ('pointer', 'Twice')})

    # D.dll and E.dll: a loop of forwards, D.Loop -> E.Loop -> D.Loop

    images['D.dll'] = build('D.dll', 0x10000000, Code(), {}, [('Loop', ('forward', 'E.Loop'))], {})
    images['E.dll'] = build('E.dll', 0x10000000, Code(), {}, [('Loop', ('forward', 'D.Loop'))], {})

    # F.dll: delayed import of B!Add

    code = Code()
    code.label('DelayedTwice')
    code.emit(b'\x48\x83\xec\x28\x89\xca')
    code.rip(b'\xff\x15', 'diat:B.dll!Add')
    code.emit(b'\x48\x83\xc4\x28\xc3')
    images['F.dll'] = build('F.dll', 0x10000000, code, {}, [('DelayedTwice', ('code', 'DelayedTwice')), ('DelayHandle', ('symbol', 'dhandle:B.dll'))], {},
                            delayed={'B.dll': ['Add']})

    # G.dll and H.dll: stripped relocations, the same ImageBase

    for name in ('G.dll', 'H.dll'):
        code = Code()
        code.label('Answer')
        code.emit(b'\xb8\x2a\x00\x00\x00\xc3')     # mov eax, 42; ret
        images[name] = build(name, 0x200000000, code, {}, [('Answer', ('code', 'Answer')), ('Self', ('data', 'Self'))],
                             {'Self': ('pointer', 'Answer')}, fixed=True)

    # S.dll: SectionAlignment below the page size

    code = Code()
    code.label('Seven')
    code.emit(b'\xb8\x07\x00\x00\x00\xc3')         # mov eax, 7; ret
    images['S.dll'] = build('S.dll', 0x10000000, code, {}, [('Seven', ('code', 'Seven'))], {}, section_alignment=0x200)

    # T.dll: TEB and __chkstk

    code = Code()
    code.label('Chkstk')
    code.emit(bytes.fromhex('4883ec10' '4c891424' '4c895c2408' '4d33db' '4c8d542418' '4c2bd0' '4d0f42d3'
                            '654c8b1c2510000000' '4d3bd3' '7316' '664181e200f0' '4d8d9b00f0ffff' '41c60300'
                            '4d3bd3' '75f0' '4c8b1424' '4c8b5c2408' '4883c410' 'c3'))
    code.label('GetSelf')
    code.emit(bytes.fromhex('65488b042530000000c3'))          # mov rax, gs:[0x30]; ret
    code.label('GetLimit')
    code.emit(bytes.fromhex('65488b042510000000c3'))          # mov rax, gs:[0x10]; ret
    code.label('GetThread')
    code.emit(bytes.fromhex('658b042548000000c3'))            # mov eax, gs:[0x48]; ret
    code.label('GetLastErrorInline')
    code.emit(bytes.fromhex('658b042568000000c3'))            # mov eax, gs:[0x68]; ret
    code.label('GetPeb')
    code.emit(bytes.fromhex('65488b042560000000c3'))          # mov rax, gs:[0x60]; ret
    code.label('GetTlsSlot0')
    code.emit(bytes.fromhex('65488b042580140000c3'))          # mov rax, gs:[0x1480]; ret
    for label, size in (('Big', 0x5000), ('Huge', 0x400000)):
        code.label(label)
        code.emit(b'\xb8' + struct.pack('<I', size))           # mov eax, size
        code.rip(b'\xe8', 'code:Chkstk')                       # call __chkstk
        code.emit(b'\x48\x29\xc4\xc6\x04\x24\x01')            # sub rsp, rax; mov byte [rsp], 1
        code.emit(b'\x48\x81\xc4' + struct.pack('<I', size))   # add rsp, size
        code.emit(b'\xb8\x01\x00\x00\x00\xc3')                # mov eax, 1; ret
    images['T.dll'] = build('T.dll', 0x10000000, code, {},
                            [(label, ('code', label)) for label in ('GetSelf', 'GetLimit', 'GetThread', 'Big', 'Huge', 'GetLastErrorInline', 'GetPeb', 'GetTlsSlot0')], {})

    # U.dll: static TLS, a TLS callback and DllMain reporting to TEST.dll!Note

    def note(code, who, entry):
        # rdx is the reason already; DllMain also returns TRUE (or FALSE for V)
        if entry is None:
            code.emit(b'\xb9' + struct.pack('<I', who))           # mov ecx, who
            code.rip(b'\xff\x25', 'iat:TEST.dll!Note')            # jmp [rip + iat]
            return
        code.emit(b'\x48\x83\xec\x28')                         # sub rsp, 40
        code.emit(b'\xb9' + struct.pack('<I', who))
        code.rip(b'\xff\x15', 'iat:TEST.dll!Note')               # call [rip + iat]
        code.emit(b'\x48\x83\xc4\x28')                         # add rsp, 40
        code.emit(b'\xb8' + struct.pack('<I', entry) + b'\xc3')  # mov eax, result; ret

    tls_access = bytes.fromhex('654c8b142558000000' '4d8b14c2')     # mov r10, gs:[0x58]; mov r10, [r10 + rax * 8]
    code = Code()
    code.label('Callback')
    note(code, 1, None)
    code.label('DllMain')
    note(code, 2, 1)
    code.label('GetTls')
    code.rip(b'\x8b\x05', 'tls:index')                         # mov eax, [rip + index]
    code.emit(tls_access + bytes.fromhex('498b02c3'))             # mov rax, [r10]; ret
    code.label('SetTls')
    code.rip(b'\x8b\x05', 'tls:index')
    code.emit(tls_access + bytes.fromhex('49890ac3'))             # mov [r10], rcx; ret
    code.label('GetZero')
    code.rip(b'\x8b\x05', 'tls:index')
    code.emit(tls_access + bytes.fromhex('498b4208c3'))           # mov rax, [r10 + 8]; ret
    images['U.dll'] = build('U.dll', 0x10000000, code, {'TEST.dll': ['Note']},
                            [(label, ('code', label)) for label in ('GetTls', 'SetTls', 'GetZero')], {},
                            tls={'template': struct.pack('<Q', 0x1122334455667788), 'zero': 8, 'callback': 'Callback'},
                            entry_point='DllMain')

    code = Code()
    code.label('DllMain')
    note(code, 3, 1)
    code.label('Value')
    code.rip(b'\xff\x25', 'iat:U.dll!GetTls')                  # jmp [rip + iat]
    images['W.dll'] = build('W.dll', 0x10000000, code, {'TEST.dll': ['Note'], 'U.dll': ['GetTls']},
                            [('Value', ('code', 'Value'))], {}, entry_point='DllMain')

    code = Code()
    code.label('DllMain')
    note(code, 4, 0)
    images['V.dll'] = build('V.dll', 0x10000000, code, {'TEST.dll': ['Note']}, [('DllMain', ('code', 'DllMain'))], {}, entry_point='DllMain')

    # X.dll: unwind information for FrameBridgeTest.c

    code = Code()
    code.label('Outer')
    code.emit(b'\x55')                                   # push rbp                   1
    code.emit(b'\x53')                                   # push rbx                   2
    code.emit(b'\x48\x83\xec\x48')                       # sub rsp, 0x48              6
    code.emit(b'\x48\x8d\x6c\x24\x20')                   # lea rbp, [rsp + 0x20]      11
    code.emit(b'\x48\x89\x74\x24\x40')                   # mov [rsp + 0x40], rsi      16
    code.emit(b'\x48\x83\xec\x30')                       # sub rsp, 0x30: dynamic, only rbp describes the frame now
    code.rip(b'\xe8', 'code:Middle')                     # call Middle (rcx, rdx pass through)
    code.emit(b'\x48\x83\xc4\x30')                       # add rsp, 0x30
    code.emit(b'\x48\x8b\x74\x24\x40')                   # mov rsi, [rsp + 0x40]
    code.emit(b'\x48\x83\xc4\x48')                       # add rsp, 0x48
    code.emit(b'\x5b\x5d\xc3')                           # pop rbx; pop rbp; ret
    code.label('OuterEnd')
    code.emit(b'\xcc' * 3)
    code.label('Middle')
    code.emit(b'\x48\x81\xec\x88\x00\x00\x00')           # sub rsp, 0x88              7
    code.label('MiddleBody')
    code.emit(b'\x48\x89\xc8')                           # mov rax, rcx
    code.emit(b'\x48\x89\xd1')                           # mov rcx, rdx
    code.emit(b'\xff\xd0')                               # call rax
    code.emit(b'\x48\x81\xc4\x88\x00\x00\x00')           # add rsp, 0x88
    code.emit(b'\xc3')
    code.label('MiddleEnd')
    code.emit(b'\xcc' * 5)                               # a gap: covered as a leaf
    code.label('Trap')
    code.emit(b'\x0f\x0b\xc3')                           # ud2; ret
    code.label('TrapEnd')
    unwind_info = [
        {'begin': 'Outer', 'end': 'OuterEnd', 'prolog': 16, 'frame': (5, 2),
         'codes': [(1, 0, 5, []), (2, 0, 3, []), (6, 2, (0x48 - 8) // 8, []), (11, 3, 0, []), (16, 4, 6, [0x40 // 8])]},
        {'begin': 'Middle', 'end': 'MiddleBody', 'prolog': 7, 'codes': [(7, 1, 0, [0x88 // 8])]},
        {'begin': 'MiddleBody', 'end': 'MiddleEnd', 'prolog': 0, 'codes': [], 'chain': 1}]
    images['X.dll'] = build('X.dll', 0x10000000, code, {},
                            [(label, ('code', label)) for label in ('Outer', 'OuterEnd', 'Middle', 'MiddleBody', 'MiddleEnd', 'Trap', 'TrapEnd')], {},
                            pdata=unwind_info)

    for name, image in images.items():
        with open(os.path.join(output, name), 'wb') as file:
            file.write(image)


if __name__ == '__main__':
    main()
