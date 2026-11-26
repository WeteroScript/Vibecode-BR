#!/usr/bin/env python3
"""Карта PLT-заглушек libkolson.so и поиск вызовов импортируемых функций.

    python3 tools/kolson/plt_callers.py time clock_gettime
"""
import struct, sys
from elftools.elf.elffile import ELFFile

PATH = 'libkolson.so'


def build(path=PATH):
    raw = open(path, 'rb').read()
    f = ELFFile(open(path, 'rb'))
    # GOT (offset -> symbol) из .rela.plt
    got = {}
    for secname in ('.rela.plt', '.rela.dyn'):
        sec = f.get_section_by_name(secname)
        if not sec:
            continue
        for r in sec.iter_relocations():
            sym = f.get_section(r['r_info_sym']) if False else None
        # elftools: reloc_entry.symbol доступен через get_symbol
    dynsym = f.get_section_by_name('.dynsym')
    for secname in ('.rela.plt', '.rela.dyn'):
        sec = f.get_section_by_name(secname)
        if not sec:
            continue
        for r in sec.iter_relocations():
            idx = r['r_info_sym']
            if not idx:
                continue
            name = dynsym.get_symbol(idx).name
            if name:
                got.setdefault(r['r_offset'], name)
    # заглушки: adrp x16, page ; ldr x17,[x16,#off] ; ... br x17
    stubs = {}
    for i in range(0, len(raw) - 24, 4):
        w, = struct.unpack_from('<I', raw, i)
        if (w & 0x9F000000) != 0x90000000 or (w & 0x1F) != 16:
            continue
        imm = ((w >> 5) & 0x7FFFF) << 2 | ((w >> 29) & 3)
        if imm & (1 << 20):
            imm -= 1 << 21
        page = (i & ~0xFFF) + (imm << 12)
        w2, = struct.unpack_from('<I', raw, i + 4)
        if (w2 & 0xFFC00000) != 0xF9400000 or ((w2 >> 5) & 0x1F) != 16 or (w2 & 0x1F) != 17:
            continue
        g = page + ((w2 >> 10) & 0xFFF) * 8
        if g in got:
            stubs[i] = got[g]
    return raw, stubs


def callers(raw, stubs, name):
    targets = {a for a, n in stubs.items() if n == name}
    out = []
    for i in range(0, len(raw) - 4, 4):
        w, = struct.unpack_from('<I', raw, i)
        if (w & 0xFC000000) != 0x94000000:
            continue
        imm = w & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        if i + imm * 4 in targets:
            out.append(i)
    return sorted(set(out))


if __name__ == '__main__':
    raw, stubs = build()
    print('# заглушек найдено: %d' % len(stubs))
    for n in sys.argv[1:]:
        print('%-18s %s' % (n, [hex(x) for x in callers(raw, stubs, n)]))
