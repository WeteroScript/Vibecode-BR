#!/usr/bin/env python3
"""Ищем ссылки на адрес (строку/данные) в AArch64-коде libkolson.so.

Сопоставление VA -> файловое смещение берётся из PT_LOAD, так что годится
и для .rodata выше 0x7764b0 (там смещение не совпадает с VA).

    python3 tools/kolson/xrefs.py 0x73a26 0x74ae5 ...
"""
import struct, sys
from elftools.elf.elffile import ELFFile

PATH = 'libkolson.so'


def load(path=PATH):
    data = open(path, 'rb').read()
    segs = []
    f = ELFFile(open(path, 'rb'))
    for s in f.iter_segments():
        if s['p_type'] == 'PT_LOAD':
            segs.append((s['p_vaddr'], s['p_offset'], s['p_filesz']))
    return data, segs


def off2va(off, segs):
    for va, po, sz in segs:
        if po <= off < po + sz:
            return off - po + va
    return None


def va2off(va, segs):
    for v, po, sz in segs:
        if v <= va < v + sz:
            return va - v + po
    return None


def xrefs(data, segs, target, span=6):
    hits = []
    for i in range(0, len(data) - 4 * span, 4):
        w, = struct.unpack_from('<I', data, i)
        if (w & 0x9F000000) != 0x90000000:      # adrp
            continue
        rd = w & 0x1F
        imm = ((w >> 5) & 0x7FFFF) << 2 | ((w >> 29) & 3)
        if imm & (1 << 20):
            imm -= 1 << 21
        page = (i & ~0xFFF) + (imm << 12)       # file-offset арифметика
        for k in range(1, span):
            w2, = struct.unpack_from('<I', data, i + 4 * k)
            op = w2 & 0xFFC00000
            if ((w2 >> 5) & 0x1F) != rd:
                continue
            if op == 0x91000000:                              # add xN, xN, #imm
                t = page + ((w2 >> 10) & 0xFFF)
            elif op in (0xF9400000, 0xF9000000, 0xB9400000, 0xB9000000,
                        0x39400000, 0x39000000):               # ldr/str [xN, #imm]
                scale = 8 if op in (0xF9400000, 0xF9000000) else 4
                t = page + ((w2 >> 10) & 0xFFF) * scale
            else:
                continue
            if off2va(t, segs) == target:
                hits.append(off2va(i, segs))
                break
    return sorted(set(hits))


if __name__ == '__main__':
    data, segs = load()
    for a in sys.argv[1:]:
        t = int(a, 16)
        print('%#x -> %s' % (t, [hex(x) for x in xrefs(data, segs, t)]))
