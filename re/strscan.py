#!/usr/bin/env python3
"""List string references (adrp+add / adrp+ldr) inside an address window.

usage: strscan.py <so> <start_va> <end_va> [--min N]
"""
import sys, argparse
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_MEM, ARM64_OP_IMM

ap = argparse.ArgumentParser()
ap.add_argument('so'); ap.add_argument('start'); ap.add_argument('end')
ap.add_argument('--min', type=int, default=4)
a = ap.parse_args()
lo, hi = int(a.start, 16), int(a.end, 16)

elf = ELFFile(open(a.so, 'rb')); raw = open(a.so, 'rb').read()
segs = [(s['p_vaddr'], s['p_filesz'], s['p_offset']) for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']


def cstr(va):
    for v, sz, off in segs:
        if v <= va < v + sz:
            o = off + va - v
            e = raw.find(b'\0', o)
            if e < 0 or e - o > 300:
                return None
            try:
                s = raw[o:e].decode('utf-8')
            except UnicodeDecodeError:
                return None
            return s if all(c in '\n\t' or ord(c) >= 32 for c in s) else None
    return None


t = elf.get_section_by_name('.text'); base = t['sh_addr']; code = t.data()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True
page = {}; out = {}
for ins in md.disasm(code[lo - base:hi - base], lo):
    if ins.mnemonic == 'adrp':
        page[ins.operands[0].reg] = ins.operands[1].imm
        continue
    ops = ins.operands
    if len(ops) < 2 or ops[0].type != ARM64_OP_REG:
        continue
    va = None
    if ins.mnemonic == 'add' and len(ops) == 3 and ops[1].type == ARM64_OP_REG \
            and ops[2].type == ARM64_OP_IMM and ops[1].reg in page:
        va = page[ops[1].reg] + ops[2].imm      # adrp xN, #page ; add xM, xN, #off
    elif ins.mnemonic == 'ldr' and ops[1].type == ARM64_OP_MEM \
            and ops[1].mem.base in page and ops[1].mem.index == 0:
        va = page[ops[1].mem.base] + ops[1].mem.disp
    if va is None:
        continue
    s = cstr(va)
    if s and len(s) >= a.min:
        out.setdefault(s, []).append(ins.address)

for s, addrs in sorted(out.items(), key=lambda kv: kv[1][0]):
    print(f'{addrs[0]:#010x} {s[:120]!r}')
