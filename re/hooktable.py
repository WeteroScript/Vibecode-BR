#!/usr/bin/env python3
"""Recover every inline-hook install site: (game_rva, handler, ctx) for each `bl 0x5908fc`.
Usage: hooktable.py libkolson.so [installer_va]
"""
import sys, struct
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM

INSTALLER = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x5908fc
elf = ELFFile(open(sys.argv[1], 'rb'))
text = elf.get_section_by_name('.text'); base = text['sh_addr']; code = text.data()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True

def canon(r):
    n = md.reg_name(r) or '?'
    return 'x' + n[1:] if n.startswith('w') else n

sites = []
for off in range(0, len(code) - 4, 4):
    w = struct.unpack_from('<I', code, off)[0]
    if (w & 0xFC000000) == 0x94000000:
        imm = w & 0x03FFFFFF
        if imm & 0x02000000: imm -= 0x04000000
        if base + off + imm * 4 == INSTALLER:
            sites.append(base + off)

def analyze(pc):
    lo = max(base, pc - 0x90)
    st = {}
    for ins in md.disasm(code[lo - base:pc - base + 4], lo):
        o = ins.operands; m = ins.mnemonic
        if len(o) == 2 and o[0].type == ARM64_OP_REG and o[1].type == ARM64_OP_IMM:
            d = canon(o[0].reg)
            if m == 'adrp': st[d] = ('page', o[1].imm)
            elif m in ('mov', 'movz'): st[d] = ('const', o[1].imm)
            elif m == 'movk':
                sh = o[1].shift.value; cur = st.get(d)
                st[d] = ('const', (cur[1] if cur and cur[0] == 'const' else 0) | (o[1].imm << sh))
        elif len(o) == 3 and o[0].type == ARM64_OP_REG and o[2].type == ARM64_OP_IMM and o[1].type == ARM64_OP_REG:
            d = canon(o[0].reg); s = canon(o[1].reg)
            if m in ('add', 'sub'):
                sg = 1 if m == 'add' else -1
                imm = o[2].imm
                if getattr(o[2], 'shift', None) and o[2].shift.type:
                    imm = o[2].imm << o[2].shift.value
                if s in st and st[s][0] in ('page', 'const'): st[d] = ('const', st[s][1] + sg * imm)
                elif s in st and st[s][0] == 'reg': st[d] = ('reg', st[s][1], st[s][2] + sg * imm)
                else: st[d] = ('reg', s, sg * imm)
            elif m == 'ldr':
                st[d] = ('mem', s, o[2].imm)
        elif len(o) == 3 and o[0].type == ARM64_OP_REG and o[1].type == ARM64_OP_REG and o[2].type == ARM64_OP_REG:
            a, b, c = canon(o[0].reg), canon(o[1].reg), canon(o[2].reg)
            if m in ('add', 'sub') and a in st and st[a][0] == 'const' and b in st and st[b][0] == 'const':
                st[c] = ('const', st[a][1] + st[b][1])
        if m == 'bl' and not (o and o[0].type == ARM64_OP_IMM and o[0].imm == INSTALLER):
            for k in list(st):
                if k.startswith('x') and k[1:].isdigit() and int(k[1:]) < 19: st.pop(k, None)
        if m == 'bl' and o and o[0].type == ARM64_OP_IMM and o[0].imm == INSTALLER:
            return st.get('x0'), st.get('x1'), st.get('x2')
    return (None, None, None)

def fmt(s):
    if not s: return '-'
    if s[0] in ('const', 'page'): return hex(s[1])
    if s[0] == 'reg': return '%s%+d' % (s[1], s[2])
    if s[0] == 'mem': return '[%s%+d]' % (s[1], s[2])
    return str(s)

print('installer %#x, call sites: %d' % (INSTALLER, len(sites)))
for pc in sites:
    x0, x1, x2 = analyze(pc)
    print('  site %#08x  target=%-18s handler=%-12s ctx=%s' % (pc, fmt(x0), fmt(x1), fmt(x2)))
