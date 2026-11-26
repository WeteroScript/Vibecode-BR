#!/usr/bin/env python3
"""adrp/add xref finder for AArch64 ELF (Android .so)."""
import sys, struct
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG

path = sys.argv[1]
needles = [n.encode() for n in sys.argv[2:]]

f = open(path, 'rb')
elf = ELFFile(f)
def v2o(va):
    for s in elf.iter_sections():
        a = s['sh_addr']; n = s['sh_size']
        if s['sh_type'] != 'SHT_NOBITS' and a <= va < a+n:
            return s['sh_offset'] + (va-a)
    return None

data = open(path,'rb').read()
targets = {}
for nd in needles:
    start = 0
    while True:
        i = data.find(nd, start)
        if i < 0: break
        # map offset -> vaddr
        va = None
        for s in elf.iter_sections():
            if s['sh_type']=='SHT_NOBITS': continue
            o=s['sh_offset']; n=s['sh_size']
            if o <= i < o+n: va = s['sh_addr'] + (i-o); sec=s.name; break
        if va is not None:
            targets[va] = (sec, nd.decode('utf-8','replace'))
        start = i+1
print(f'string targets: {len(targets)}')
            
text = elf.get_section_by_name('.text')
code = text.data(); base = text['sh_addr']
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True

regs = {}
hits = []
for ins in md.disasm(code, base):
    m = ins.mnemonic
    if m == 'adrp':
        # op1 = reg, op2 = imm (page)
        try:
            reg = ins.operands[0].reg
            imm = ins.operands[1].imm
        except Exception:
            continue
        regs[reg] = imm
    elif m == 'add' and len(ins.operands) == 3:
        o = ins.operands
        if o[0].type==ARM64_OP_REG and o[1].type==ARM64_OP_REG and o[2].type==ARM64_OP_IMM:
            r = o[1].reg
            if r == o[0].reg and r in regs:
                tgt = regs[r] + o[2].imm
                if tgt in targets:
                    hits.append((ins.address, tgt))

print(f'xrefs: {len(hits)}')
seen=set()
for a,t in hits:
    if (a,t) in seen: continue
    seen.add((a,t))
    print(f'  {a:#x} -> {t:#x}  {targets[t][0]:10} {targets[t][1][:60]}')
