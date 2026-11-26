#!/usr/bin/env python3
"""For each installed hook handler in libkolson.so, print the strings it logs (=> purpose)
and the target it patches in libblackrussia-client.so."""
import sys, struct
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM

elf = ELFFile(open(sys.argv[1],'rb'))
text = elf.get_section_by_name('.text'); base=text['sh_addr']; code=text.data()
ro   = elf.get_section_by_name('.rodata'); rob=ro.data(); roa=ro['sh_addr']
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail=True

def cstr(va):
    o = va-roa
    if o<0 or o>=len(rob): return None
    e = rob.find(b'\0', o)
    if e<0 or e-o>400: return None
    try: t = rob[o:e].decode('utf-8')
    except Exception: return None
    if len(t)<2 or not all(32<=ord(c)<127 or c in '\n\t' for c in t): return None
    return t

def strings_in(fn, nbytes=0x600):
    regs={}; out=[]
    for ins in md.disasm(code[fn-base:fn-base+nbytes], fn):
        o=ins.operands
        if ins.mnemonic=='adrp' and len(o)==2 and o[0].type==ARM64_OP_REG and o[1].type==ARM64_OP_IMM:
            regs[o[0].reg]=o[1].imm
        elif ins.mnemonic=='add' and len(o)==3 and o[0].type==ARM64_OP_REG and o[1].type==ARM64_OP_REG and o[2].type==ARM64_OP_IMM:
            if o[1].reg in regs:
                t=cstr(regs[o[1].reg]+o[2].imm)
                if t: out.append((ins.address,t))
        elif ins.mnemonic=='ret' and len(o)==0:
            pass
    return out

sites = [l.split() for l in open('re/out/hook_sites.txt') if l.strip().startswith('site')]
seen=set()
print(f'{"handler":<12} {"logs":<60}')
for s in sites:
    h = [x for x in s if x.startswith('handler=')][0].split('=')[1]
    if not h.startswith('0x'): continue
    hv=int(h,16)
    if hv in seen: continue
    seen.add(hv)
    ss = strings_in(hv)
    uniq=[]
    for a,t in ss:
        if t not in uniq: uniq.append(t)
    print(f'{h:<12} {"; ".join(uniq)[:150]}')
