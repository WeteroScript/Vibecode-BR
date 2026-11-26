#!/usr/bin/env python3
"""For each `bl installer` site, print candidate 32-bit constants (movz/movk pairs => game RVAs)."""
import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM
INSTALLER=0x5908fc
elf=ELFFile(open(sys.argv[1],'rb')); t=elf.get_section_by_name('.text'); base=t['sh_addr']; code=t.data()
md=Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail=True
import struct
sites=[]
for off in range(0,len(code)-4,4):
    w=struct.unpack_from('<I',code,off)[0]
    if (w&0xFC000000)==0x94000000:
        imm=w&0x3FFFFFF
        if imm&0x2000000: imm-=0x4000000
        if base+off+imm*4==INSTALLER: sites.append(base+off)
def rn(r):
    n=md.reg_name(r) or '?'
    return n
for pc in sites:
    lo=max(base,pc-0x50); consts={}; out=[]
    for ins in md.disasm(code[lo-base:pc-base+4], lo):
        o=ins.operands
        if ins.mnemonic in ('mov','movz') and len(o)==2 and o[0].type==ARM64_OP_REG and o[1].type==ARM64_OP_IMM:
            consts[rn(o[0].reg)]=o[1].imm
        elif ins.mnemonic=='movk' and len(o)==2:
            r=rn(o[0].reg); sh=o[1].shift.value
            consts[r]=(consts.get(r,0)&~(0xffff<<sh))|(o[1].imm<<sh)
        elif ins.mnemonic=='add' and len(o)==3 and o[0].type==ARM64_OP_REG and o[1].type==ARM64_OP_REG and o[2].type==ARM64_OP_IMM:
            a,b=rn(o[0].reg),rn(o[1].reg)
            if b in consts: consts[a]=consts[b]+o[2].imm
        elif ins.mnemonic=='bl' and o and o[0].type==ARM64_OP_IMM and o[0].imm==INSTALLER:
            for r,v in consts.items():
                if 0x1000 < v < 0x2000000: out.append((r,v))
    hs=[x for x in out if x[0].startswith('x') or x[0].startswith('w')]
    rvas=sorted({v for r,v in out if v>=0x10000})
    print(f'{pc:#08x}  cands={[hex(v) for v in rvas][:6]}')
