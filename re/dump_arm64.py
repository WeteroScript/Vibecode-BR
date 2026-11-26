#!/usr/bin/env python3
import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM

path, start, count = sys.argv[1], int(sys.argv[2],0), int(sys.argv[3])
f=open(path,'rb'); elf=ELFFile(f)
text=elf.get_section_by_name('.text'); base=text['sh_addr']; code=text.data()
ro=elf.get_section_by_name('.rodata'); rob=ro.data(); roa=ro['sh_addr']
def str_at(va):
    o=va-roa
    if o<0 or o>=len(rob): return None
    end=rob.find(b'\x00',o)
    s=rob[o:end]
    try: t=s.decode('utf-8')
    except: return None
    if all(32<=ord(c)<127 or c in '\n\t' for c in t) and len(t)>1: return t
    return None
md=Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail=True
off=start-base
regs={}
for ins in md.disasm(code[off:off+4*count], start):
    ann=''
    if ins.mnemonic=='adrp':
        regs[ins.operands[0].reg]=ins.operands[1].imm
    elif ins.mnemonic in ('add','ldr','str','adr') and len(ins.operands)>=2:
        o=ins.operands
        if o[1].type==ARM64_OP_REG and o[1].reg in regs and len(o)>2 and o[2].type==ARM64_OP_IMM:
            tgt=regs[o[1].reg]+o[2].imm
            s=str_at(tgt) if ins.mnemonic=='add' else None
            if s: ann='; "%s"'%s[:90]
            elif ins.mnemonic=='add': ann='; @%#x'%tgt
        if o[1].type==ARM64_OP_MEM and o[1].mem.base in regs:
            tgt=regs[o[1].mem.base]+o[1].mem.disp
            s=str_at(tgt)
            if s: ann='; "%s"'%s[:90]
    print(f'{ins.address:#08x}  {ins.mnemonic:<8}{ins.op_str}{ann}')
