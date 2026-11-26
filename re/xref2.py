#!/usr/bin/env python3
import sys, struct
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
elf=ELFFile(open(sys.argv[1],'rb')); t=elf.get_section_by_name('.text'); base=t['sh_addr']; code=t.data()
targets=[int(x,0) for x in sys.argv[2:]]
hits={x:[] for x in targets}
for off in range(0,len(code)-4,4):
    w=struct.unpack_from('<I',code,off)[0]
    if (w&0xFC000000)==0x94000000:
        imm=w&0x3FFFFFF
        if imm&0x2000000: imm-=0x4000000
        dst=base+off+imm*4
        if dst in hits: hits[dst].append(base+off)
for k,v in hits.items(): print(f'{k:#x} <- ' + ', '.join(f'{x:#x}' for x in v[:12]) + (f' (+{len(v)-12})' if len(v)>12 else ''))
