#!/usr/bin/env python3
"""Decode the 18-entry expected-code fingerprint table at .rodata+0x74180."""
import sys, struct
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
elf=ELFFile(open(sys.argv[1],'rb'))
ro=elf.get_section_by_name('.rodata'); rob=ro.data(); roa=ro['sh_addr']
md=Cs(CS_ARCH_ARM64, CS_MODE_ARM)
tbl=int(sys.argv[2],0) if len(sys.argv)>2 else 0x74180
def dec(w):
    b=struct.pack('<I',w)
    ins=list(md.disasm(b,0))
    return (ins[0].mnemonic+' '+ins[0].op_str) if ins else '??'
for k in range((0x74330-tbl)//0x18):
    off,e0,e1=struct.unpack_from('<3Q',rob,tbl-roa+k*0x18)
    w=[ (e0>>(32*i))&0xFFFFFFFF for i in (0,1) ]+[ (e1>>(32*i))&0xFFFFFFFF for i in (0,1) ]
    print(f'[{k:2d}] game+{off:#010x}  {dec(w[0]):<28} | {dec(w[1]):<28} | {dec(w[2]):<28} | {dec(w[3])}')
