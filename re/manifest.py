#!/usr/bin/env python3
"""Build hooks.json: correlate fingerprint table <-> installer call sites <-> handlers."""
import sys, struct, json, re
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM

path=sys.argv[1]; out=sys.argv[2]
INSTALLER=0x5908fc; TBL=0x74180; TBL_END=0x74330
elf=ELFFile(open(path,'rb')); d=open(path,'rb').read()
text=elf.get_section_by_name('.text'); base=text['sh_addr']; code=text.data()
ro=elf.get_section_by_name('.rodata'); rob=ro.data(); roa=ro['sh_addr']
md=Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail=True

def cstr(va):
    o=va-roa
    if o<0 or o>=len(rob): return None
    e=rob.find(b'\0',o)
    if e<0 or e-o>160: return None
    t=rob[o:e].decode('utf-8','replace')
    return t if t and all(32<=ord(c)<127 or c in '\n\t' for c in t) else None

finger=[]
for k in range((TBL_END-TBL)//0x18):
    rva,e0,e1=struct.unpack_from('<3Q',rob,TBL-roa+k*0x18)
    finger.append({'idx':k,'rva':rva,'words':[ (e0>>(32*i))&0xffffffff for i in (0,1)]+[ (e1>>(32*i))&0xffffffff for i in (0,1)]})
fmap={f['rva']:f['idx'] for f in finger}

sites=[]
for off in range(0,len(code)-4,4):
    w=struct.unpack_from('<I',code,off)[0]
    if (w&0xFC000000)!=0x94000000: continue
    imm=w&0x3FFFFFF
    if imm&0x2000000: imm-=0x4000000
    if base+off+imm*4==INSTALLER: sites.append(base+off)

def cstrs_in(fn, nb=0x400):
    regs={}; out=[]
    for ins in md.disasm(code[fn-base:fn-base+nb], fn):
        o=ins.operands
        if ins.mnemonic=='adrp' and len(o)==2 and o[0].type==ARM64_OP_REG and o[1].type==ARM64_OP_IMM: regs[o[0].reg]=o[1].imm
        elif ins.mnemonic=='add' and len(o)==3 and o[0].type==ARM64_OP_REG and o[1].type==ARM64_OP_REG and o[2].type==ARM64_OP_IMM and o[1].reg in regs:
            t=cstr(regs[o[1].reg]+o[2].imm)
            if t and t not in out: out.append(t)
    return out

CANON=lambda r: ('x'+md.reg_name(r)[1:]) if (md.reg_name(r) or '').startswith('w') else md.reg_name(r)
res=[]
for pc in sites:
    lo=max(base,pc-0x90); consts={}; pages={}; handler=None; imm0=None
    for ins in md.disasm(code[lo-base:pc-base+4], lo):
        o=ins.operands; m=ins.mnemonic
        if len(o)==2 and o[0].type==ARM64_OP_REG and o[1].type==ARM64_OP_IMM:
            r=CANON(o[0].reg)
            if m=='adrp': pages[r]=o[1].imm
            elif m in ('mov','movz'): consts[r]=o[1].imm
            elif m=='movk':
                sh=o[1].shift.value; consts[r]=consts.get(r,0)|(o[1].imm<<sh)
        elif m=='add' and len(o)==3 and o[0].type==ARM64_OP_REG and o[1].type==ARM64_OP_REG and o[2].type==ARM64_OP_IMM:
            d=CANON(o[0].reg); s2=CANON(o[1].reg)
            if d=='x1' and s2=='x1':
                handler=(pages.get('x1',0)+o[2].imm) if 'x1' in pages else o[2].imm
            if d=='x0' and s2=='x0': imm0=o[2].imm
    cand=[v for r,v in consts.items() if v in fmap]
    rva = imm0 if (imm0 in fmap) else (cand[0] if cand else None)
    res.append({'site':pc,'rva':rva,'tbl_idx':fmap.get(rva),'handler':handler})

hooks=[]; seen=set()
for r in res:
    if r['rva'] is None: continue
    if (r['rva'], r['handler']) in seen: continue
    seen.add((r['rva'], r['handler']))
    hooks.append({
        'game_rva': r['rva'],
        'fingerprint_index': r['tbl_idx'],
        'expected_code_words': finger[r['tbl_idx']]['words'] if r['tbl_idx'] is not None else None,
        'installer_site': r['site'],
        'handler_va': r['handler'],
        'handler_logs': cstrs_in(r['handler'])[:6] if r['handler'] else [],
    })
# fingerprint entries with no attributed install site
known={h['fingerprint_index'] for h in hooks}
for f in finger:
    if f['idx'] not in known:
        hooks.append({'game_rva':f['rva'],'fingerprint_index':f['idx'],'expected_code_words':f['words'],
                      'installer_site':None,'handler_va':None,'handler_logs':[]})
hooks.sort(key=lambda x: x['game_rva'])
json.dump({'source':'libkolson.so','installer':INSTALLER,'fingerprint_table':TBL,'hooks':hooks}, open(out,'w'), indent=1)
print(f'{len(hooks)} hooks written to {out}')
for h in hooks:
    print(f"  game+{h['game_rva']:#09x} tbl[{h['fingerprint_index']:>2}] handler={h['handler_va'] and hex(h['handler_va']) or '-'}  {h['handler_logs'][:2]}")
