#!/usr/bin/env python3
"""
kolson_hooks.py - static extractor for the Kolson/NEIZZIR launcher payload.

Pulls out of libkolson.so:
  * the inline-hook installer (AArch64 `A64_HOOK`) and every call site feeding it
  * the 18-entry expected-code fingerprint table used as a pre-patch gate
  * for each hook: the target RVA inside libblackrussia-client.so, the 4 expected
    instruction words, the lokal handler and the strings that handler logs
  * the JNINativeMethod table registered from JNI_OnLoad
  * the stock weapon.json table (the payload the weapon hook restores/swaps)

Output: hooks.json / natives.json / stock_weapon.json next to -o.

Usage:
  ./kolson_hooks.py libkolson.so -o out/
Needs: pyelftools, capstone (/usr/bin/env python3 -m venv .venv && pip install pyelftools capstone)
"""
import argparse, json, os, re, struct, sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM

INSTALLER_DEFAULT = 0x5908FC          # hook(void *target, void *handler, void **orig)
FP_TABLE_DEFAULT  = 0x74180          # .rodata, 18 * {u64 rva, u64 w0, u64 w1}
FP_TABLE_END      = 0x74330
FP_WORDS          = 4                # 16 bytes of expected code compared before patching
JNI_TABLE_DEFAULT = 0x5E5E38         # JNINativeMethod[] : {name, sig, fn} * 8
JNI_TABLE_END     = 0x5E5EF8
WEAPON_JSON_MAGIC = b'{"weapons":[{"aimAndMeleeButton"'


class Bin:
    def __init__(self, path):
        self.path = path
        self.raw = open(path, 'rb').read()
        self.elf = ELFFile(open(path, 'rb'))
        self.secs = []
        for s in self.elf.iter_sections():
            self.secs.append((s.name, s['sh_addr'], s['sh_size'], s['sh_offset'], s['sh_type']))
        self.text = self.elf.get_section_by_name('.text')
        self.tbase = self.text['sh_addr']
        self.tcode = self.text.data()
        self.relocs = {}
        rel = self.elf.get_section_by_name('.rela.dyn')
        if rel is not None:
            for r in rel.iter_relocations():
                self.relocs[r['r_offset']] = r['r_addend'] if r.is_RELA() else 0

    def va2off(self, va):
        for name, addr, size, off, typ in self.secs:
            if typ == 'SHT_NOBITS':
                continue
            if addr <= va < addr + size:
                return off + (va - addr)
        return None

    def q(self, va):
        if va in self.relocs:
            return self.relocs[va]
        o = self.va2off(va)
        if o is None or o + 8 > len(self.raw):
            return 0
        return struct.unpack_from('<Q', self.raw, o)[0]

    def cstr(self, va, maxlen=200):
        o = self.va2off(va)
        if o is None:
            return None
        e = self.raw.find(b'\0', o)
        if e < 0 or e - o > maxlen:
            return None
        try:
            t = self.raw[o:e].decode('utf-8')
        except UnicodeDecodeError:
            return None
        if not t or any(not (32 <= ord(c) < 127 or c in '\t\n') for c in t):
            return None
        return t


def canon(md, reg):
    n = md.reg_name(reg) or '?'
    return ('x' + n[1:]) if n.startswith('w') else n


def find_install_sites(b, installer):
    out = []
    code = b.tcode
    for off in range(0, len(code) - 4, 4):
        w = struct.unpack_from('<I', code, off)[0]
        if (w & 0xFC000000) != 0x94000000:          # BL
            continue
        imm = w & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        if b.tbase + off + imm * 4 == installer:
            out.append(b.tbase + off)
    return out


def analyse_site(md, b, pc):
    """Recover x0 (target) and x1 (handler) for the installer call at pc."""
    lo = max(b.tbase, pc - 0x90)
    consts, pages, handler, imm0 = {}, {}, None, None
    for ins in md.disasm(b.tcode[lo - b.tbase: pc - b.tbase + 4], lo):
        o = ins.operands
        m = ins.mnemonic
        if len(o) == 2 and o[0].type == ARM64_OP_REG and o[1].type == ARM64_OP_IMM:
            r = canon(md, o[0].reg)
            if m == 'adrp':
                pages[r] = o[1].imm
            elif m in ('mov', 'movz'):
                consts[r] = o[1].imm
            elif m == 'movk':
                sh = o[1].shift.value
                consts[r] = consts.get(r, 0) | (o[1].imm << sh)
        elif m == 'add' and len(o) == 3 and o[0].type == ARM64_OP_REG and \
                o[1].type == ARM64_OP_REG and o[2].type == ARM64_OP_IMM:
            d, s = canon(md, o[0].reg), canon(md, o[1].reg)
            if d == 'x1' and s == 'x1':
                handler = (pages.get('x1', 0) + o[2].imm) if 'x1' in pages else o[2].imm
            if d == 'x0' and s == 'x0':
                imm0 = o[2].imm
    return imm0, handler, consts


def strings_in(md, b, fn, nbytes=0x400):
    regs, out = {}, []
    lo = max(b.tbase, fn)
    for ins in md.disasm(b.tcode[lo - b.tbase: lo - b.tbase + nbytes], lo):
        o = ins.operands
        if ins.mnemonic == 'adrp' and len(o) == 2 and o[0].type == ARM64_OP_REG and o[1].type == ARM64_OP_IMM:
            regs[o[0].reg] = o[1].imm
        elif ins.mnemonic == 'add' and len(o) == 3 and o[0].type == ARM64_OP_REG and \
                o[1].type == ARM64_OP_REG and o[2].type == ARM64_OP_IMM and o[1].reg in regs:
            t = b.cstr(regs[o[1].reg] + o[2].imm)
            if t and t not in out:
                out.append(t)
    return out


def fingerprint_table(b, tbl, end, words):
    res = []
    for k in range((end - tbl) // 0x18):
        rva, w0, w1 = struct.unpack_from('<3Q', b.raw, b.va2off(tbl) + k * 0x18)
        w = [(w0 >> (32 * i)) & 0xFFFFFFFF for i in (0, 1)] + [(w1 >> (32 * i)) & 0xFFFFFFFF for i in (0, 1)]
        res.append({'index': k, 'game_rva': rva, 'expected_words': w[:words]})
    return res


def jni_natives(b, tbl, end):
    out = []
    o = b.va2off(tbl)
    if o is None:
        return out
    for k in range((end - tbl) // 24):
        va = tbl + k * 24
        nm = b.cstr(b.q(va))
        sg = b.cstr(b.q(va + 8))
        fn = b.q(va + 16)
        if not nm or not sg or not (0x137e40 <= fn < 0x5e007c):
            break
        out.append({'name': nm, 'signature': sg, 'fn_va': fn})
    return out


def weapon_table(b):
    i = b.raw.find(WEAPON_JSON_MAGIC)
    if i < 0:
        return None
    depth, end = 0, None
    for j in range(i, min(len(b.raw), i + 0x100000)):
        c = b.raw[j]
        if c == 0x7b:
            depth += 1
        elif c == 0x7d:
            depth -= 1
            if depth == 0:
                end = j + 1
                break
    if end is None:
        return None
    try:
        return json.loads(b.raw[i:end].decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        return None


def build(b, installer, tbl, tbl_end, words, jni_tbl, jni_end):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    fp = fingerprint_table(b, tbl, tbl_end, words)
    fmap = {f['game_rva']: f for f in fp}
    hooks, seen = [], set()
    for pc in find_install_sites(b, installer):
        imm0, handler, consts = analyse_site(md, b, pc)
        cand = [v for v in consts.values() if v in fmap]
        rva = imm0 if imm0 in fmap else (cand[0] if cand else None)
        if rva is None or (rva, handler) in seen:
            continue
        seen.add((rva, handler))
        f = fmap[rva]
        hooks.append({
            'game_rva': rva,
            'fingerprint_index': f['index'],
            'expected_words': f['expected_words'],
            'installer_site': pc,
            'handler_va': handler,
            'handler_logs': strings_in(md, b, handler)[:8] if handler else [],
        })
    attributed = {h['fingerprint_index'] for h in hooks}
    for f in fp:
        if f['index'] not in attributed:
            hooks.append({'game_rva': f['game_rva'], 'fingerprint_index': f['index'],
                          'expected_words': f['expected_words'], 'installer_site': None,
                          'handler_va': None, 'handler_logs': []})
    hooks.sort(key=lambda h: h['game_rva'])
    return {
        'source': os.path.basename(b.path),
        'installer_va': installer,
        'fingerprint_table_va': tbl,
        'expected_bytes_compared': words * 4,
        'patch_stub': {'insn0': hex(0x58000051), 'insn1': hex(0xD61F0220),
                       'meaning': 'ldr x17, #8 ; br x17 ; .quad handler'},
        'hooks': hooks,
        'natives': jni_natives(b, jni_tbl, jni_end),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('so')
    ap.add_argument('-o', '--out', default='out')
    ap.add_argument('--installer', type=lambda x: int(x, 0), default=INSTALLER_DEFAULT)
    ap.add_argument('--fp-table', type=lambda x: int(x, 0), default=FP_TABLE_DEFAULT)
    ap.add_argument('--fp-end', type=lambda x: int(x, 0), default=FP_TABLE_END)
    ap.add_argument('--jni-table', type=lambda x: int(x, 0), default=JNI_TABLE_DEFAULT)
    ap.add_argument('--jni-end', type=lambda x: int(x, 0), default=JNI_TABLE_END)
    ap.add_argument('--words', type=int, default=FP_WORDS)
    a = ap.parse_args()

    os.makedirs(a.out, exist_ok=True)
    b = Bin(a.so)
    man = build(b, a.installer, a.fp_table, a.fp_end, a.words, a.jni_table, a.jni_end)
    json.dump(man, open(os.path.join(a.out, 'hooks.json'), 'w'), indent=1)

    wp = weapon_table(b)
    if wp:
        json.dump(wp, open(os.path.join(a.out, 'stock_weapon.json'), 'w'), indent=1)

    print(f'{len(man["hooks"])} hooks ({sum(1 for h in man["hooks"] if h["handler_va"])} with handler), '
          f'{len(man["natives"])} JNI natives, weapons={len(wp["weapons"]) if wp else 0}')
    for h in man['hooks']:
        print(f"  game+{h['game_rva']:#09x} fp[{h['fingerprint_index']:>2}] "
              f"handler={('0x%x' % h['handler_va']) if h['handler_va'] else '-':>10}  {h['handler_logs'][:2]}")


if __name__ == '__main__':
    sys.exit(main())
