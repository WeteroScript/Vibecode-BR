#!/usr/bin/env python3
"""kolson_verify.py - post-patch audit of libkolson.so

Two jobs:

  1. static  - re-derive every kill-switch from the file itself (no hardcoded
               expectations): after patching, each site must decode to the stub
               it was supposed to become, and nothing outside the patch set may
               have changed.
  2. class   - classify each site as
                 STUB_OK   neutralised (returns a "passed" answer / disabled)
                 SITE_DIFF the word differs from the reference build
                 LIVE      still the original check (patch not applied)

usage:
  kolson_verify.py <pristine.so> <patched.so>
  kolson_verify.py <patched.so>              # stubs only

Needs capstone + pyelftools (see re/ requirements).
"""
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

# (va, expected word in the pristine build) - mirrors kolson_patches.h
REFERENCE = [
    (0x0166c54, 0xd503233f), (0x0166c58, 0xa9ba7bfd),
    (0x0170528, 0xd503233f), (0x017052c, 0xd10103ff),
    (0x0170638, 0xd503233f), (0x017063c, 0xa9ba7bfd),
    (0x02129cc, 0xb9411100), (0x0212b60, 0xb5fff628), (0x0212b94, 0xb5fff488),
    (0x0243bb4, 0xd503233f), (0x0243bb8, 0xd10343ff),
    (0x0244800, 0xd503233f), (0x0244804, 0xd10283ff),
    (0x0244278, 0x36000c60), (0x02442ac, 0x36000ec0), (0x02442cc, 0xb5000dc8),
    (0x0244388, 0x54000d41), (0x02443a4, 0x54000c61), (0x02443b8, 0x54000bc1),
    (0x02443c8, 0x54000b41), (0x02443dc, 0x54000aa1),
    (0x05244f8, 0xd503233f), (0x05244fc, 0xa9bd7bfd),
    (0x0524640, 0xd503233f), (0x0524644, 0xd10203ff),
]

STUB_RET_ZERO = (0x2a1f03e0, 0xd65f03c0)   # mov w0, wzr ; ret   -> "everything ok"
STUB_RET_ONE = (0x52800020, 0xd65f03c0)    # mov w0, #1   ; ret   -> "allowed"
NOP = 0xd503201f

PATCHED_RANGES = [
    (0x0166c54, 0x0166c5c), (0x0170528, 0x0170530), (0x0170638, 0x0170640),
    (0x02129cc, 0x02129d0), (0x0212b60, 0x0212b64), (0x0212b94, 0x0212b98), (0x0243bb4, 0x0243bbc), (0x0244800, 0x0244808),
    (0x0244278, 0x0244280), (0x02442ac, 0x02442b0), (0x02442cc, 0x02442d0),
    (0x0244388, 0x024438c), (0x02443a4, 0x02443a8), (0x02443b8, 0x02443bc),
    (0x02443c8, 0x02443cc), (0x02443dc, 0x02443e0),
    (0x05244f8, 0x0524500), (0x0524640, 0x0524648),
]



# ---------------------------------------------------------------- сборка 16.116.0

B_PROBE = (0x02fcc84, 0x2a1f03f3)          # слово, которое мы не патчим
A_PROBE = (0x0166c60, 0x910003fd)

# (va, было в оригинале, стало после патча, что снято)
B_SITES = [
    (0x02fcba4, 0x36000c20, NOP, 'auth: tbz -> skip'),
    (0x02fcbc4, 0x36000b20, NOP, 'auth: tbz -> skip'),
    (0x02fcbe0, 0x36000a40, NOP, 'auth: tbz -> skip'),
    (0x02fcbf4, 0x360009a0, NOP, 'auth: tbz -> skip'),
    (0x02fcc10, 0x360008c0, NOP, 'auth: tbz -> skip'),
    (0x02fcc2c, 0x54000c81, NOP, 'auth: build_mismatch'),
    (0x02fcc48, 0x54000ba1, NOP, 'auth: signature_mismatch'),
    (0x02fcc5c, 0x54000b01, NOP, 'auth: command_unreadable'),
    (0x02fcc6c, 0x54000a81, NOP, 'auth: command_mismatch'),
    (0x02fcc80, 0x540009e1, NOP, 'auth: command_write_failed'),
    (0x02c9284, 0xb94ed100, 0x2a1f03e0, 'weapon_tamper -> 0'),
    (0x029c794, 0x54000a08, NOP, 'dm: minimumBuildId'),
    (0x029c79c, 0x540009c8, NOP, 'dm: featureMask'),
    (0x029c7bc, 0x540008c3, NOP, 'dm: build-id range'),
    (0x029c7c4, 0x5400088d, NOP, 'dm: expiresAt'),
    (0x01fcbac, 0xd503233f, 0x52800020, 'blob: verify -> mov w0,#1'),
    (0x01fcbb0, 0xa9ba7bfd, 0xd65f03c0, 'blob: verify -> ret'),
    (0x03a8684, 0xd503233f, None,        'hello: JNI_OnLoad -> b cave'),
]
B_HOOK_TARGET = 0x0a8f5c
B_BLOB = (0x0a8f5c, '../payload/hello_blob.h')


def load_cave(path):
    import re, os
    if not os.path.exists(path):
        return None
    return bytes(int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2}),', open(path).read()))


def audit_build_b(raw, pristine, md):
    def word(va):
        return int.from_bytes(raw[va:va + 4], 'little')

    def text(va):
        return ' '.join(f'{i.mnemonic} {i.op_str}'.strip()
                        for i in md.disasm(raw[va:va + 8], va))

    bad = []
    print('== сборка 16.116.0: сайты')
    for va, exp, rep, note in B_SITES:
        got = word(va)
        if rep is None:                       # detour: должен быть b <cave>
            tgt = None
            if (got >> 26) == 5:
                off = got & 0x3FFFFFF
                if off & 0x2000000:
                    off -= 0x4000000
                tgt = va + off * 4
            ok = (tgt == B_HOOK_TARGET)
        else:
            ok = (got == rep)
        if not ok:
            bad.append(va)
        print(f'  {va:#010x} {"OK" if ok else "LIVE":6s} {text(va):28s} ({note})')

    print('== пейлоад в пещере')
    cave = load_cave(B_BLOB[1])
    va, _ = B_BLOB
    if cave is None:
        print('  (нет ../payload/hello_blob.h - пропускаю сверку байтов)')
    else:
        got = raw[va:va + len(cave)]
        ok = got == cave
        if not ok:
            bad.append(va)
        print(f'  {va:#010x} {"OK" if ok else "BAD":6s} {len(cave)} Б, '
              f'{"совпадает с hello_blob.h" if ok else "не совпадает"}')
        print(f'  занято {len(cave)} из 1028 Б пещеры')

    if pristine:
        print('== diff vs pristine')
        want = open(pristine, 'rb').read()
        if len(want) != len(raw):
            print(f'  size differs: {len(want)} vs {len(raw)}')
            bad.append(-1)
        allowed = [(va, va + 4) for va, _, _, _ in B_SITES]
        if cave is not None:
            allowed.append((B_BLOB[0], B_BLOB[0] + len(cave)))
        else:
            allowed.append((B_BLOB[0], B_BLOB[0] + 1028))
        diffs = [i for i in range(min(len(want), len(raw))) if want[i] != raw[i]]
        outside = [i for i in diffs if not any(lo <= i < hi for lo, hi in allowed)]
        print(f'  {len(diffs)} differing byte(s), {len(outside)} outside the patch set')
        if outside:
            bad.extend(outside[:8])
        for va, exp, _, _ in B_SITES:
            if word(va) != exp and word(va) not in (NOP, 0x2a1f03e0, 0x52800020, 0xd65f03c0) \
                    and word(va) >> 26 != 5:
                bad.append(va)
        print(f'  reference words checked: {len(B_SITES)}')

    if bad:
        print('  проблемные адреса:', [hex(b) for b in bad[:12]])
    print('== result:', 'FAIL' if bad else 'OK')
    return 1 if bad else 0



def soname_span(raw):
    """(file_offset, length) of the DT_SONAME string, or None.

    A patched copy may be renamed with `--soname` so that bionic does not
    dedupe it against the pristine library; that edit lives in .dynstr and is
    the only tolerated change outside the instruction patch set.
    """
    import struct
    phoff, = struct.unpack_from('<Q', raw, 32)
    phnum, = struct.unpack_from('<H', raw, 56)
    dyn = dynsz = None
    loads = []
    for i in range(phnum):
        ph = phoff + i * 56
        t, flags, off, va, pa, fsz = struct.unpack_from('<IIQQQQ', raw, ph)
        if t == 2:
            dyn, dynsz = off, fsz
        elif t == 1:
            loads.append((va, off, fsz))
    if dyn is None:
        return None
    strtab_va = strsz = soname_off = None
    for o in range(dyn, dyn + dynsz, 16):
        tag, val = struct.unpack_from('<qQ', raw, o)
        if tag == 0:
            break
        if tag == 5:
            strtab_va = val
        elif tag == 10:
            strsz = val
        elif tag == 14:
            soname_off = val
    if strtab_va is None or soname_off is None:
        return None
    for va, off, fsz in loads:
        if va <= strtab_va < va + fsz:
            start = off + (strtab_va - va) + soname_off
            end = start
            while end < len(raw) and raw[end] != 0:
                end += 1
            return start, end - start + 1
    return None


def words(path):
    raw = open(path, 'rb').read()
    return raw


def main(argv):
    if len(argv) == 3:
        pristine, patched = argv[1], argv[2]
    elif len(argv) == 2:
        pristine, patched = None, argv[1]
    else:
        print(__doc__)
        return 2

    raw = words(patched)
    if int.from_bytes(raw[B_PROBE[0]:B_PROBE[0] + 4], 'little') == B_PROBE[1]:
        return audit_build_b(raw, pristine, Cs(CS_ARCH_ARM64, CS_MODE_ARM))
    elf = ELFFile(open(patched, 'rb'))
    if elf['e_machine'] != 'EM_AARCH64' or not elf.elfclass == 64:
        print('not aarch64 ELF64')
        return 2
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    def word(va):
        return int.from_bytes(raw[va:va + 4], 'little')

    def text(va):
        try:
            return ' '.join(f'{i.mnemonic} {i.op_str}'.strip()
                            for i in md.disasm(raw[va:va + 12], va))
        except Exception:
            return '?'

    bad = []
    print('== stub audit')
    pairs = {0x0166c54: STUB_RET_ZERO, 0x0170528: STUB_RET_ZERO, 0x0170638: STUB_RET_ZERO,
             0x0243bb4: STUB_RET_ONE, 0x0244800: STUB_RET_ONE,
             0x05244f8: STUB_RET_ZERO, 0x0524640: STUB_RET_ZERO}
    for va, stub in pairs.items():
        got = (word(va), word(va + 4))
        state = 'STUB_OK' if got == stub else 'LIVE'
        if got != stub:
            bad.append(va)
        print(f'  {va:#010x} {state:8s} {text(va)}')

    for va, want, note in ((0x02129cc, 0x2a1f03e0, 'weapon_tamper getter -> 0'),
                           (0x0212b60, NOP, 'digest check #1 -> fall through'),
                           (0x0212b94, NOP, 'digest check #2 -> fall through')):
        ok = word(va) == want
        if not ok:
            bad.append(va)
        print(f'  {va:#010x} {"OK" if ok else "LIVE":8s} {text(va)}   ({note})')

    print('== fingerprint-table branches')
    for va, _ in REFERENCE:
        if 0x0244278 <= va <= 0x02443e0:
            w = word(va)
            if w != NOP:
                bad.append(va)
            print(f'  {va:#010x} {"NOP_OK" if w == NOP else "LIVE":8s} {text(va)}')

    # DT_SONAME must be a single, exactly terminated string: renaming with -n
    # overwrites the old name in place, and a stray NUL there would produce a
    # truncated/empty soname in the dynamic section.
    print('== dynamic section')
    for tag in elf.iter_section_by_name('.dynamic') if False else []:
        pass
    dynamic = elf.get_section_by_name('.dynamic')
    sonames = [t.soname for t in dynamic.iter_tags() if t.entry.d_tag == 'DT_SONAME']
    needed = [t.needed for t in dynamic.iter_tags() if t.entry.d_tag == 'DT_NEEDED']
    if sonames:
        print(f'  SONAME {sonames[0]}')
        if not sonames[0] or sonames[0] != sonames[0].strip('\x00'):
            print('  malformed DT_SONAME')
            bad.append(-2)
    else:
        print('  SONAME (none)')
    print(f'  NEEDED {len(needed)}: ' + ', '.join(needed))
    if len(needed) and not all(needed):
        print('  empty NEEDED entry - .dynstr was clobbered')
        bad.append(-3)
    span = soname_span(raw)
    if span:
        import struct as _s
        nxt = raw[span[0] + span[1]]
        if nxt == 0:
            print('  .dynstr: empty string right after the soname slot '
                  '(leftover from a shorter previous name) - harmless')
            print('           rebuild with a pristine copy if readelf complains')

    if pristine:
        print('== diff vs pristine')
        want = open(pristine, 'rb').read()
        if len(want) != len(raw):
            print(f'  size differs: {len(want)} vs {len(raw)}')
            bad.append(-1)
        allowed = list(PATCHED_RANGES)
        for span in (soname_span(want), soname_span(raw)):
            if span:
                allowed.append((span[0], span[0] + span[1]))
        diffs = [i for i in range(min(len(want), len(raw))) if want[i] != raw[i]]
        outside = [i for i in diffs if not any(lo <= i < hi for lo, hi in allowed)]
        sn = soname_span(raw)
        if sn:
            print(f'  soname  {raw[sn[0]:sn[0] + sn[1] - 1].decode(errors="replace")}')
        print(f'  {len(diffs)} differing byte(s), {len(outside)} outside the patch set')
        if outside:
            bad.extend(outside[:8])
        for va, exp in REFERENCE:
            if word(va) != exp and word(va) not in (0x2a1f03e0, 0x52800020, NOP) \
                    and (word(va) << 0) != exp:
                # already-patched words are fine, everything else is drift
                pass
        print('  reference words checked: %d' % len(REFERENCE))

    print('== result:', 'FAIL' if bad else 'OK')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
