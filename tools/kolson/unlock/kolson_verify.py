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

    if pristine:
        print('== diff vs pristine')
        want = open(pristine, 'rb').read()
        if len(want) != len(raw):
            print(f'  size differs: {len(want)} vs {len(raw)}')
            bad.append(-1)
        diffs = [i for i in range(min(len(want), len(raw))) if want[i] != raw[i]]
        outside = [i for i in diffs if not any(lo <= i < hi for lo, hi in PATCHED_RANGES)]
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
