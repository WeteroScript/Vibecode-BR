#!/usr/bin/env python3
"""retarget.py - перенос адресов патчей между сборками libkolson.so.

Зачем: 25 сайтов в kolson_patches.h - это адреса КОНКРЕТНОЙ сборки. На новой
сборке все они не совпадают (патчер честно отказывается: `--list` печатает
MISMATCH). Скрипт ищет каждый сайт в новом файле по окну машинных слов, маскируя
позиционно-зависимые инструкции (b/bl/b.cond/cbz/adr/adrp/ldr literal), и
возвращает новый адрес + уверенность.

    python3 tools/kolson/retarget.py old/libkolson.so new/libkolson.so
    python3 tools/kolson/retarget.py old.so new.so --half 32 --min 20
    python3 tools/kolson/retarget.py old.so old.so        # самопроверка

Если уверенных совпадений нет - код в новой сборке переписан, нужен новый RE
(см. tools/kolson/NEW-BUILD-16.116.0.md: якоря по строкам и xref-ам).
"""
import struct
import sys


def words(raw, off, n):
    return list(struct.unpack_from('<%dI' % n, raw, off))

def is_relative(w):
    # b/bl: 000101|001111 ; b.cond 0101010 ; cbz/cbnz 1011010 ; ldr literal 01011000/01011001/01111000...
    if (w & 0x7C000000) == 0x14000000: return True   # b
    if (w & 0xFC000000) == 0x94000000: return True   # bl
    if (w & 0xFF000010) == 0x54000000: return True   # b.cond
    if (w & 0x7E000000) == 0x34000000: return True   # cbz/cbnz
    if (w & 0x7F000000) == 0x35000000: return True   # cbnz
    if (w & 0x9F000000) == 0x10000000: return True   # adr
    if (w & 0x9F000000) == 0x90000000: return True   # adrp
    if (w & 0x3B000000) == 0x18000000: return True   # ldr literal
    if (w & 0xFFC00000) == 0x91000000 and False: pass
    return False

def find(old, new, old_site, half=20, min_match=14):
    start = max(0, old_site - half*4)
    n = 2*half
    pat = words(old, start, n)
    masked = [is_relative(w) for w in pat]
    best = []
    for off in range(0, len(new) - 4*n, 4):
        cand = words(new, off, n)
        ok = 0; bad = 0
        for i in range(n):
            if masked[i]: continue
            if cand[i] == pat[i]: ok += 1
            else:
                bad += 1
                if bad > 2: break
        if bad <= 2 and ok >= min_match:
            best.append((ok, -bad, off))
    best.sort(reverse=True)
    return start, old_site - start, best[:5]

SITES = [0x166c54, 0x170528, 0x170638, 0x2129cc, 0x212b60, 0x212b94, 0x243bb4,
         0x244800, 0x244278, 0x2442ac, 0x2442cc, 0x244388, 0x2443a4, 0x2443b8,
         0x2443c8, 0x2443dc, 0x5244f8, 0x524640]

def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    half, min_match = 20, 14
    for i, a in enumerate(argv):
        if a == "--half":
            half = int(argv[i + 1])
        if a == "--min":
            min_match = int(argv[i + 1])
    if len(args) < 2:
        print(__doc__)
        return 2
    old = open(args[0], "rb").read()
    new = open(args[1], "rb").read()
    same = args[0] == args[1]
    print("old=%s (%d Б) new=%s (%d Б)%s" % (args[0], len(old), args[1], len(new),
                                             "  [самопроверка]" if same else ""))
    found = 0
    for site in SITES:
        start, delta, best = find(old, new, site, half=half, min_match=min_match)
        if not best:
            print("%#x: не найдено (код переписан)" % site)
            continue
        ok, nb, off = best[0]
        new_site = off + delta
        uniq = len([b for b in best if b[0] == ok]) == 1
        found += 1
        print("%#x -> %#x  (совпало слов %d, кандидатов %d%s)"
              % (site, new_site, ok, len(best), "" if uniq else ", НЕОДНОЗНАЧНО"))
    print("итого перенесено: %d из %d" % (found, len(SITES)))
    return 0 if found == len(SITES) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
