#!/usr/bin/env python3
"""Патч libkolson.so сборки 16.116.0 (8 609 952 B) - самостоятельный скрипт.

Ничего компилировать не нужно, только python3:

    python3 -V                                  # проверить, что он есть
    python3 kolson_16_116_0.py libkolson.so      # только проверить, ничего не писать
    python3 kolson_16_116_0.py libkolson.so libkolson.new.so   # пропатчить

Что делает: 18 слов (auth/weapon/dm/blob/hello) + пейлоад "KOLSON: Library
Loaded" в код-пещеру 0xa8f5c. Размер файла не меняется, DT_SONAME не трогается,
вне набора патчей ни один байт не меняется.

Защиты в самом скрипте: сборка узнаётся по probe-слову 0x2fcc84, каждое слово
сверяется с ожидаемым, область пещеры должна быть нулевой. Если хоть что-то не
совпало - скрипт отказывается и ничего не пишет (повторный запуск на уже
пропатченном файле безопасен: слова просто "уже пропатчены").
"""
import base64
import hashlib
import sys

BUILD_NAME = "16.116.0 (8 609 952 B)"
BUILD_SIZE = 8609952
PROBE_VA, PROBE_WORD = 0x02fcc84, 0x2a1f03f3
CAVE_VA = 0x000a8f5c
CAVE_SIZE = 1028

# (группа, адрес, было, стало)
SITES = [
    ("blob",   0x001fcbac, 0xd503233f, 0x52800020),
    ("blob",   0x001fcbb0, 0xa9ba7bfd, 0xd65f03c0),
    ("dm",     0x0029c794, 0x54000a08, 0xd503201f),
    ("dm",     0x0029c79c, 0x540009c8, 0xd503201f),
    ("dm",     0x0029c7bc, 0x540008c3, 0xd503201f),
    ("dm",     0x0029c7c4, 0x5400088d, 0xd503201f),
    ("weapon", 0x002c9284, 0xb94ed100, 0x2a1f03e0),
    ("auth",   0x002fcba4, 0x36000c20, 0xd503201f),
    ("auth",   0x002fcbc4, 0x36000b20, 0xd503201f),
    ("auth",   0x002fcbe0, 0x36000a40, 0xd503201f),
    ("auth",   0x002fcbf4, 0x360009a0, 0xd503201f),
    ("auth",   0x002fcc10, 0x360008c0, 0xd503201f),
    ("auth",   0x002fcc2c, 0x54000c81, 0xd503201f),
    ("auth",   0x002fcc48, 0x54000ba1, 0xd503201f),
    ("auth",   0x002fcc5c, 0x54000b01, 0xd503201f),
    ("auth",   0x002fcc6c, 0x54000a81, 0xd503201f),
    ("auth",   0x002fcc80, 0x540009e1, 0xd503201f),
    ("hello",  0x003a8684, 0xd503233f, 0x17f40236),
]

PAYLOAD = base64.b64decode(
    "/8MB0eAHAKniDwGp5BcCqeYfA6noJwSp6i8Fqf4zAPkI//8QieuR0kkBoPIIAQnL4AMIquED"
    "QPkLAACU/jNA+eovRanoJ0Sp5h9DqeQXQqniD0Gp4AdAqf/DAZE/IwPVs/0LFP9DAtH9ewep"
    "81MGqfVbBan3YwSp9wMAqvMDAKr0AwGq9QMfqv0DAJHADwBQWwAAlIgCQPkIGUD54AMUquED"
    "AZHCAIBSIgCgcgABP9ZgCAA19SNA+TUIALTgAxWqIREAEFYAAJSAAAC1QA4AMEsAAJQ6AAAU"
    "9gMAquADFarhAxaqwhAAcEMRAFBPAACUYAYAtOEDFqriAwCq4AMVqlMAAJSAAAC1YA0AcDwA"
    "AJQrAAAU9gMAquADFaqBEABQPwAAlMAEALTzAwCq4AMVquEDE6piEABwoxAAEDsAAJTgAwC0"
    "9AMAquADFapBEgBwRQAAlEADALThAxOq4gMUquMDFqrkAwCqJQCAUuADFao6AACUQAIAtPMD"
    "AKrgAxWq4QMTqi8AAJSgAQC04QMAquADFarCEABQwxAAcCYAAJTgAAC04QMTquIDAKrgAxWq"
    "MAAAlMAIAHARAACUVQEAtKgCQPkIkUP54AMVqgABP9agAAA0qAJA+QhFQPngAxWqAAE/1vdj"
    "RKn1W0Wp81NGqf17R6n/QwKRwANf1uMDAKqAAIBSwQMAEMIDAHAJ0oLS6Q6g8ukCCYsgAR/W"
    "CABA+QgZQPkAAR/WCABA+QjVQfkAAR/WCABA+QiFQPkAAR/WCABA+Qh9QPkAAR/WCABA+QjZ"
    "QfkAAR/WCABA+QjZQfkAAR/WCABA+QitQvkAAR/WCABA+Qj1QPkAAR/WS09MU09OACVzAHBh"
    "eWxvYWQ6IGVudGVyAHBheWxvYWQ6IEFjdGl2aXR5VGhyZWFkIG5vdCBmb3VuZABwYXlsb2Fk"
    "OiBubyBhcHBsaWNhdGlvbgBwYXlsb2FkOiB0b2FzdCBzaG93bgBhbmRyb2lkL2FwcC9BY3Rp"
    "dml0eVRocmVhZABjdXJyZW50QXBwbGljYXRpb24AKClMYW5kcm9pZC9hcHAvQXBwbGljYXRp"
    "b247AGFuZHJvaWQvd2lkZ2V0L1RvYXN0AG1ha2VUZXh0AChMYW5kcm9pZC9jb250ZW50L0Nv"
    "bnRleHQ7TGphdmEvbGFuZy9DaGFyU2VxdWVuY2U7SSlMYW5kcm9pZC93aWRnZXQvVG9hc3Q7"
    "AEtPTFNPTjogTGlicmFyeSBMb2FkZWQAc2hvdwAoKVYAAA=="
)


def main(argv):
    if len(argv) not in (2, 3):
        print(__doc__)
        return 2
    src = argv[1]
    raw = bytearray(open(src, "rb").read())

    if len(raw) != BUILD_SIZE:
        print("размер %d Б, а у сборки %s - %d Б" % (len(raw), BUILD_NAME, BUILD_SIZE))
        print("это другая сборка, скрипт рассчитан только на неё")
        return 2
    probe = int.from_bytes(raw[PROBE_VA:PROBE_VA + 4], "little")
    if probe != PROBE_WORD:
        print("probe %#010x != %#010x - сборка не та" % (probe, PROBE_WORD))
        return 2

    todo, already, bad = [], 0, []
    for mod, va, exp, rep in SITES:
        now = int.from_bytes(raw[va:va + 4], "little")
        if now == rep:
            already += 1
        elif now != exp:
            bad.append("%s %#010x: сейчас %#010x, ждали %#010x" % (mod, va, now, exp))
        else:
            todo.append((mod, va, now, rep))

    cave_now = bytes(raw[CAVE_VA:CAVE_VA + len(PAYLOAD)])
    cave_same = cave_now == PAYLOAD
    if not cave_same and any(cave_now):
        bad.append("пещера %#010x: область не нулевая" % CAVE_VA)

    print("сборка: %s" % BUILD_NAME)
    print("к записи: %d, уже пропатчено: %d, пейлоад: %s"
          % (len(todo), already, "на месте" if cave_same else "не записан"))

    if bad:
        for line in bad:
            print("ОТКАЗ " + line)
        print("ничего не записано")
        return 3

    if len(argv) == 2:
        print("режим проверки: файл не изменён")
        return 0

    for mod, va, now, rep in todo:
        raw[va:va + 4] = rep.to_bytes(4, "little")
        print("  %-6s %#010x  %#010x -> %#010x" % (mod, va, now, rep))
    if not cave_same:
        raw[CAVE_VA:CAVE_VA + len(PAYLOAD)] = PAYLOAD
        print("  %-6s %#010x  пейлоад %d Б" % ("hello", CAVE_VA, len(PAYLOAD)))

    out = open(argv[2], "wb")
    out.write(raw)
    out.close()

    orig = open(src, "rb").read()
    diff = sum(1 for a, b in zip(orig, raw) if a != b)
    print("записано: %s (%d Б, отличий %d)" % (argv[2], len(raw), diff))
    print("sha256: %s" % hashlib.sha256(raw).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
