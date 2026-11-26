#!/usr/bin/env python3
"""repack_clean.py — APK без единого лишнего .so: патч заменой libkolson.so.

Зачем: лаунчер считает сторонними библиотеками те .so, которых нет в оригинальном
APK (наш `libklnc.so` / `libkolson_patch.so` — ровно такие). Вариант «одна
библиотека» не добавляет ни одного файла: патченный код лежит внутри самого
libkolson.so, а имя и набор библиотек остаются как в оригинале.

    # посмотреть, какие .so лишние
    python3 repack_clean.py --check app.apk

    # собрать чистый APK: заменить libkolson.so, выкинуть libklnc.so/шим
    python3 repack_clean.py --apk app.apk --so libkolson.unlocked.so -o app-clean.apk

Дальше (обязательно, т.к. подпись пересчитывается):
    zipalign -f -p 4 app-clean.apk app-clean-aligned.apk
    apksigner sign --ks key.jks --out app-final.apk app-clean-aligned.apk
На телефоне то же самое делает MT Manager: заменить файл в APK -> подписать.

Либо без внешних утилит, если APK собран с extractNativeLibs=false (.so лежат
STORED и выровнены): repack_clean.py сам сохраняет способ хранения и порядок
файлов, но zipalign всё равно нужен — замена меняет офсеты.
"""
import argparse
import hashlib
import re
import sys
import zipfile

OURS = re.compile(r"lib/(arm64-v8a|armeabi-v7a|armeabi|x86|x86_64)/lib(klnc|kolson_patch)\.so$")
KOLSON = "lib/arm64-v8a/libkolson.so"


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def list_libs(path):
    out = []
    with zipfile.ZipFile(path) as z:
        for i in z.infolist():
            if i.filename.startswith("lib/") and i.filename.endswith(".so"):
                out.append((i.filename, i.file_size, i.compress_type))
    return sorted(out)


def check_dex(path):
    """Если dex зовёт loadLibrary("klnc")/("kolson_patch"), без этого .so не запустится."""
    hits = []
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if not re.match(r"classes\d*\.dex$", n):
                continue
            raw = z.read(n)
            for word in (b"klnc", b"kolson_patch"):
                if word in raw:
                    hits.append((n, word.decode()))
    return hits


def check(path):
    libs = list_libs(path)
    ours = [l for l in libs if OURS.match(l[0])]
    print("APK: %s" % path)
    print(".so всего: %d" % len(libs))
    for name, size, ctype in libs:
        mark = "  <-- лишний (наш)" if OURS.match(name) else ""
        print("   %10d  %s%s%s" % (size, name, " (stored)" if ctype == 0 else "", mark))
    dex = check_dex(path)
    if dex:
        print("\nВ dex есть ссылки на наши имена: %s" % ", ".join(
            "%s:%s" % h for h in dex))
        print("   -> для чистой установки dex должен быть ОРИГИНАЛЬНЫМ "
              "(System.loadLibrary(\"kolson\"))")
    if ours:
        print("\nнайдено наших лишних библиотек: %d -> именно они попадают под "
              "«сторонние библиотеки»" % len(ours))
    else:
        print("\nлишних наших библиотек нет: набор .so совпадает с оригиналом")
    return 0


def repack(apk, so_path, out):
    with open(so_path, "rb") as fh:
        patched = fh.read()
    if not patched.startswith(b"\x7fELF"):
        print("%s: не ELF" % so_path)
        return 2
    print("патченный libkolson.so: %d байт sha256=%s" % (len(patched), sha256(patched)[:16]))

    dropped, replaced, kept = [], [], 0
    with zipfile.ZipFile(apk) as zin, zipfile.ZipFile(out, "w") as zout:
        if KOLSON not in [i.filename for i in zin.infolist()]:
            print("в APK нет %s — это не тот APK" % KOLSON)
            return 2
        for info in zin.infolist():
            n = info.filename
            if OURS.match(n):
                dropped.append(n)
                continue
            data = zin.read(n)
            if n == KOLSON:
                if info.file_size != len(patched):
                    print("ВНИМАНИЕ: размер отличается (%d против %d), патчер должен "
                          "сохранять размер" % (info.file_size, len(patched)))
                data = patched
                replaced.append(n)
            zi = zipfile.ZipInfo(n, date_time=info.date_time)
            zi.compress_type = info.compress_type      # .so обычно STORED
            zi.external_attr = info.external_attr
            zi.internal_attr = info.internal_attr
            zi.create_system = info.create_system
            zout.writestr(zi, data)
            kept += 1
    print("файлов перенесено: %d" % kept)
    print("заменено: %s" % ", ".join(replaced))
    print("удалено лишних: %s" % (", ".join(dropped) if dropped else "нет"))
    print("готово: %s" % out)
    print("\nдальше: zipalign -f -p 4 %s aligned.apk && "
          "apksigner sign --ks key.jks --out final.apk aligned.apk" % out)
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("apk_pos", nargs="?")
    ap.add_argument("--check", metavar="APK")
    ap.add_argument("--apk", metavar="APK")
    ap.add_argument("--so", metavar="PATCHED_SO")
    ap.add_argument("-o", "--out", default="app-clean.apk")
    a = ap.parse_args()
    target = a.check or None
    if a.apk_pos:
        target = target or a.apk_pos
    if target and not a.apk:
        return check(target)
    if not (a.apk and a.so):
        ap.print_help()
        return 2
    return repack(a.apk, a.so, a.out)


if __name__ == "__main__":
    sys.exit(main())
