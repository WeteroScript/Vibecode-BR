#!/usr/bin/env python3
"""find_notice.py - найти UI-строку в APK/дексах и выйти на код, который её показывает.

Зачем: сообщения вида "Удалите сторонние библиотеки из папки 1NEIZZIR/Modules или
Custom/modules и перезапустите игру" могут жить в ЛЮБОМ classesN.dex (или приходить
по сети), поэтому искать надо по всем сразу - и сразу видеть класс/метод/ветку,
а не только факт наличия строки.

    python3 find_notice.py app.apk "сторонние библиотеки"
    python3 find_notice.py --device com.br.top "сторонние"     # снять APK с телефона
    python3 find_notice.py --lib libkolson.so                  # что искать в нативной части
    python3 find_notice.py app.apk --list модул        # все строки с подстрокой
    python3 find_notice.py classes8.dex --list Custom  # можно по одному dex
    python3 find_notice.py app.apk "фраза" --smali     # плюс псевдо-smali метода

Парсер свой (struct), зависимостей нет. Точность: строку находим по string_id,
место использования - по сырому шаблону const-string/const-string/jumbo в
code_item, владельца метода - по class_data_item. Для вывода контекста рядом
подтягиваются соседние const-string того же метода.
"""
import io
import os
import re
import struct
import sys
import zipfile

CONST_STRING = 0x1A        # const-string vAA, string@BBBB
CONST_STRING_JUMBO = 0x1B  # const-string/jumbo vAA, string@BBBBBBBB


# ------------------------------------------------------------------ dex parser
class Dex:
    def __init__(self, raw, name="<dex>"):
        self.raw = raw
        self.name = name
        (self.string_ids_size, self.string_ids_off,
         self.type_ids_size, self.type_ids_off,
         self.proto_ids_size, self.proto_ids_off,
         self.field_ids_size, self.field_ids_off,
         self.method_ids_size, self.method_ids_off,
         self.class_defs_size, self.class_defs_off) = struct.unpack_from("<12I", raw, 56)
        self._strings = {}
        self._types = None
        self._methods = None
        self._code_map = None

    # -- uleb128 -------------------------------------------------------------
    def uleb(self, p):
        n = 0
        shift = 0
        while True:
            b = self.raw[p]
            p += 1
            n |= (b & 0x7F) << shift
            shift += 7
            if b < 0x80:
                return n, p

    def string_off(self, idx):
        """(file offset of the utf8 data, length in bytes) для string_id[idx]."""
        if idx in self._strings:
            return self._strings[idx]
        off, = struct.unpack_from("<I", self.raw, self.string_ids_off + 4 * idx)
        n, p = self.uleb(off)
        self._strings[idx] = (p, n)
        return p, n

    def string(self, idx):
        p, n = self.string_off(idx)
        return self.raw[p:p + n].decode("utf-8", "replace")

    def type_name(self, idx):
        if self._types is None:
            self._types = []
            for i in range(self.type_ids_size):
                sidx, = struct.unpack_from("<I", self.raw, self.type_ids_off + 4 * i)
                self._types.append(self.string(sidx))
        return self._types[idx]

    def method(self, idx):
        """(class, name, proto) для method_id[idx]."""
        if self._methods is None:
            self._methods = []
            for i in range(self.method_ids_size):
                cidx, pidx, nidx = struct.unpack_from("<HHI", self.raw,
                                                      self.method_ids_off + 8 * i)
                self._methods.append((self.type_name(cidx), self.string(nidx), pidx))
        return self._methods[idx]

    def proto_desc(self, pidx):
        return "proto@%d" % pidx

    def code_map(self):
        """{code_off: (class, method, desc, regs, insns_size)}"""
        if self._code_map is not None:
            return self._code_map
        m = {}
        for i in range(self.class_defs_size):
            base = self.class_defs_off + 32 * i
            cidx, _acc, _sup, _ifaces, _src, _ann, cdata = struct.unpack_from("<7I", self.raw, base)
            if not cdata or cdata >= len(self.raw):
                continue
            p = cdata
            sf, p = self.uleb(p)
            inf, p = self.uleb(p)
            dm, p = self.uleb(p)
            vm, p = self.uleb(p)
            for _ in range(sf):
                _, p = self.uleb(p)
                _, p = self.uleb(p)
            for k in range(dm + vm):
                diff, p = self.uleb(p)
                _, p = self.uleb(p)
                code_off, p = self.uleb(p)
                if k == 0 or k == dm:          # method_idx_diff - накопительный
                    midx = diff
                else:
                    midx += diff
                if not code_off or code_off + 16 > len(self.raw):
                    continue
                regs, _ins, _outs, _tries, _dbg, insns_size = struct.unpack_from(
                    "<4H2I", self.raw, code_off)
                if midx >= self.method_ids_size:
                    continue
                lo, hi = self.code_range()
                if not (lo <= code_off < hi) or regs > 64 or _ins > 64 \
                        or not (0 < insns_size < 200000):
                    continue          # битая запись class_data - пропускаем
                cname, mname, pidx = self.method(midx)
                m[code_off] = (cname, mname, self.proto_desc(pidx), regs, insns_size)
        self._code_map = m
        return m

    def owner_of(self, file_off):
        """Какому методу принадлежит байтовый офсет: (code_off, info, delta)."""
        if getattr(self, "_sorted", None) is None:
            self._sorted = sorted(self.code_map().items())
        items = self._sorted
        # бинарный поиск последнего code_off <= file_off
        lo, hi = 0, len(items)
        while lo < hi:
            mid = (lo + hi) // 2
            if items[mid][0] <= file_off:
                lo = mid + 1
            else:
                hi = mid
        if lo == 0:
            return None
        off, info = items[lo - 1]
        end = off + 16 + 2 * info[4]
        if file_off < end:
            return (off, info, file_off - (off + 16))
        return None

    def _sections(self):
        """map_list: [(type, size, offset)] - чтобы не сканировать .data/текст наугад."""
        if getattr(self, "_sec", None) is not None:
            return self._sec
        map_off, = struct.unpack_from("<I", self.raw, 52)
        n, = struct.unpack_from("<I", self.raw, map_off)
        out = []
        p = map_off + 4
        for _ in range(n):
            t, _unused, size, off = struct.unpack_from("<HHII", self.raw, p)
            out.append((t, size, off))
            p += 12
        self._sec = out
        return out

    def code_range(self):
        """Байтовый диапазон code_item берём из map_list (type 0x2001), а не по
        разобранным code_off: так границы точные, даже если class_data битые."""
        for t, size, off in self._sections():
            if t == 0x2001:
                # следующая секция после code_item
                end = len(self.raw)
                for t2, _s2, off2 in self._sections():
                    if off2 > off and off2 < end:
                        end = off2
                return (off, end)
        return (0, len(self.raw))


    def sites_of(self, sidx):
        """Все места, где string@%d грузится инструкцией const-string."""
        out = []
        pat16 = struct.pack("<H", sidx)
        pat32 = struct.pack("<I", sidx)
        lo, hi = self.code_range()
        for i in range(lo, max(lo, hi - 8)):
            b = self.raw[i]
            if b == CONST_STRING and self.raw[i + 2:i + 4] == pat16:
                if self.owner_of(i):
                    out.append((i, False))
            elif b == CONST_STRING_JUMBO and self.raw[i + 2:i + 6] == pat32:
                if self.owner_of(i):
                    out.append((i, True))
        return out

    def strings_matching(self, needle):
        """[(string_id, string)] где needle встречается как подстрока."""
        res = []
        for i in range(self.string_ids_size):
            p, n = self.string_off(i)
            if needle.encode() in self.raw[p:p + n]:
                res.append((i, self.string(i)))
        return res

    def all_strings(self):
        for i in range(self.string_ids_size):
            yield i, self.string(i)



# --------------------------------------------------- apk: ресурсы, assets, .so
def arsc_strings(raw):
    """Глобальный пул строк resources.arsc: yield (index, str)."""
    try:
        ctype, hsize, _size = struct.unpack_from("<HHI", raw, 0)
        if ctype != 0x0002:                     # RES_TABLE_TYPE
            return
        p = hsize
        while p + 8 <= len(raw):
            ctype, hsize, size = struct.unpack_from("<HHI", raw, p)
            if size < 8:
                return
            if ctype == 0x0001:                 # RES_STRING_POOL_TYPE
                yield from _string_pool(raw, p)
                return
            p += size
    except struct.error:
        return


def _string_pool(raw, base):
    ctype, hsize, size = struct.unpack_from("<HHI", raw, base)
    count, _styles, flags, strings_start, _ss = struct.unpack_from("<5I", raw, base + 8)
    utf8 = bool(flags & 0x100)
    offs = struct.unpack_from("<%dI" % count, raw, base + hsize)
    for i, o in enumerate(offs):
        q = base + strings_start + o
        try:
            if utf8:
                # utf16_len, utf8_len (1-2 байта каждое)
                n = raw[q]
                q += 2 if n & 0x80 else 1
                n = raw[q]
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | raw[q + 1]
                    q += 2
                else:
                    q += 1
                yield i, raw[q:q + n].decode("utf-8", "replace")
            else:
                n, = struct.unpack_from("<H", raw, q)
                q += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", raw, q)[0]
                    q += 2
                yield i, raw[q:q + 2 * n].decode("utf-16-le", "replace")
        except (IndexError, struct.error):
            continue


def _encodings(needle):
    return [("utf-8", needle.encode("utf-8")), ("utf-16-le", needle.encode("utf-16-le"))]


def search_blob(raw, needle):
    """[(offset, encoding)] - вхождения подстроки в utf-8/utf-16-le."""
    out = []
    for enc, pat in _encodings(needle):
        i = raw.find(pat)
        while i >= 0:
            out.append((i, enc))
            i = raw.find(pat, i + 1)
    return sorted(out)


def context(raw, off, enc, limit=160):
    """Расширяем найденное до читаемой строки вокруг офсета."""
    step = 2 if enc == "utf-16-le" else 1
    lo = off
    while lo > 0 and off - lo < 400:
        if enc == "utf-16-le":
            if raw[lo - 2:lo] == b"\x00\x00":
                break
        elif raw[lo - 1] == 0:
            break
        lo -= step
    hi = off
    while hi < len(raw) and hi - off < 400:
        if enc == "utf-16-le":
            if raw[hi:hi + 2] == b"\x00\x00":
                break
        elif raw[hi] == 0:
            break
        hi += step
    chunk = raw[lo:hi]
    txt = chunk.decode(enc if enc == "utf-16-le" else "utf-8", "replace")
    return " ".join(txt.split())[:limit]


def scan_apk(path, needle):
    """Все dex + resources.arsc + assets + lib/*/*.so в одном проходе."""
    import zipfile
    total = 0
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        dexes = [n for n in names if re.match(r"classes\d*\.dex$", n)]
        others = [n for n in names if n == "resources.arsc" or n.startswith("assets/")
                  or (n.startswith("lib/") and n.endswith(".so"))]
        print("apk: %d dex, %d прочих файлов" % (len(dexes), len(others)))
        for n in sorted(dexes, key=lambda x: (len(x), x)):
            d = Dex(z.read(n), n)
            total += report_dex(d, needle)
        for n in others:
            raw = z.read(n)
            if n == "resources.arsc":
                hits = [(i, "pool", s) for i, s in arsc_strings(raw) if needle.lower() in s.lower()]
                hits = hits[:40]
                if hits:
                    print("== %s: %d строк(и) в пуле строк" % (n, len(hits)))
                    for i, _t, s in hits:
                        print("   pool#%-6d %r" % (i, s[:150]))
                total += len(hits)
                continue
            hits = search_blob(raw, needle)
            if hits:
                print("== %s: %d вхождений" % (n, len(hits)))
                for off, enc in hits[:20]:
                    print("   +%#x [%s] %r" % (off, enc, context(raw, off, enc)))
                total += len(hits)
    return total


# ---------------------------------------------------------------------- вход
def load_dexes(path):
    if os.path.isdir(path):
        names = sorted(f for f in os.listdir(path) if f.endswith(".dex"))
        return [(n, open(os.path.join(path, n), "rb").read()) for n in names]
    if path.endswith(".apk") or zipfile.is_zipfile(path):
        out = []
        with zipfile.ZipFile(path) as z:
            for n in sorted(z.namelist()):
                if n.endswith(".dex"):
                    out.append((n, z.read(n)))
        return out
    return [(os.path.basename(path), open(path, "rb").read())]


def show_site(dex, off, jumbo):
    own = dex.owner_of(off)
    if not own:
        print("   %s+%#x: (вне code_item)" % (dex.name, off))
        return
    code_off, (cname, mname, pdesc, regs, insns), delta = own
    insn_idx = delta // 2
    print("   %s+%#x  %s->%s" % (dex.name, off, cname, mname))
    print("        code_item=%#x  insn#%d  registers=%d  insns=%d" %
          (code_off, insn_idx, regs, insns))
    # соседние const-string того же метода: подсказка, о чём ветка
    lo, hi = code_off, code_off + 16 + 2 * insns
    neigh = []
    for i in (0x1A, 0x1B):
        j = lo
        while j < hi:
            if dex.raw[j] == i:
                if i == 0x1A:
                    idx, = struct.unpack_from("<H", dex.raw, j + 2)
                else:
                    idx, = struct.unpack_from("<I", dex.raw, j + 2)
                if 0 < idx < dex.string_ids_size:
                    try:
                        s = dex.string(idx)
                    except Exception:
                        s = ""
                    printable = sum(1 for c in s if c.isprintable() or c in "\n\t")
                    if s and printable >= len(s) * 0.8 and len(s) < 200:
                        neigh.append((j, s))
            j += 1
    near = sorted(neigh, key=lambda x: abs(x[0] - off))[:6]
    for j, s in sorted(near):
        mark = " <== искомое" if j == off else ""
        print("        %s+%#x  %r%s" % (dex.name, j, s[:90], mark))


def pull_from_device(pkg, out_dir="/tmp"):
    """adb: pm path -> pull всех split-APK пакета. Возвращает список путей."""
    import subprocess
    try:
        r = subprocess.run(["adb", "shell", "pm", "path", pkg],
                           capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        print("adb не найден в PATH")
        return []
    if r.returncode != 0 or "package:" not in r.stdout:
        print("pm path не дал результата (adb devices / установлен ли %s?)" % pkg)
        print(r.stdout.strip(), r.stderr.strip())
        return []
    paths = [l.split("package:", 1)[1].strip() for l in r.stdout.splitlines() if "package:" in l]
    local = []
    for p in paths:
        dest = os.path.join(out_dir, "%s-%s" % (pkg, os.path.basename(p)))
        rr = subprocess.run(["adb", "pull", p, dest], capture_output=True, text=True, timeout=300)
        if rr.returncode == 0 and os.path.exists(dest):
            local.append(dest)
            print("pulled %s -> %s" % (p, dest))
        else:
            print("не удалось снять %s: %s" % (p, rr.stderr.strip()))
    return local


# строки из libkolson.so, которые показывают, что идёт проверка модулей
LIB_HINTS = ("NEIZZIR", "custom_active", "Module", "module", "Modules", "/proc/self/maps",
             "dl_iterate_phdr", "houdini", "ndk_translation", "Umbrella", "umbrella")


def lib_report(path):
    """строки-libkolson, связанные с модулями/окружением"""
    """Что искать в нативной части: строки-libkolson, связанные с модулями."""
    try:
        raw = open(path, "rb").read()
    except OSError as e:
        print("не читается %s: %s" % (path, e))
        return
    print("== %s (%.1f MB): строки про модули/окружение" % (path, len(raw) / 1e6))
    seen = set()
    if not raw.startswith(b"\x7fELF"):
        print("   это не ELF-файл")
        return
    for hint in LIB_HINTS:
        i = 0
        while True:
            i = raw.find(hint.encode(), i + 1)
            if i < 0:
                break
            a = raw.rfind(b"\x00", max(0, i - 80), i) + 1
            b = raw.find(b"\x00", i)
            s = raw[a:b].decode("utf-8", "replace")
            printable = sum(1 for c in s if c.isprintable())
            if s in seen or len(s) < 6 or printable < len(s) * 0.8:
                continue
            seen.add(s)
            print("   %#x %r" % (a, s[:120]))
            break


def report_dex(d, needle, mode_list=False, mode_smali=False):
    """Печатает hits по одному dex, возвращает их число."""
    total = 0
    if mode_list:
        hits = d.strings_matching(needle)
        if hits:
            print("== %s: %d string(s)" % (d.name, len(hits)))
            for idx, s in hits:
                print("   #%d %r" % (idx, s[:140]))
        return len(hits)
    for idx, s in d.strings_matching(needle):
        total += 1
        print("== %s  string #%d: %r" % (d.name, idx, s[:160]))
        sites = d.sites_of(idx)
        if not sites:
            print("   используется как аргумент/в данных, прямых const-string нет")
        for off, jumbo in sites:
            show_site(d, off, jumbo)
    return total


def main(argv):
    argv = list(argv)
    if "--lib" in argv:
        i = argv.index("--lib")
        lib_report(argv[i + 1])
        return 0
    device_pkg = None
    if "--device" in argv:
        i = argv.index("--device")
        device_pkg = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]

    pos = [a for a in argv[1:] if not a.startswith("--")]
    if len(pos) < 2:
        print(__doc__)
        return 2
    target, needle = pos[0], pos[1]
    mode_list = "--list" in argv
    mode_smali = "--smali" in argv

    if device_pkg:
        apks = pull_from_device(device_pkg)
        if not apks:
            return 1
        target = apks
        print("APK: %d файл(ов)" % len(apks))

    paths = target if isinstance(target, list) else [target]
    dexes = []
    if not (len(paths) == 1 and paths[0].endswith(".apk")):
        for path in paths:
            dexes += [Dex(raw, name) for name, raw in load_dexes(path)]
        print("dex files: %s" % ", ".join("%s (%.1f MB)" % (d.name, len(d.raw) / 1e6) for d in dexes))

    if len(paths) == 1 and paths[0].endswith(".apk"):
        total = scan_apk(paths[0], needle)
    else:
        total = 0
        for d in dexes:
            total += report_dex(d, needle, mode_list, mode_smali)

    if mode_list:
        print("итого строк с %r: %d" % (needle, total))
    else:
        print("итого вхождений %r: %d" % (needle, total))
        if not total:
            print("строки в этих dex нет -> она приходит извне (сервер/канал обновлений)")
            print("или лежит в другом dex/нативной библиотеке: прогоните по APK целиком")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
