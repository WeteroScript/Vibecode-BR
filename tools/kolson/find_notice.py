#!/usr/bin/env python3
"""find_notice.py - найти UI-строку в APK/дексах и выйти на код, который её показывает.

Зачем: сообщения вида "Удалите сторонние библиотеки из папки 1NEIZZIR/Modules или
Custom/modules и перезапустите игру" могут жить в ЛЮБОМ classesN.dex (или приходить
по сети), поэтому искать надо по всем сразу - и сразу видеть класс/метод/ветку,
а не только факт наличия строки.

    python3 find_notice.py app.apk "сторонние библиотеки"
    python3 find_notice.py --device com.br.top "сторонние"     # снять APK с телефона
    python3 find_notice.py --lib libkolson.so                  # что искать в нативной части
    python3 find_notice.py --hide app.apk -o app-clean.apk     # сделать баннер невидимым
    python3 find_notice.py --scan-dir /sdcard/Download "сторонние"  # все apk в папке
    python3 find_notice.py --ls app.apk                          # что вообще лежит в APK
    python3 find_notice.py --deep app.apk "сторонние" --xor       # все файлы + распаковка + xor
    python3 find_notice.py --deep app.apk "сторонние" --frag сторон библиотек  # по кускам
    python3 find_notice.py --audit /sdcard/Download/"Telegram" -o audit.txt  # всё сразу
    python3 find_notice.py --net "сторонние"                  # политики с CDN лаунчера
    python3 find_notice.py --grep-dir /sdcard/1NEIZZIR "сторон"  # данные игры на устройстве
    python3 find_notice.py app.apk "сторонние" --report r.txt  # короткий отчёт файлом
    python3 find_notice.py app.apk --list модул        # все строки с подстрокой
    python3 find_notice.py classes8.dex --list Custom  # можно по одному dex
    python3 find_notice.py app.apk "фраза" --smali     # плюс псевдо-smali метода

Парсер свой (struct), зависимостей нет. Точность: строку находим по string_id,
место использования - по сырому шаблону const-string/const-string/jumbo в
code_item, владельца метода - по class_data_item. Для вывода контекста рядом
подтягиваются соседние const-string того же метода.
"""
import gzip
import io
import lzma
import os
import re
import struct
import sys
import zipfile
import zlib

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
def arsc_entries(raw):
    """Глобальный пул строк resources.arsc: yield (index, (text, data_off, bytes))."""
    try:
        ctype, hsize, _size = struct.unpack_from("<HHI", raw, 0)
        if ctype != 0x0002:
            return
        p = hsize
        while p + 8 <= len(raw):
            ctype, hsize, size = struct.unpack_from("<HHI", raw, p)
            if size < 8:
                return
            if ctype == 0x0001:
                yield from _string_pool(raw, p)
                return
            p += size
    except struct.error:
        return


def arsc_strings(raw):
    """Глобальный пул строк resources.arsc: yield (index, str)."""
    for i, (txt, _off, _n) in arsc_entries(raw):
        yield i, txt


def _unused_arsc_strings(raw):
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
                yield i, (raw[q:q + n].decode("utf-8", "replace"), q, n)
            else:
                n, = struct.unpack_from("<H", raw, q)
                q += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", raw, q)[0]
                    q += 2
                yield i, (raw[q:q + 2 * n].decode("utf-16-le", "replace"), q, 2 * n)
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


# ---------------------------------------------------------------- обезвреживание
# Невидимые символы той же байтовой длины: строка остаётся валидной и на том же
# месте (офсеты пула строк не меняются), но на экране читается как пусто.
_BLANK = {1: " ", 2: "\u00a0", 3: "\u2000", 4: "\U0001d15d"}


def _blank_text(txt):
    """Заменяет каждый символ на невидимый той же длины в байтах (или None)."""
    out = []
    for ch in txt:
        n = len(ch.encode("utf-8"))
        rep = _BLANK.get(n)
        if rep is None:
            return None
        out.append(rep)
    return "".join(out)


def hide_blob(raw, needle):
    """Бланкирует вхождения в произвольном файле (assets, .so, dex) по NUL-границам."""
    data = bytearray(raw)
    done = []
    for enc, pat in _encodings(needle):
        step = 1 if enc == "utf-8" else 2
        end_mark = b"\x00" if step == 1 else b"\x00\x00"
        start = 0
        while True:
            i = bytes(data).find(pat, start)
            if i < 0:
                break
            lo, hi = i, i + len(pat)
            while lo - step >= 0 and data[lo - step:lo] != end_mark:
                lo -= step
            while hi + step <= len(data) and data[hi:hi + step] != end_mark:
                hi += step
            try:
                txt = bytes(data[lo:hi]).decode(enc, "strict")
            except UnicodeDecodeError:
                start = i + 1
                continue
            if needle.lower() not in txt.lower():
                start = i + 1
                continue
            blank = _blank_text(txt)
            if blank is None or len(blank.encode(enc)) != len(txt.encode(enc)):
                done.append((lo, enc, txt, None))
                start = hi
                continue
            data[lo:hi] = blank.encode(enc)
            done.append((lo, enc, txt, blank))
            start = hi
    return bytes(data), done


def hide_arsc(raw, needle):
    """Бланкирует строки пула resources.arsc точно по (offset, len) из пула."""
    data = bytearray(raw)
    done = []
    for idx, (txt, off, n) in arsc_entries(raw):
        if needle.lower() not in txt.lower():
            continue
        blank = _blank_text(txt)
        if blank is None:
            done.append((off, "arsc", txt, None))
            continue
        enc = "utf-8" if len(blank.encode("utf-8")) == n else "utf-16-le"
        enc_bytes = blank.encode(enc)
        if len(enc_bytes) != n:
            done.append((off, "arsc", txt, None))
            continue
        data[off:off + n] = enc_bytes
        done.append((off, "arsc", txt, blank))
    return bytes(data), done


def hide_dex(raw, needle):
    """Бланкирует строки dex по строковым офсетам (uleb-длину не трогаем)."""
    d = Dex(raw, "<dex>")
    data = bytearray(raw)
    done = []
    for idx in range(d.string_ids_size):
        off, n = d.string_off(idx)
        chunk = raw[off:off + n]
        if needle.encode("utf-8") not in chunk or needle.encode("utf-16-le") in chunk:
            continue
        try:
            txt = chunk.decode("utf-8", "strict")
        except UnicodeDecodeError:
            continue
        if needle.lower() not in txt.lower():
            continue
        blank = _blank_text(txt)
        if blank is None or len(blank.encode("utf-8")) != n:
            done.append((off, "dex", txt, None))
            continue
        data[off:off + n] = blank.encode("utf-8")
        done.append((off, "dex", txt, blank))
    return bytes(data), done


def hide_apk(src, dst, needle):
    """Новый APK, в котором строка-баннер невидима (arsc/assets/.so/dex)."""
    total = 0
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            raw = zin.read(info.filename)
            n = info.filename
            may_hit = (n == "resources.arsc" or n.startswith("assets/")
                       or (n.startswith("lib/") and n.endswith(".so"))
                       or re.match(r"classes\d*\.dex$", n))
            if may_hit and search_blob(raw, needle):
                if n == "resources.arsc":
                    new, done = hide_arsc(raw, needle)
                    if not done:                     # пул не распознан - грубый путь
                        new, done = hide_blob(raw, needle)
                elif re.match(r"classes\d*\.dex$", n):
                    new, done = hide_dex(raw, needle)
                else:
                    new, done = hide_blob(raw, needle)
                for off, enc, was, now in done:
                    if now is None:
                        print("   %s+%#x [%s] НЕ обезврежено (непечатаемые байты), "
                              "строка длиной %d: %r" % (n, off, enc, len(was), was[:60]))
                    else:
                        print("   %s+%#x [%s] %r -> скрыто" % (n, off, enc, was[:70]))
                        total += 1
                raw = new
            # сохраняем исходный способ хранения (STORED для .so и .arsc и т.п.)
            zi = zipfile.ZipInfo(n, date_time=info.date_time)
            zi.compress_type = info.compress_type
            zi.external_attr = info.external_attr
            zi.internal_attr = info.internal_attr
            zi.create_system = info.create_system
            zout.writestr(zi, raw)
    print("обезврежено строк: %d -> %s" % (total, dst))
    if total:
        print("дальше: подпиши APK заново (apksigner с любым своим ключом) и установи — "
              "подпись всё равно меняется из-за замены libkolson.so")
    return total


# ---------------------------------------------------- глубокий скан: всё + xor
def blob_variants(raw, limit=200 * 1024 * 1024, max_in=64 * 1024 * 1024):
    """(метка, распакованные байты) для zlib/gzip/lzma/deflate, если применимо."""
    out = [("raw", raw)]
    if len(raw) > max_in:                 # большие .so/ассеты не пытаемся распаковывать
        return out
    for tag, fn in (("zlib", lambda b: zlib.decompress(b)),
                    ("gzip", lambda b: gzip.decompress(b)),
                    ("lzma", lambda b: lzma.decompress(b)),
                    ("deflate", lambda b: zlib.decompress(b, -15))):
        try:
            d = fn(raw)
        except Exception:
            continue
        if 0 < len(d) <= limit:
            out.append((tag, d))
    return out


def iter_blobs(path):
    """Все файлы APK, кроме подписей. yield (имя, байты)."""
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            n = info.filename
            if n.endswith("/") or n.startswith("META-INF/"):
                continue
            try:
                yield n, z.read(n)
            except (RuntimeError, zipfile.BadZipFile):
                continue


def xor_scan(raw, needle, max_key=255):
    """Однобайтовый XOR: [(key, offset)] там, где после xor видно needle."""
    pats = [p for _e, p in _encodings(needle)]
    found = []
    for k in range(1, max_key + 1):
        tbl = bytes((i ^ k) for i in range(256))
        try:
            dec = raw.translate(tbl)
        except Exception:
            continue
        for pat in pats:
            i = dec.find(pat)
            while i >= 0:
                lo = max(0, i - 200)
                hi = min(len(dec), i + len(pat) + 200)
                around = dec[lo:hi]
                cyr = sum(1 for b in around if 0xD0 <= b <= 0xD1)
                printable = sum(1 for b in around if 32 <= b < 127 or b >= 0x80)
                if cyr >= 3 or (printable > len(around) * 0.95 and cyr >= 1):
                    found.append((k, i))
                i = dec.find(pat, i + 1)
                if len(found) > 20:
                    return found
    return found


def deep_scan(path, needle, fragments=None, do_xor=False):
    """Скан ВСЕХ файлов APK: как есть, после распаковки, после однобайтового xor."""
    total = 0
    listed = []
    for name, raw in iter_blobs(path):
        listed.append((name, len(raw)))
        for how, blob in blob_variants(raw):
            hits = search_blob(blob, needle)
            if hits:
                total += len(hits)
                print("== %s [%s]: %d" % (name, how, len(hits)))
                for off, enc in hits[:6]:
                    print("   +%#x [%s] %r" % (off, enc, context(blob, off, enc)))
            if fragments:
                if len(blob) <= 32 * 1024 * 1024:
                    low = blob.lower()
                    got = [f for f in fragments if f.lower().encode() in low
                           or f.lower().encode("utf-16-le") in low]
                else:
                    got = [f for f in fragments if f.encode() in blob
                           or f.encode("utf-16-le") in blob]
                if got:
                    print("== %s [%s]: фрагменты %s" % (name, how, ", ".join(got)))
            if do_xor and len(blob) <= 64 * 1024 * 1024:
                for key, off in xor_scan(blob, needle):
                    total += 1
                    print("== %s [%s]: XOR 0x%02x +%#x" % (name, how, key, off))
                    break
    if not total:
        print("нет ни в открытом виде, ни после распаковки%s" %
              (", ни под однобайтовым xor" if do_xor else ""))
    return total, listed


# ------------------------------------------------------- сеть и файлы на устройстве
CDN_URLS = (
    "https://cdn.kolson.online/servers.json",
    "https://cdnru.kolson.online/servers.json",
    "https://cdn.kolson.online/launcher-release-v7.json",
    "https://cdnru.kolson.online/launcher-release-v7.json",
)


def net_scan(needle, urls=CDN_URLS, timeout=20):
    """Качает политики лаунчера и ищет в них строку/фрагменты."""
    import urllib.request
    total = 0
    frags = [needle] + [needle[:6], "сторон", "библиотек"]
    for u in urls:
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "kolson-find/1"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read()
                code = r.status
        except Exception as e:
            print("== %s: %s" % (u, e))
            continue
        print("== %s: HTTP %s, %d байт" % (u, code, len(body)))
        try:
            txt = body.decode("utf-8", "replace")
        except Exception:
            txt = ""
        hit = [f for f in frags if f.lower() in txt.lower()]
        if hit:
            total += 1
            print("   ЕСТЬ: %s" % ", ".join(hit))
            low = txt.lower()
            for f in hit:
                i = low.find(f.lower())
                print("   ...%s..." % " ".join(txt[max(0, i - 120):i + 160].split()))
        else:
            print("   нет вхождения; ключи: %s" % ", ".join(sorted(set(
                re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]{2,24})"\s*:', txt)))[:25]))
    return total


def grep_dir(folder, needle, max_size=64 * 1024 * 1024):
    """Ищет строку в файлах папки (данные игры/лаунчера на устройстве)."""
    total = 0
    for root, _dirs, files in os.walk(folder):
        for f in files:
            path = os.path.join(root, f)
            try:
                if os.path.getsize(path) > max_size:
                    continue
                raw = open(path, "rb").read()
            except OSError:
                continue
            hits = search_blob(raw, needle)
            if hits:
                total += 1
                print("== %s: %d" % (path, len(hits)))
                for off, enc in hits[:5]:
                    print("   +%#x [%s] %r" % (off, enc, context(raw, off, enc)))
    if not total:
        print("в %s строки нет" % folder)
    return total


def audit(target, needle="сторонние библиотеки", do_net=True):
    """Полная проверка в один проход: APK (все байты), папки на устройстве, сеть."""
    apks = []
    if os.path.isdir(target):
        for root, _d, files in os.walk(target):
            for f in files:
                if f.lower().endswith((".apk", ".apks", ".zip")):
                    apks.append(os.path.join(root, f))
    else:
        apks = [target]
    apks.sort()
    print("# audit: %d архив(ов), строка %r" % (len(apks), needle))
    for path in apks:
        try:
            with zipfile.ZipFile(path) as z:
                infos = [i for i in z.infolist()
                         if not i.filename.endswith("/") and not i.filename.startswith("META-INF/")]
        except (OSError, zipfile.BadZipFile) as e:
            print("\n## %s: не читается (%s)" % (path, e))
            continue
        names = [i.filename for i in infos]
        top = sorted(((i.file_size, i.filename) for i in infos), reverse=True)[:12]
        print("\n## %s" % os.path.basename(path))
        print("   файлов: %d, 9 крупнейших: %s" % (len(names), ", ".join(
            "%s(%.1fM)" % (n, sz / 1e6) for sz, n in top[:9])))
        unity = any("assets/bin/Data" in n for n in names)
        print("   unity-ассеты: %s | split: %s | dex: %d" % (
            "да" if unity else "нет",
            "да" if any(n.startswith("split_") for n in names) else "нет",
            sum(1 for n in names if re.match(r"classes\d*\.dex$", n))))
        total, _listed = deep_scan(path, needle, ["сторон", "библиотек", "перезапуст",
                                                  "папки 1NEIZZIR", "Custom/modules"],
                                   do_xor=True)
        print("   ИТОГ по файлу: %d вхождений" % total)
    # папки игры на устройстве
    for folder in ("/sdcard/1NEIZZIR", "/sdcard/Android/data/com.br.top",
                   "/storage/emulated/0/Android/data/com.br.top"):
        if os.path.isdir(folder):
            print("\n## папка %s" % folder)
            n = grep_dir(folder, needle.split()[0] if needle else "сторон")
            print("   вхождений: %d" % n)
    if do_net:
        print("\n## сеть (канал обновлений лаунчера)")
        net_scan(needle)
    print("\nготово")


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
    if "--audit" in argv:
        i = argv.index("--audit")
        target = argv[i + 1]
        out = argv[argv.index("-o") + 1] if "-o" in argv else "audit.txt"
        skip = {"-o", out, target, "--audit", "--no-net"}
        rest = [a for a in argv[1:] if not a.startswith("--") and a not in skip]
        needle = rest[0] if rest else "сторонние библиотеки"
        class _Tee2:
            def __init__(self):
                self.buf = io.StringIO()

            def write(self, s):
                sys.__stdout__.write(s)
                self.buf.write(s)

            def flush(self):
                sys.__stdout__.flush()

        tee = _Tee2()
        sys.stdout = tee
        try:
            audit(target, needle, do_net="--no-net" not in argv)
        except Exception as e:                      # чтобы отчёт всё равно сохранился
            print("\nОШИБКА: %r" % e)
        finally:
            sys.stdout = sys.__stdout__
            open(out, "w", encoding="utf-8").write(tee.buf.getvalue())
            print("\nотчёт сохранён: %s — пришли его целиком" % out)
        return 0
    if "--net" in argv:
        i = argv.index("--net")
        needle = argv[i + 1] if len(argv) > i + 1 and not argv[i + 1].startswith("--") \
            else "сторонние библиотеки"
        return 0 if net_scan(needle) else 1
    if "--grep-dir" in argv:
        i = argv.index("--grep-dir")
        folder = argv[i + 1]
        rest = [a for a in argv[i + 2:] if not a.startswith("--")]
        needle = rest[0] if rest else "сторонние библиотеки"
        return 0 if grep_dir(folder, needle) else 1
    if "--ls" in argv:
        i = argv.index("--ls")
        path = argv[i + 1]
        print("содержимое %s:" % path)
        for name, raw in sorted(iter_blobs(path), key=lambda x: -len(x[1]))[:80]:
            print("   %10d  %s" % (len(raw), name))
        return 0
    if "--deep" in argv:
        i = argv.index("--deep")
        path = argv[i + 1]
        rest = [a for a in argv[1:] if not a.startswith("--") and a != path
                and a not in (argv[argv.index("-o") + 1] if "-o" in argv else "",)]
        needle = rest[0] if rest else "сторонние библиотеки"
        frags = None
        if "--frag" in argv:
            frags = [f for f in rest[1:]] or ["сторон", "библиотек", "перезапуст"]
        total, listed = deep_scan(path, needle, frags, do_xor="--xor" in argv)
        print("итого вхождений %r: %d (файлов: %d)" % (needle, total, len(listed)))
        return 0 if total else 1
    if "--scan-dir" in argv:
        i = argv.index("--scan-dir")
        folder = argv[i + 1]
        pos = [a for a in argv[1:] if not a.startswith("--") and a != folder
               and a not in (argv[argv.index("-o") + 1] if "-o" in argv else "", )]
        needle = pos[0] if pos else "сторонние библиотеки"
        files = sorted(f for f in os.listdir(folder) if re.search(r"\.(apk|apks|zip)$", f))
        print("папка %s: %d apk" % (folder, len(files)))
        hit = []
        for f in files:
            try:
                n = scan_apk(os.path.join(folder, f), needle)
            except (zipfile.BadZipFile, OSError) as e:
                print("   %s: пропущено (%s)" % (f, e))
                continue
            if n:
                hit.append((f, n))
        print("итого: %s" % (", ".join("%s (%d)" % h for h in hit) if hit else "нет совпадений"))
        return 0 if hit else 1
    if "--hide" in argv:
        i = argv.index("--hide")
        src = argv[i + 1]
        dst = "hid.apk"
        if "-o" in argv:
            dst = argv[argv.index("-o") + 1]
        pos = [a for a in argv[1:] if not a.startswith("--") and a not in ("-o", dst, src)]
        needle = pos[0] if pos else "сторонние библиотеки"
        hide_apk(src, dst, needle)
        return 0
    if "--report" in argv:
        i = argv.index("--report")
        out = argv[i + 1]
        class _Tee:
            def __init__(self, fh):
                self.fh = fh
                self.buf = io.StringIO()

            def write(self, s):
                sys.__stdout__.write(s)
                self.buf.write(s)

            def flush(self):
                sys.__stdout__.flush()

        tee = _Tee(None)
        sys.stdout = tee
        try:
            rc = main([a for a in argv if a not in ("--report", out)])
        finally:
            sys.stdout = sys.__stdout__
            open(out, "w", encoding="utf-8").write(tee.buf.getvalue())
            print("отчёт: %s" % out)
        return rc
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
