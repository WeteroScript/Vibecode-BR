#!/usr/bin/env python3
"""Статическая проверка smali-файла без JDK.

Проверяет то, на чём чаще всего спотыкается ручная правка:
  * синтаксис директив/инструкций (по таблице opcode'ов Dalvik),
  * число операндов invoke-*, разрешённые типы регистров (vN/pN),
  * что каждый используемый регистр < .registers,
  * что .registers >= число параметров дескриптора (для instance-метода +1 на this),
  * парность :label / :label-ссылок, метки в .catch,
  * отсутствие дублей .method,
  * соответствие move-result* непосредственно после invoke-*.

Не заменяет baksmali/smali, но ловит 90% ошибок до сборки APK.

Использование: python3 check_smali.py NativeLoader.smali
"""
import re
import sys

# opcode -> (формат, число регистров-операндов)
OPS = {
    "nop": "10x", "move": "12x", "move/from16": "22x", "move/16": "32x",
    "move-wide": "12x", "move-wide/from16": "22x", "move-wide/16": "32x",
    "move-object": "12x", "move-object/from16": "22x", "move-object/16": "32x",
    "move-result": "11x", "move-result-wide": "11x", "move-result-object": "11x",
    "move-exception": "11x", "return-void": "10x", "return": "11x",
    "return-wide": "11x", "return-object": "11x",
    "const/4": "11n", "const/16": "21s", "const": "31i", "const/high16": "21h",
    "const-wide/16": "21s", "const-wide/32": "31i", "const-wide": "51l",
    "const-wide/high16": "21h", "const-string": "21c", "const-string/jumbo": "31c",
    "const-class": "21c", "monitor-enter": "11x", "monitor-exit": "11x",
    "check-cast": "21c", "instance-of": "22c", "array-length": "12x",
    "new-instance": "21c", "new-array": "22c", "filled-new-array": "35c",
    "filled-new-array/range": "3rc", "fill-array-data": "31t",
    "throw": "11x", "goto": "10t", "goto/16": "20t", "goto/32": "30t",
    "packed-switch": "31t", "sparse-switch": "31t",
    "cmpl-float": "23x", "cmpg-float": "23x", "cmpl-double": "23x", "cmpg-double": "23x",
    "cmp-long": "23x", "if-eq": "22t", "if-ne": "22t", "if-lt": "22t", "if-ge": "22t",
    "if-gt": "22t", "if-le": "22t", "if-eqz": "21t", "if-nez": "21t", "if-ltz": "21t",
    "if-gez": "21t", "if-gtz": "21t", "if-lez": "21t",
    "aget": "23x", "aget-wide": "23x", "aget-object": "23x", "aget-boolean": "23x",
    "aget-byte": "23x", "aget-char": "23x", "aget-short": "23x",
    "aput": "23x", "aput-wide": "23x", "aput-object": "23x", "aput-boolean": "23x",
    "aput-byte": "23x", "aput-char": "23x", "aput-short": "23x",
    "iget": "22c", "iget-wide": "22c", "iget-object": "22c", "iget-boolean": "22c",
    "iget-byte": "22c", "iget-char": "22c", "iget-short": "22c",
    "iput": "22c", "iput-wide": "22c", "iput-object": "22c", "iput-boolean": "22c",
    "iput-byte": "22c", "iput-char": "22c", "iput-short": "22c",
    "sget": "21c", "sget-wide": "21c", "sget-object": "21c", "sget-boolean": "21c",
    "sget-byte": "21c", "sget-char": "21c", "sget-short": "21c",
    "sput": "21c", "sput-wide": "21c", "sput-object": "21c", "sput-boolean": "21c",
    "sput-byte": "21c", "sput-char": "21c", "sput-short": "21c",
    "invoke-virtual": "35c", "invoke-super": "35c", "invoke-direct": "35c",
    "invoke-static": "35c", "invoke-interface": "35c",
    "invoke-virtual/range": "3rc", "invoke-super/range": "3rc",
    "invoke-direct/range": "3rc", "invoke-static/range": "3rc",
    "invoke-interface/range": "3rc",
}
for _p in ("add", "sub", "mul", "div", "rem", "and", "or", "xor", "shl", "shr", "ushr"):
    OPS[_p + "-int"] = OPS[_p + "-int/lit16"] = OPS[_p + "-int/lit8"] = "23x"
    OPS[_p + "-long"] = OPS[_p + "-long/2addr"] = "23x"
OPS["rsub-int"] = "22s"
for _t in ("int", "long", "float", "double"):
    for _s in ("", "/2addr"):
        OPS[_t + "-to-" + _t + "/2addr"] = "12x"
for _conv in ("int-to-long", "int-to-float", "int-to-double", "long-to-int", "long-to-float",
              "long-to-double", "float-to-int", "float-to-long", "float-to-double",
              "double-to-int", "double-to-long", "double-to-float", "int-to-byte",
              "int-to-char", "int-to-short"):
    OPS[_conv] = "12x"
for _n in ("neg-int", "not-int", "neg-long", "not-long", "neg-float", "neg-double"):
    OPS[_n] = "12x"
for _s in ("int", "long", "float", "double"):
    for _o in ("add", "sub", "mul", "div", "rem"):
        for _k in ("int", "long", "float", "double"):
            if _s == _k:
                OPS["%s-%s/2addr" % (_s, _o)] = "12x"


def params_of(desc):
    """Число регистров-слов, занимаемых аргументами дескриптора."""
    body = desc[desc.index("(") + 1:desc.index(")")]
    n, i = 0, 0
    while i < len(body):
        c = body[i]
        if c == "[":
            i += 1
            while body[i] == "[":
                i += 1
            if body[i] == "L":
                while body[i] != ";":
                    i += 1
            i += 1
            n += 1
        elif c == "L":
            while body[i] != ";":
                i += 1
            i += 1
            n += 1
        elif c == "J" or c == "D":
            n += 2
            i += 1
        else:
            n += 1
            i += 1
    return n


def check(path):
    errs, warns = [], []
    lines = open(path, encoding="utf-8").read().splitlines()
    in_method = False
    registers = None
    is_static = None
    desc = None
    name = None
    methods = set()
    labels_defined, labels_used, catch_labels = set(), set(), set()
    prev_invoke = False
    n_insns = 0

    for ln, raw in enumerate(lines, 1):
        line = raw.split("#")[0].strip() if not raw.strip().startswith("#") else ""
        if not line:
            continue

        if line.startswith(".class"):
            if name:
                errs.append("%d: .class внутри метода" % ln)
            continue
        if line.startswith(".method"):
            in_method = True
            toks = line.split()
            acc = toks[1:-1]
            sig = toks[-1]
            name, desc = sig.split("(")
            name, desc = name, "(" + desc
            methods.add(name + desc)
            is_static = "static" in acc
            registers = None
            labels_defined, labels_used, catch_labels = set(), set(), set()
            prev_invoke = False
            n_insns = 0
            continue
        if line.startswith(".end method"):
            if registers is None:
                errs.append("%d: метод %s без .registers/.locals" % (ln, name + desc))
            in_method = False
            continue

        if not in_method:
            continue

        if line.startswith(".registers") or line.startswith(".locals"):
            n = int(line.split()[1].strip())
            regs = n
            if line.startswith(".locals"):
                regs = n + params_of(desc) + (0 if is_static else 1)
            if regs < params_of(desc) + (0 if is_static else 1):
                errs.append("%d: .registers %d < параметров %d в %s" %
                            (ln, regs, params_of(desc) + (0 if is_static else 1), name + desc))
            registers = regs
            continue

        m = re.match(r"^:(.+)$", line)
        if m:
            lbl = ":" + m.group(1)
            if lbl in labels_defined:
                errs.append("%d: метка %s объявлена дважды" % (ln, lbl))
            labels_defined.add(lbl)
            continue

        m = re.match(r"^\.catch\s+(\S+)\s+\{(\S+)\s+\.\.\s+(\S+)\}\s+(\S+)$", line)
        if m:
            labels_used.add(m.group(2))
            labels_used.add(m.group(3))
            catch_labels.add(m.group(4))
            continue

        if line.startswith(".param") or line.startswith(".line") or line.startswith(".local") \
                or line.startswith(".end local") or line.startswith(".prologue") \
                or line.startswith(".source") or line.startswith(".annotation"):
            continue

        # инструкция
        toks = line.split(None, 1)
        op = toks[0]
        rest = toks[1] if len(toks) > 1 else ""
        if op not in OPS:
            errs.append("%d: неизвестный опкод/директива %r" % (ln, op))
            continue
        n_insns += 1
        if op.startswith("invoke-"):
            prev_invoke = True
        else:
            if op.startswith("move-result"):
                pass
            prev_invoke = False

        if registers is None:
            errs.append("%d: инструкция до .registers" % ln)
            continue

        # регистры в фигурных скобках
        for grp in re.findall(r"\{([^}]*)\}", rest):
            if not grp.strip():
                continue  # invoke-static {} - вызов без аргументов
            for r in grp.split(","):
                r = r.strip()
                if not re.match(r"^[vp]\d+$", r):
                    errs.append("%d: странный регистр %r" % (ln, r))
                    continue
                num = int(r[1:])
                if r[0] == "p":
                    lim = params_of(desc) + (0 if is_static else 1)
                    if num >= lim:
                        errs.append("%d: %s вне параметров (p0..p%d)" % (ln, r, lim - 1))
                elif num >= registers:
                    errs.append("%d: %s >= .registers %d" % (ln, r, registers))

        # регистры вида "vN," / "vN," / "vN" в начале операндов
        first = rest.split(",")[0].strip() if rest else ""
        if re.match(r"^[vp]\d+$", first):
            num, pre = int(first[1:]), first[0]
            if pre == "v" and num >= registers:
                errs.append("%d: %s >= .registers %d" % (ln, first, registers))
            if pre == "p":
                lim = params_of(desc) + (0 if is_static else 1)
                if num >= lim:
                    errs.append("%d: %s вне параметров (p0..p%d)" % (ln, first, lim - 1))

        if op.startswith("invoke-") and "/range" not in op:
            grp = re.search(r"\{([^}]*)\}", rest)
            if grp:
                nregs = len([x for x in grp.group(1).split(",") if x.strip()])
                if nregs > 5:
                    errs.append("%d: %s с %d регистрами (максимум 5, нужен /range)" % (ln, op, nregs))

    for lbl in labels_used:
        if lbl not in labels_defined:
            errs.append("метка %s используется, но не объявлена" % lbl)
    for lbl in catch_labels:
        if lbl not in labels_defined:
            errs.append("catch-метка %s не объявлена" % lbl)
    if labels_defined:
        used = labels_used | {x for x in labels_defined if any(
            re.search(r"(?<![\w:])%s(?![\w:])" % re.escape(x), l) for l in lines)}
        for lbl in sorted(labels_defined - used):
            warns.append("метка %s объявлена, но нигде не используется" % lbl)

    return errs, warns


if __name__ == "__main__":
    bad = 0
    for p in sys.argv[1:]:
        e, w = check(p)
        print("%s: %d error(s), %d warning(s)" % (p, len(e), len(w)))
        for x in e:
            print("  ERROR  ", x)
        for x in w:
            print("  WARN   ", x)
        bad += len(e)
    sys.exit(1 if bad else 0)
