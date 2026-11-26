# kolson unlock

Вырубает всю защиту `libkolson.so` (`KOLSON_6`, AArch64, 6 956 216 B) и отдаёт в
качестве ответов «проверка пройдена». Два способа:

| способ | что делает | когда использовать |
|---|---|---|
| **одна библиотека** `libkolson_patch.so` | находит/подгружает штатную `libkolson.so` и патчит 25 слов **в памяти**; файл игры не меняется, второй копии в процессе нет | APK: `lib/arm64-v8a/libkolson_patch.so`, один вызов `loadLibrary` |
| **offline** `kolson_unlock` | правит 25 слов прямо в `.so`, на выходе `libkolson.unlocked.so` (или `libklnc.so` с ключом `-n`), размер байт в байт как у оригинала | замена файла в APK / `lib/arm64-v8a/` |
| **runtime** `libkolson_unlock_rt.so` | конструктор находит уже замапленный `libkolson.so`, валидирует слова, патчит через `mprotect(rwx)`, сбрасывает i-cache, возвращает `r-x` | оригинал на диске не трогаем, `LD_PRELOAD` / инжект |

Оба читают одну таблицу — `kolson_patches.h`. Точка входа одна: если слово на
месте не совпало с эталонным, сайт не патчится (offline-режим вообще
останавливается, если не `--force`).

## что именно выключается

| модуль | RVA | было | стало | эффект |
|---|---|---|---|---|
| `core` | `0x166c54` | `paciasp; stp …` | `mov w0,wzr; ret` | агрегатор проверок всегда возвращает 0 флагов |
| `tracer` | `0x170528` | `paciasp; sub sp` | `mov w0,wzr; ret` | inotify-вотчер за `/proc` не создаётся |
| `tracer` | `0x170638` | `paciasp; stp …` | `mov w0,wzr; ret` | тело трейсер-потока отключено |
| `weapon` | `0x2129cc` | `ldr w0,[x8,#0x110]` | `mov w0,wzr` | геттер кэш-флага `weapon_tamper` всегда 0 |
| `weapon` | `0x212b60`, `0x212b94` | `cbnz x8,#abort` | `nop` | дайджест-проверки оружия не уводят в abort-путь: `KOLSON_WEAPON`-хендлер доходит до конца и ставит `0x6ba118/0x6ba120` |
| `gate` | `0x243bb4` | `paciasp; sub sp` | `mov w0,#1; ret` | «клиентская либа наша» → да |
| `gate` | `0x244800` | `paciasp; sub sp` | `mov w0,#1; ret` | чтение команд/дайджестов → ok |
| `sig` | `0x244278, 0x2442ac, 0x2442cc, 0x244388, 0x2443a4, 0x2443b8, 0x2443c8, 0x2443dc` | `tbz/cbnz/b.ne` | `nop` | 18-RVA таблица отпечатков + 5 identity-констант больше не могут увести в `signature_mismatch` / `command_mismatch` |
| `crash` | `0x5244f8` | `paciasp; stp …` | `mov w0,wzr; ret` | хендлеры сигналов не ставятся |
| `crash` | `0x524640` | `paciasp; sub sp` | `mov w0,wzr; ret` | блок `sigaction/sigprocmask` выключен |

`signature_mismatch` не «подменяется текстом» — он просто недостижим: все
условные переходы, которые вели в `0x244484` (mismatch) и `0x244530`
(command_mismatch), стали `nop`, поэтому поток исполнения всегда доходит до
`stp x8,x9,[x13]` (запись «валидных» указателей) и `b 0x2444a4` с
`w23 = 0` — то есть «проверка прошла».

## сборка локально

```bash
cd tools/kolson/unlock
make                      # build/kolson_unlock (+ arm64 shim, если найден NDK)
make list                 # показать 25 сайтов и их слова в вашем билде
make one                  # build/libkolson_patch.so - ОДНА библиотека (нужен NDK)
make one-test             # хост-проверка: патч в памяти == offline-патч
make patch                # build/libkolson.unlocked.so (SONAME libkolson.so)
make patch-klnc           # build/libklnc.so (те же патчи, SONAME libklnc.so)
make verify               # аудит: стабы + дифф «ничего лишнего не изменено»
```

### одна библиотека (рекомендуется)

`make one` → `build/libkolson_patch.so` (≈12 КБ). Это единственный файл, который
нужно положить в APK: он сам находит (или `dlopen`-ит) штатную `libkolson.so`,
сверяет все 25 эталонных слов и патчит её **в памяти** — файл на диске остаётся
оригинальным, второй копии игровой библиотеки в процессе нет, и в
`1NEIZZIR/Modules` / `Custom/modules` ничего не появляется.

```
System.loadLibrary("kolson")          // штатная загрузка, как обычно
System.loadLibrary("kolson_patch")    // патч: 25 сайтов -> «проверка пройдена»
```

`make one-test` доказывает на хосте (без устройства и NDK), что runtime-патч даёт
**побайтово тот же образ**, что и offline-патчер:

```
kolson_patch_image: rc=0 patched=25 failed=0
bytes changed vs pristine: 98
bytes differing from build/libkolson.unlocked.so: 0
OK: runtime patch == offline patch
one-test: runtime patch == offline patch (byte-for-byte)
```

JNI-интерфейс (`smali/KolsonPatch.smali`): `nativeApply()`, `nativeApplyDir(dir)`,
`nativePatched()`, `nativeFailed()`, `nativeReport()`. Если библиотека только
предзагружена — конструктор делает то же самое без Java.

### два артефакта и SONAME

`bionic` опознаёт библиотеку по `DT_SONAME`, поэтому одна и та же патченная
сборка отдаётся в двух вариантах:

| файл | SONAME | когда брать |
|---|---|---|
| `libkolson.unlocked.so` | `libkolson.so` | грузим **первыми**; все последующие `System.loadLibrary("kolson")` вернут уже наше отображение |
| `libklnc.so` | `libklnc.so` | если стоковая `libkolson.so` могла быть замаплена раньше; тогда `System.load("/data/local/tmp/libklnc.so")` даёт отдельное отображение и свой `JNI_OnLoad` |

```bash
./kolson_unlock -i libkolson.so -o libklnc.so -n libklnc.so -v
readelf -d libklnc.so | grep SONAME        # libklnc.so
```

Строка в `.dynstr` переписывается только если новое имя не длиннее старого
(`libklnc.so` короче `libkolson.so`), остальные `NEEDED` не страдают.
Готовый smali-загрузчик: `smali/NativeLoader.smali` (+ `smali/README.md`).

NDK для рантайм-шима:

```bash
make NDK=$ANDROID_HOME/ndk/26.3.11579264 rt
# либо
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang \
  -O2 -fPIC -shared -I. -o build/libkolson_unlock_rt.so kolson_unlock_rt.c -llog -ldl
```

Подмножество модулей и обход несовпадения слов:

```bash
./kolson_unlock -i libkolson.so -o out.so --only sig,gate,tracer
./kolson_unlock -i libkolson.so --list      # выход 3, если билд не тот
./kolson_unlock -i libkolson.so -o out.so --force -v
```

## применение

**1. замена в APK** (файл `lib/arm64-v8a/libkolson.so`):

```bash
unzip -q app.apk -d app_x
cp build/libkolson.unlocked.so app_x/lib/arm64-v8a/libkolson.so
cd app_x && zip -9 -r ../app-unlocked.apk . && cd ..
zipalign -f -p 4 app-unlocked.apk app-unlocked-aligned.apk
apksigner sign --ks key.jks --out app-final.apk app-unlocked-aligned.apk   # подпись своя
```

`libkolson.so` обычно лежит несжатым и выровненным (`extractNativeLibs=false`) —
тогда размер и выравнивание обязаны совпадать. Патчер сохраняет размер байт в
байт и не двигает секции, так что это условие выполняется.

**2. рантайм, без изменения APK:**

```bash
adb push build/libkolson_unlock_rt.so /data/local/tmp/
adb shell su -c "LD_PRELOAD=/data/local/tmp/libkolson_unlock_rt.so \
                 am start -n com.br.top/<activity>"
```

Конструктор печатает в logcat:

```
kolson_unlock_rt: /data/app/.../lib/arm64-v8a/libkolson.so base=0x... patched=23 failed=0
```

Если `failed>0` — билд другой, в логе будет конкретное слово и адрес.

## CI

`.github/workflows/kolson-unlock.yml`:

* `push` по изменению `libkolson.so` / `tools/kolson/unlock/**` → сборка host
  патчера, `--list` (падает, если эталонные слова не совпали), патч, `--verify`,
  `kolson_verify.py` (стабы + дифф: **0 байт вне набора**), сборка arm64-шима
  через NDK 26.3, артефакт `kolson-unlocked.zip`.
* `workflow_dispatch` с `upload_release=true` → дополнительно `gh release create`
  с зипом (`tag_only`/`upload_release`/`release_tag` — входные параметры).

Локальный прогон без Actions: `make patch verify`.

## проверки, которые остаются живыми

* **`0x74180`-таблица всё ещё физически в файле** — мы её не трогали, но её
  потребитель (`0x243efc`) больше не может уйти в mismatch, поэтому значения
  не важны.
* **Сторона dex** (`classes8.dex`): `WeaponChecksum.sha1OfFile`, `StockCacheIdentity`,
  `KeyManager.verifyKey` (ECDSA) — это лаунчер/контент, не нативная защита.
  Если нужно — это отдельный патч на smali, к этой таблице отношения не имеет.
* **Подпись APK**: если положить патченный `.so` в APK, подпись пересчитывается
  (см. `apksigner`). Сама либа целостность APK не проверяет.
* `libumbrella.so` / `libblackrussia-client.so` в репозитории отсутствуют —
  не проверялось, но по строкам `libkolson` только *сравнивает имена* модулей
  через `dl_iterate_phdr`, ничего из них не вызывает.

## gotchas

* `.text` в этом ELF имеет `file_offset == virtual_address`, поэтому патчер
  читает/пишет по VA напрямую. Для другого билда это надо перепроверять
  (в `re/` есть `dump_arm64.py`/`xref.py`).
* `paciasp` в точке входа — не трогаем `BTI`, поэтому на ядрах с BTI
  страницы остаются валидными: мы пишем `mov`/`ret` сразу после `paciasp`,
  сама `paciasp` замещается только у функций-стабов (там `ret` уже не
  возвращается в PAuth-контекст, ключ не нужен).
* Инструкции пишутся по 8 байт (2 слова) — i-cache сбрасывается по странице,
  для рантайм-шима `dc ivac` + `ic ivau` + `dsb ish; isb`.
* Рантайм-шим должен грузиться **после** того, как `libkolson.so` замаплен
  (иначе он честно скажет `not loaded yet`). Если нужен режим «до», используйте
  offline-патч.

## если лаунчер пишет «Удалите сторонние библиотеки из папки …»

Это сообщение **не** dex-строка: в `classes8.dex` / `classes9.dex` его нет,
и в `libkolson.so` его тоже нет. Что есть в dex — только имена папок
(`/storage/emulated/0/1NEIZZIR/Modules/`, `Custom/modules`), а сам текст
приходит из ресурсов (`resources.arsc`, строка-шаблон с `%1$s`/`%2$s`) либо
из другого dex / нативной части лаунчера. Поэтому грепать `classes8.dex` по
«Удалите» бесполезно.

Найти источник на своём APK:

```bash
# весь APK: все classesN.dex + resources.arsc + assets + все lib/*/*.so
python3 tools/kolson/find_notice.py app.apk "сторонние библиотеки"

# или сразу снять APK с подключённого телефона и просканировать
python3 tools/kolson/find_notice.py --device com.br.top "сторонние"
```

Вывод даёт файл + офсет + (для arsc) номер строки в пуле. Дальше по номеру
строки ищется `R.string` в dex, а по нему — метод, который её показывает.

Пока источник не найден, причины баннера проверяются в таком порядке:

1. **лишние `.so` в `lib/arm64-v8a`** — лаунчер перечисляет загруженные
   библиотеки и сравнивает с тем, что лежит в APK. Наш `libkolson_patch.so`
   (и прежний `libklnc.so`) — как раз «сторонняя библиотека». Вариант без
   единого лишнего файла: offline-патч (`--patch`, замена
   `lib/arm64-v8a/libkolson.so`) — имя и число библиотек не меняются;
2. **загрузка не из APK** — `LD_PRELOAD=/data/local/tmp/...` или `System.load()`
   по абсолютному пути даёт библиотеку из «чужой» папки; для чистого теста
   ставить только через APK;
3. **реально занятые папки модулей**:

   ```bash
   adb shell 'ls -la /sdcard/1NEIZZIR/Modules 2>&1;
              ls -la /sdcard/Android/data/com.br.top/files/Custom/modules 2>&1'
   ```

   если там лежат `.so` от прошлых модов — убрать их и перезапустить игру;
4. **лог** — что именно лаунчер считает сторонним:

   ```bash
   adb logcat -c; adb shell am start -n com.br.top/... ; sleep 8
   adb logcat -d | grep -iE "modules|third|сторон|umbrella|kolson" | head -50
   ```

### если APK нельзя никуда загрузить

Всё считается на телефоне (Termux) или на ПК, ничего никуда не отправляется.

```bash
# 1) скрипт (без зависимостей, чистый python3)
curl -LO https://raw.githubusercontent.com/WeteroScript/Vibecode-BR/\
arena/0d3e1ff3-vibecode-br/tools/kolson/find_notice.py

# 2) найти APK, если не помнишь где он
ls -la /sdcard/Download/*.apk /sdcard/*.apk 2>/dev/null

# 3) просканировать все apk в папке (все dex + arsc + assets + .so)
python3 find_notice.py --scan-dir /sdcard/Download "сторонние"

# 4) отчёт по конкретному APK текстом (его можно скопировать/переслать)
python3 find_notice.py /sdcard/Download/base.apk "сторонние" --report notice.txt

# 5) сразу обезвредить баннер (строка станет невидимой, длина файла не меняется)
python3 find_notice.py --hide /sdcard/Download/base.apk -o /sdcard/Download/base-clean.apk
```

`--hide` бланкирует найденные вхождения невидимыми символами той же байтовой
длины: пул строк `resources.arsc`, строки dex (по строковым офсетам, uleb-длина
не трогается) и строки в `assets/*` / `lib/*/*.so`. Смещения и размеры не
меняются, но `resources.arsc` попадает в APK — подпись всё равно пересчитывается
(она и так пересчитывается из-за замены `libkolson.so`).

Важно: `--hide` убирает только текст. Если баннер ещё и блокирует функции,
нужен патч самой проверки — тогда по отчёту (`--report`) видно класс/метод и
дальше правится либо dex, либо нативная часть.

### если по всему APK 0 вхождений

Значит текст **не хранится в APK в открытом виде**. Дальше по порядку:

```bash
# 1) канал обновлений лаунчера (servers.json / launcher-release-v7.json на CDN)
python3 find_notice.py --net "сторонние"

# 2) данные игры на устройстве (если лаунчер скачал текст в свою папку)
python3 find_notice.py --grep-dir /sdcard/1NEIZZIR "сторон"
python3 find_notice.py --grep-dir /sdcard/Android/data/com.br.top "сторон"

# 3) APK целиком: все файлы (не только dex/arsc/assets) + распаковка gzip/zlib/xz
#    + перебор однобайтового XOR (если текст зашифрован, как в Unity-ассетах)
python3 find_notice.py --deep base.apk "сторонние" --xor

# 4) текст мог быть собран из кусков — ищем фрагменты
python3 find_notice.py --deep base.apk "сторонние" --frag сторон библиотек перезапуст

# 5) если APK из App Bundle — частей несколько, сканировать надо все
python3 find_notice.py --scan-dir /sdcard/Download "сторонние"

# и просто посмотреть состав APK (Unity это или нет)
python3 find_notice.py --ls base.apk
```

Если и это пусто — текст приходит с сервера в момент срабатывания проверки (или
собирается в рантайме из ресурсов, подгруженных по сети). В этом случае
прятать нечего: убирать надо **причину** срабатывания — лишние `.so`
(см. пункты 1–2 выше), а не сообщение.

### один запуск, один отчёт (для случая «APK на телефоне, выгружать некуда»)

```bash
python3 find_notice.py --audit "/storage/emulated/0/Download/Telegram" -o audit.txt
# или по конкретному файлу (кавычки обязательны: пробелы и скобки в имени)
python3 find_notice.py --audit "/storage/emulated/0/Download/Telegram/NEIZZIR 3.7.9 16.116.0 (1).apk" -o audit.txt
cat audit.txt
```

`--audit` за один проход: состав архива (Unity-ассеты/split/dex), поиск строки во
**всех** файлах как есть, после распаковки (gzip/zlib/xz), под однобайтовым XOR,
по фрагментам слов; затем те же поиски в папках игры на устройстве
(`/sdcard/1NEIZZIR`, `/sdcard/Android/data/com.br.top`) и в канале обновлений
лаунчера. Отчёт пишется в файл — его можно просто переслать текстом.

### чистая установка: набор `.so` как в оригинале

Аудит APK показал, что баннер «Удалите сторонние библиотеки…» висит на APK, внутри
которого лежит **`lib/arm64-v8a/libklnc.so`** — наш собственный шим, файл, которого
в оригинальном APK нет. Лаунчер сравнивает набор библиотек с тем, что было
изначально, и такой файл для него сторонний.

Правильная (и единственная без лишних файлов) установка — замена самого
`libkolson.so`; патченный код уже внутри него, имя и число библиотек не меняются:

```bash
# 1) что в APK лишнего (и зовёт ли dex наши имена)
python3 repack_clean.py --check app.apk

# 2) собрать чистый APK: заменить libkolson.so, выбросить libklnc.so/libkolson_patch.so
python3 repack_clean.py --apk app.apk --so libkolson.unlocked.so -o app-clean.apk

# 3) подписать (подпись всё равно пересчитывается)
zipalign -f -p 4 app-clean.apk app-clean-aligned.apk
apksigner sign --ks key.jks --out app-final.apk app-clean-aligned.apk
```

`libkolson.unlocked.so` берётся из релиза `kolson-unlock-v1`
(sha256 `3ec7f6ce111511ec4d527bda89e885ebfcfea6eb8cbbdf01484d740c14241066`,
размер совпадает с оригиналом байт в байт: 6 956 216).

На телефоне шаги 2–3 делает MT Manager: открыть APK → заменить
`lib/arm64-v8a/libkolson.so` → удалить `libklnc.so` → «Подписать».

Требование: dex должен быть **оригинальным** — вызов
`System.loadLibrary("kolson")` в `KolsonLibrary.loadKolsonLibrary` уже есть, ничего
дописывать в smali не нужно. `repack_clean.py --check` предупреждает, если в dex
остались ссылки на `klnc`/`kolson_patch`.

## обходчик, которого не видно (`kolson_stealth.c`)

Сам обходчик — это `libkolson_patch.so` (12 КБ): **файл `libkolson.so` он не
меняет**, а находит уже загруженную библиотеку в памяти и выключает в ней 25
проверок (`mov w0,#1; ret` / `nop`, 98 байт из 6 956 216). Обратная сторона:
для проверки «сторонние библиотеки» наш `.so` — такой же посторонний файл, как
любой мод, и он виден в списке модулей и в `/proc/self/maps`.

`kolson_stealth.c` закрывает именно это, без записи чего-либо на диск:

* `kolson_stealth_promote()` — поднимает нас в `RTLD_GLOBAL`; библиотека,
  загруженная после нас (`libkolson.so`), при биндинге импортов `open`/`fopen`/
  `dl_iterate_phdr` берёт наши функции (обычный PLT-interpose);
* `kolson_stealth_install()` — для модулей, загруженных раньше нас, точечно
  подменяет их GOT-записи на те же обёртки;
* `open`/`open64`/`openat`/`fopen`/`fopen64` — на `/proc/self/maps` отдают
  отфильтрованную копию (memfd), из которой выкинуты строки с нашими маркерами;
* `dl_iterate_phdr` — не показывает наши модули в списке;
* маркеры по умолчанию: `libklnc.so`, `libkolson_patch.so`, `libkolson.unlock`,
  плюс `KOLSON_STEALTH_MARKS` (через `:`/пробел) для переименованных сборок.

Вход со стороны Java/smali:

```smali
invoke-static {}, Lcom/klnc/native/KolsonPatch;->apply()I     # 25 проверок
invoke-static {}, Lcom/klnc/native/KolsonPatch;->stealth()I   # спрятать себя
```

Проверки без устройства:

```bash
make stealth-test    # host: сырые maps содержат маркер -> обёртки его не отдают
make one-test        # runtime patch == offline patch, байт в байт
```

`make stealth-test` печатает `RESULT: OK (обёртки прячут наш модуль)`.
