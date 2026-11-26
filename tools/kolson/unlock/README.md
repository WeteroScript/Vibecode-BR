# kolson unlock

Вырубает всю защиту `libkolson.so` (`KOLSON_6`, AArch64, 6 956 216 B) и отдаёт в
качестве ответов «проверка пройдена». Два способа:

| способ | что делает | когда использовать |
|---|---|---|
| **offline** `kolson_unlock` | правит 23 слова прямо в `.so`, на выходе `libkolson.unlocked.so`, побайтово совпадает по размеру с оригиналом | замена файла в APK / `lib/arm64-v8a/` |
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
| `weapon` | `0x2129cc` | `ldr w0,[x8,#0x110]` | `mov w0,wzr` | кэш-флаг `weapon_tamper` всегда 0 |
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
make list                 # показать 23 сайта и их слова в вашем билде
make patch                # build/libkolson.unlocked.so
make verify               # аудит: стабы + дифф «ничего лишнего не изменено»
```

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
