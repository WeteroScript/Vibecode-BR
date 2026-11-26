# Smali-обёртки для патча libkolson

Сейчас есть один рекомендуемый вариант — **одна библиотека** `libkolson_patch.so`
(`kolson_one.c`): она находит/подгружает штатную `libkolson.so`, патчит её уже в
памяти и не трогает ни одного файла. Ей соответствует `KolsonPatch.smali`.

`NativeLoader.smali` — старый вариант «подменить загрузку на свою копию
библиотеки»; он оставлен как альтернатива, но требует второй копии `.so` и
возится с SONAME.

```
smali/
├── KolsonPatch.smali    # ОДНА библиотека: apply() / applyFrom(dir) / status()
├── NativeLoader.smali   # альтернатива: грузим патченную копию вместо оригинала
├── check_smali.py       # статическая проверка smali без JDK
└── README.md
```

## Вариант A (рекомендуется): одна библиотека

1. `libkolson_patch.so` → `lib/arm64-v8a/libkolson_patch.so` в APK.
2. `KolsonPatch.smali` → `smali_classesN/com/klnc/native/KolsonPatch.smali`.
3. Вызов в `NativeLibraryLoader$load$2.invokeSuspend` после успешной загрузки
   (или в `KolsonLibrary.loadKolsonLibrary` сразу после `loadLibrary("kolson")`):

```smali
invoke-static {}, Lcom/klnc/native/KolsonPatch;->apply()I
move-result v0
```

`apply()` возвращает число применённых слов (25) и пишет в logcat
`kolson_patch: <path> base=… patched=25 failed=0`. `status()` отдаёт строку
`patched=… failed=… base=… path=…`, `patchedCount()` — только число.

Почему так безопаснее: файл `libkolson.so` остаётся оригинальным (sha256 тот же),
второй копии игровой библиотеки в процессе нет (никаких конфликтов SONAME), и в
`1NEIZZIR/Modules` / `Custom/modules` ничего не появляется — сканеру сторонних
модулей нечего находить. Патч ставится между `loadLibrary("kolson")` и первым
нативным вызовом, а вердикт защиты внутри `libkolson` считается лениво, поэтому
«чисто» не ломается.

## Вариант B (альтернатива): своя копия библиотеки

Грузим `libklnc.so` (SONAME `libklnc.so`, `make patch-klnc`) вместо стоковой:

```smali
-    invoke-static {v5}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
+    invoke-static {v5}, Lcom/klnc/native/NativeLoader;->load(Ljava/lang/String;)V
```

Три места загрузки `"kolson"` в `classes8.dex`:

| файловый офсет `const-string` | класс / метод |
|---|---|
| `0x213072` | `Lcom/blackhub/bronline/neizzir/KolsonLibrary;->loadKolsonLibrary(Landroid/content/Context;)V` |
| `0x214166` | `Lcom/blackhub/bronline/neizzir/KolsonReleaseFeed;->verifyNative([B[B)Z` |
| `0x214892` | `Lcom/blackhub/bronline/neizzir/KolsonServerPolicySync;->verifyNative([B[B)Z` |

Заворачивать надо все три, иначе позже догрузится стоковая `libkolson.so` вторым
экземпляром и её `JNI_OnLoad` перерегистрирует методы поверх наших.

### Где менять (вариант B)

Положить файл как `smali_classesN/com/klnc/native/NativeLoader.smali` и в каждом
из трёх мест поменять `method_id` (дескриптор тот же `(Ljava/lang/String;)V`,
регистры, строки и `.catch` не трогаются):

```smali
-    invoke-static {v5}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
+    invoke-static {v5}, Lcom/klnc/native/NativeLoader;->load(Ljava/lang/String;)V
```

`load()` сначала пробует патченную копию (`libklnc` из APK → `<filesDir>/libklnc.so`
→ `/data/local/tmp/libklnc.so`), и только если её нет — вызывает штатный
`loadLibrary(name)`, то есть приложение остаётся работоспособным в любом случае.

Сборка: `apktool b` / `smali assemble`; подпись и установка как обычно.

### Правка dex без пересборки дерева

Обе инструкции 2-байтные, поэтому достаточно переписать `method_id` вызова
(и, при желании, `string_id`):

```
было:  1a 05 84 47            const-string v5, "kolson"        (string@0x4784)
       71 10 a7 35 05 00      invoke-static {v5}, System->loadLibrary (method@0x35a7)
стало: 1a 05 84 47            const-string v5, "kolson"        (можно оставить)
       71 10 XX XX 05 00      invoke-static {v5}, Lcom/klnc/native/NativeLoader;->load
```

`method_id` нашего класса появляется в пуле только после инъекции класса в
`classes8.dex` (dexlib2 / `baksmali`-цикл). Если инжектить класс не хочется —
см. вариант «без нового класса» в шапке `NativeLoader.smali`
(`const-string` → путь, `loadLibrary` → `System.load`), но там нужен
`string_id` на путь и `method_id` `System.load(String)`.

### SONAME: когда нужен `-n`

`bionic` опознаёт библиотеку по `DT_SONAME`. Релизный
`libkolson.unlocked.so` собран без `-n`, т.е. с `SONAME libkolson.so`:

* **Сценарий A (рекомендуемый, файл можно брать из релиза как есть).**
  Все три сайта завернуты в `NativeLoader`, наша копия грузится **первой** —
  она занимает имя `libkolson.so` в линкере, и любой последующий
  `loadLibrary("kolson")` вернёт уже наше отображение. Пересборка с `-n` не нужна.
  Файл кладётся как `lib/arm64-v8a/libklnc.so` или `/data/local/tmp/libklnc.so`
  (имя файла и SONAME не связаны).
* **Сценарий B (кто-то мог загрузить оригинал раньше нас).** Нужен уникальный
  SONAME, иначе `bionic` схлопнет копию с оригиналом и `JNI_OnLoad` не выполнится:

  ```
  ./kolson_unlock -i libkolson.so -o libklnc.so -n libklnc.so
  ```

  Проверить: `readelf -d libklnc.so | grep SONAME` → `libklnc.so`, остальные
  `NEEDED` целы (`kolson_verify.py` печатает строку `soname …`).

### Куда положить файл на устройстве

| путь | кто пускает | комментарий |
|---|---|---|
| `lib/arm64-v8a/libklnc.so` в APK | всегда | приоритет, `System.loadLibrary("klnc")` |
| `/data/data/<pkg>/files/libklnc.so` | `permitted_paths` содержит `/data` | если файл кладёт сам код |
| `/data/local/tmp/libklnc.so` | namespace пускает (`/data`) | на retail-устройствах SELinux обычно режет `exec` из `shell_data_file` — только root/эмулятор |

## Проверка smali

```bash
python3 check_smali.py NativeLoader.smali     # 0 error(s), 0 warning(s)
```

Проверяются опкоды/форматы, диапазоны `vN`/`pN`, соответствие `.registers`
числу параметров, парность меток и `.catch`, дубли `.method`.
