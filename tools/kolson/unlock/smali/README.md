# Smali-загрузчик патченной `libkolson`

`NativeLoader.smali` — класс, который грузит **патченную** копию библиотеки и тем
самым вызывает её `JNI_OnLoad` (`libkolson.so` @ RVA `0x29e3d0`, 2424 B:
`RegisterNatives` + установка хуков). Отдельно дёргать `JNI_OnLoad` из Java нельзя,
его вызывают `System.load()` / `System.loadLibrary()`.

```
smali/
├── NativeLoader.smali   # класс com/klnc/native/NativeLoader - сам загрузчик
├── check_smali.py       # статическая проверка smali без JDK (опкоды, регистры, метки)
└── README.md
```

## 1. Куда именно грузится

Три места в `classes8.dex` грузят `"kolson"` (string_idx 18308), все по шаблону
`const-string vN, "kolson"` + `invoke-static {vN}, System->loadLibrary`:

| файловый офсет `const-string` | класс / метод |
|---|---|
| `0x213072` | `Lcom/blackhub/bronline/neizzir/KolsonLibrary;->loadKolsonLibrary(Landroid/content/Context;)V` |
| `0x214166` | `Lcom/blackhub/bronline/neizzir/KolsonReleaseFeed;->verifyNative([B[B)Z` |
| `0x214892` | `Lcom/blackhub/bronline/neizzir/KolsonServerPolicySync;->verifyNative([B[B)Z` |

Поиск сделан по всем `invoke-static … loadLibrary` в `classes8.dex`
(androguard) — других загрузок `kolson` нет; `classes9.dex` его не упоминает
(`NativeDecoder.<clinit>` грузит посторонний `wndecryptor`). DEX-файлов
`classes1..7.dex` в репозитории нет — их стоит перепроверить тем же способом.

**Заменять нужно все три.** Если завернуть только первый вызов, то позднее
`verifyNative` догрузит стоковую `libkolson.so`, её `JNI_OnLoad` заново
зарегистрирует нативные методы поверх наших — защита вернётся.

## 2. Правка в smali

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

## 3. Правка dex без пересборки дерева

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

## 4. SONAME: когда нужен `-n`

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

## 5. Куда положить файл на устройстве

| путь | кто пускает | комментарий |
|---|---|---|
| `lib/arm64-v8a/libklnc.so` в APK | всегда | приоритет, `System.loadLibrary("klnc")` |
| `/data/data/<pkg>/files/libklnc.so` | `permitted_paths` содержит `/data` | если файл кладёт сам код |
| `/data/local/tmp/libklnc.so` | namespace пускает (`/data`) | на retail-устройствах SELinux обычно режет `exec` из `shell_data_file` — только root/эмулятор |

## 6. Проверка

```bash
python3 check_smali.py NativeLoader.smali     # 0 error(s), 0 warning(s)
```

Проверяются опкоды/форматы, диапазоны `vN`/`pN`, соответствие `.registers`
числу параметров, парность меток и `.catch`, дубли `.method`.
