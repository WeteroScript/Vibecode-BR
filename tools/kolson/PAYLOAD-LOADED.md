# Индикатор загрузки библиотеки («Library Loaded»)

Задача: при загрузке `libkolson.so` показать, что она вообще загрузилась.

## что уже сделано

При загрузке библиотеки вызывается `JNI_OnLoad` — его вход
(`0x3a8684`, `paciasp`) перекрыт переходом в **код-пещерить**
`0xa8f5c` (в `.text` там 1028 нулевых байт, ничего не использует):

```
0x3a8684  paciasp  ->  b 0xa8f5c          (слово 0x17f40236)

0xa8f5c  детур: сохраняет x0-x11 и x30, считает базу загрузки
         (adr - 0xa8f5c), зовёт пейлоад, восстанавливает всё,
         выполняет оригинальный paciasp и уходит на 0x3a8688 -
         дальше штатное тело JNI_OnLoad работает как обычно.
```

Пейлоад (952 байта из 1028) через JNI:

```
JavaVM->GetEnv(JNI 1.6)                       -> JNIEnv*
FindClass("android/app/ActivityThread")
GetStaticMethodID("currentApplication","()Landroid/app/Application;")
CallStaticObjectMethod                        -> Application
FindClass("android/widget/Toast")
GetStaticMethodID("makeText","(Landroid/content/Context;Ljava/lang/CharSequence;I)…")
NewStringUTF("KOLSON: Library Loaded")
CallStaticObjectMethod                        -> Toast
GetObjectClass + GetMethodID("show","()V") + CallVoidMethod
```

+ в конце снимается висящее JNI-исключение (`ExceptionCheck` →
`ExceptionClear`), чтобы `JNI_OnLoad` не вернулся с pending exception.

## что видно на устройстве

* всплывает тост **«KOLSON: Library Loaded»** — библиотека загрузилась;
* в logcat по тегу `KOLSON` (уровень I):
  * `payload: enter`
  * `payload: toast shown`
  * или `payload: ActivityThread not found` / `payload: no application`

Проверка: `logcat -s KOLSON` (или `adb logcat | grep KOLSON`).

## как пересобрать пейлоад

```sh
.venv-re/bin/python tools/kolson/payload/build.py    # нужен keystone-engine
make -s one-test                                     # runtime == offline
```

`build.py` ассемблирует код (keystone, AArch64), проверяет, что он влезает в
пещеру, и перезаписывает `tools/kolson/payload/hello_blob.h` (его и читают
оба патчера). Вручную в header ничего править не нужно.

Патч применяется как обычно:

```sh
./build/kolson_unlock -i libkolson.so -o libkolson.patched.so
```

Группа в таблице — `hello` (можно `--only hello`).

## следующий шаг: окно с зелёной кнопкой «Ok»

Сейчас индикатор — тост. Полноценное окно (`Library Loaded` + зелёная
`Ok`, которая его закрывает) требует `AlertDialog`:

```
ActivityThread.mActivities.valueAt(0).activity   -> Activity
AlertDialog.Builder(activity)
  .setTitle("Library Loaded")
  .setPositiveButton("Ok", null)
  .create().show()
getButton(BUTTON_POSITIVE).setBackgroundColor(0xFF43A047)
```

Всё это уже расписано в черновике `tools/kolson/payload/hello.c` (C, компилируется
`zig cc -target aarch64-freestanding`), но в 1028 байт пещеры он не влезает —
нужно либо ужимать ассемблер вручную, либо найти/освободить вторую пещеру.
Поэтому сначала проверяем, что JNI-путь вообще работает на устройстве
(тост), а затем меняем пейлоад на диалог.

## что именно отдаётся на выходе

Патчер делает **полную копию твоей библиотеки** того же размера и с тем же
`DT_SONAME` — это и есть готовый `libkolson.so` для замены файла:

```sh
./build/kolson_unlock -i libkolson.so -o libkolson.so.patched
```

* размер совпадает с оригиналом (8 609 952 Б) — меняются только 904 байта;
* soname не трогается (флаг `-n` нужен только для второй схемы, см. ниже);
* при замене файла в приложении ничего больше делать не нужно.

Вторая схема в репозитории — `libkolson_patch.so` (`kolson_one.c`): отдельная
маленькая библиотека, которая грузится в процесс и патчит уже отображённую
libkolson в памяти (файл на диске остаётся оригинальным, sha256 совпадает).
Она нужна только если заменить файл нельзя. Для задачи «одна библиотека,
готовый `libkolson.so`» используется первая схема.
