# libblayzservers.so — отдельная библиотека загрузки серверов

Не связана с `libkolson`: ни одного байта её кода, ни патчей, ни хуков, ни smali.
Задача одна — при загрузке в процесс лаунчера скачать JSON со списком серверов
по ссылке и положить его в файл, который читает сам лаунчер.

**URL по умолчанию:**

```
https://www.dropbox.com/scl/fi/cbse6hrwe6308xbbu5new/servers-2.json?rlkey=b1yw3qtal3xg3ppcmndziz83q&st=u5zhl7bl&dl=1
```

**Что и куда пишет:**

| файл | что |
|---|---|
| `/storage/emulated/0/1NEIZZIR/servers/servers.json` | скачанный JSON (как есть) |
| `/storage/emulated/0/1NEIZZIR/servers/_blayz_fetch.txt` | отчёт: `ok bytes=N` или `error code=-N` |

Файлы, пути и формат взяты из самого лаунчера (`com.blackhub.bronline.neizzir`):
в `classes8.dex` есть строки `1NEIZZIR/servers/servers.json`,
`Copied custom servers.json to `, `Ignored invalid custom servers.json at `,
`CDN returned an invalid servers.json; keeping the last valid local file`.
То есть лаунчер уже умеет жить с локальным `servers.json`.

## Установка

```sh
mkdir -p /storage/emulated/0/1NEIZZIR/Modules
cp libblayzservers.so /storage/emulated/0/1NEIZZIR/Modules/
```

Лаунчер сам обходит `1NEIZZIR/Modules` (`NativeLibraryLoader.load`, логи
`loadLibrary:begin / ok elapsedMs= / failed`) и грузит найденные `.so` через
`System.load*`, поэтому вызывается `JNI_OnLoad` — вся работа происходит там.

## Как проверить, что сработало

```sh
cat /storage/emulated/0/1NEIZZIR/servers/_blayz_fetch.txt
head -c 200 /storage/emulated/0/1NEIZZIR/servers/servers.json
```

* `ok bytes=NNNN` — файл скачан и записан;
* `error code=-N` — расшифровка кодов в `blayz_servers.c`:
  `-5` openStream (нет сети/URL), `-9` исключение при чтении,
  `-11` пустой ответ, `-15` нет UTF-8 строки, `-17` не удалось записать файл
  (нет доступа к `/storage/emulated/0/1NEIZZIR/servers`).

## Технически

* ELF64 AArch64, `DT_SONAME=libblayzservers.so`, **нет** `DT_NEEDED`,
  **нет** перемещений и неразрешённых символов — собрано freestanding;
* весь ввод-вывод и сеть — через JNI (`java.net.URL`, `java.io.*`), поэтому
  HTTPS, редирект Dropbox на `dl.dropboxusercontent.com` и проверка
  сертификатов работают штатно, своего TLS в библиотеке нет;
* индексы JNIEnv — стандартные из `jni.h`: `FindClass 6`, `NewObject 28`,
  `GetMethodID 33`, `CallObjectMethod 34`, `CallBooleanMethod 37`,
  `CallIntMethod 49`, `CallVoidMethod 61`, `NewStringUTF 167`,
  `GetStringUTFChars 169`, `ReleaseStringUTFChars 170`, `ExceptionClear 17`,
  `ExceptionCheck 228`;
* любое исключение Java перехватывается (`ExceptionCheck`/`ExceptionClear`) и
  превращается в код ошибки — падать библиотеке нечем;
* `JavaVM::GetEnv` — индекс 6.

## Сборка

```sh
ZIG=/path/to/zig
$ZIG cc -target aarch64-linux-android -shared -nostdlib -O2 \
    -fno-stack-protector -fno-builtin \
    -Wl,-soname,libblayzservers.so -o libblayzservers.so blayz_servers.c
```

Свой URL можно подставить на этапе сборки: `-DSERVER_URL='"https://..."'`
(в коде есть `#ifndef SERVER_URL`).

## Чего эта библиотека не делает

* не патчит `libkolson.so` и не грузит её;
* не трогает APK/dex;
* не обходит проверки лаунчера. Если лаунчер при старте успевает скачать
  официальный `servers.json` с CDN **после** загрузки модулей, он перезапишет
  файл — тогда в списке останутся официальные сервера, а `_blayz_fetch.txt`
  при этом будет `ok`. В этом случае нужен другой вектор (правка порядка
  загрузки/подмена источника в самом лаунчере), это отдельная задача.
