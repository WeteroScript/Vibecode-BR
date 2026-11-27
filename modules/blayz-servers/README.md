# libblayzservers.so (v2)

Отдельная нативная библиотека-модуль лаунчера. **Никак не связана с `libkolson.so`**:
другой код, другие символы, ноль зависимостей. Задача одна — чтобы в списке серверов
лаунчера появились сервера из внешнего JSON.

* файл: `libblayzservers.so`
* размер: **15 232 байта**
* sha256: **`ecce269bf8d033ba8837e319826231247f4d497be99f46b1460f5155ac2af3f1`**
* ELF64 AArch64, `DYN`, `SONAME=libblayzservers.so`
* `DT_NEEDED`: **0**, релокаций: **0**, неразрешённых символов: **0**
* экспортируется только `JNI_OnLoad`

## Что изменилось в v2 (почему в v1 «нету серверов»)

Причина найдена дизасмом `classes8.dex`, а не догадками.

`CustomServerConfigImporter.importIfExist(Context)` (вызывается из
`GameStarter.startLocked` сразу **после** `ServersJsonSync.sync`) делает так:

```
/storage/emulated/0/1NEIZZIR/servers/servers.json   (Custom/modules)
        │  readBytes + isValidServerList(bytes)
        ▼
<app files>/NEIZZIR/servers.json                    (то, что читает лаунчер)
```

`isValidServerList(byte[])` принимает файл **только** если:

1. корень — **JSON-массив** (не объект) и он непустой;
2. каждый элемент — объект;
3. `id` (после `trim`) — **непустое**;
4. `ip` либо `address` (после `trim`) — непустое;
5. `port` — число в диапазоне **1..65536**.

В `servers-2.json` с Dropbox поля `id` **нет вообще** (там `key/name/firstname/ip/port`),
поэтому каждая запись невалидна → в лог уходит
`Ignored invalid custom servers.json at …`, файл не копируется, серверов нет.

В v1 библиотека просто сохраняла скачанный JSON как есть. В v2 она **пересобирает**
записи в схему официального `https://cdn.kolson.online/servers.json`:

```json
{ "ip": "...", "serverId": "blayz_900", "minimumBuildId": 2026080501,
  "expiresAt": 1817337600, "featureMask": 1, "port": "7010",
  "onlineMin": "…", "onlineMax": "…", "color": "…", "password": false,
  "mapX": 72.73, "mapY": 408.9, "id": "900", "name": "…", "description": "…",
  "label": "…", "address": "...", "iconId": 900, "lastCheck": "", "lastOnline": "…" }
```

* `minimumBuildId` / `expiresAt` — ровно те значения, что сейчас отдаёт официальный CDN
  (2026080501 / 1817337600), чтобы запись не отсекалась гейтом по сборке и сроку;
* `id` и `iconId` — 900, 901, 902… (уникальные, числовые);
* `name`/`label`/`description` — `name`, иначе `firstname` из исходного файла;
* записи без `ip` или с `port` вне 1..65536 отбрасываются;
* неэкранированные «мусорные» escape-последовательности (вида `\|`) вычищаются,
  кавычки и обратные слэши экранируются корректно — JSON гарантированно парсится.

## Куда пишет

Один и тот же валидный JSON кладётся сразу в два места:

| путь | зачем |
|---|---|
| `/storage/emulated/0/1NEIZZIR/servers/servers.json` | источник для штатного импорта лаунчера |
| `/data/user/0/<пакет>/files/NEIZZIR/servers.json` | тот файл, который читает UI — появляется сразу, без ожидания импорта |

`<пакет>` библиотека узнаёт сама из `/proc/self/cmdline` — ничего не захардкожено под
конкретную сборку APK.

Отчёт для проверки без logcat:

```
/storage/emulated/0/1NEIZZIR/servers/_blayz_fetch.txt
    ok entries=35 bytes=9123
    ext=1 int=1
    pkg=com.blackhub.bronline
    file=/data/user/0/com.blackhub.bronline/files/NEIZZIR/servers.json
```

Если сеть/URL подвели — `error code=-N` (коды: −1…−8 классы/методы JNI, −9 исключение
чтения, −10 ответ больше 256 КБ, −11 ответ пустой, −1xx данные не разобрались).

## Установка

```sh
mkdir -p /storage/emulated/0/1NEIZZIR/Modules
cp libblayzservers.so /storage/emulated/0/1NEIZZIR/Modules/
```

Перезапустить лаунчер (полностью, из «недавних» тоже убрать).

## Как проверить

```sh
cat /storage/emulated/0/1NEIZZIR/servers/_blayz_fetch.txt
head -c 400 /storage/emulated/0/1NEIZZIR/servers/servers.json
```

Ожидаемо в списке серверов лаунчера: `TEST_P1_PROD`, `TEST_P2_PROD`, `YouTube`,
`Test Server-Core`, `Stage229`, `NEIZZIR DM` и остальные из Dropbox-файла.

## Сборка

```sh
zig cc -target aarch64-linux-android -shared -nostdlib -O2 -g0 \
  -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-stack-protector \
  -fno-builtin -fPIC -fvisibility=hidden -s \
  -Wl,-soname,libblayzservers.so -Wl,-z,max-page-size=16384 \
  -o libblayzservers.so blayz_servers.c
```

Исходник: `blayz_servers.c` (в этом же каталоге). Сеть — только `java.net.URL.openStream`
и `java.io.InputStream.read`, файлы — `java.io.File`/`FileWriter`; своего TLS и libc нет.
