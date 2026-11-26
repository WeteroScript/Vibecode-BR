# Разбор `libkolson.so` + `classes8.dex` / `classes9.dex`

Сборка от 26.11.2026. Всё ниже — только статический анализ (readelf/objdump/strings/ручной парсинг DEX).
Ничего не запускалось, файлы не модифицировались.

Итог одним абзацем: это **не библиотека игры, а читерский лаунчер/меню «Kolson» (он же NEIZZIR)** для Black Russia
(`com.br.top`). Нативный `.so` — это нативная часть UI (ImGui + GLES-оверлей), редактор оружия/хитбоксов и
тренировка аима; DEX — Kotlin-лаунчер, который подменяет игровые ресурсы (скины, .bpc/texdb, weapon.json),
проверяет подписку по ключу и тянет всё с `cdn.kolson.online`. Никакого шифрованного пейлоада/пакера нет —
`.so` не упакован, строки открытые.

---

## 1. `libkolson.so` — общие характеристики

| Параметр | Значение |
|---|---|
| Формат | ELF64, little-endian, `ET_DYN`, **AArch64** (ARM64), только 64-бит |
| Размер / `.text` | 6 956 216 Б (6.63 МБ) / 4.88 МБ кода |
| SONAME | `libkolson.so` |
| Версионирование | `KOLSON_6` (`.gnu.version_d`) |
| Экспорт | **ровно 1 символ**: `JNI_OnLoad@@KOLSON_6` (0x29e3d0, 2424 Б) |
| Импорт | 251 символ, `BIND_NOW` + `FLAGS_1 NOW` (полный RELRO) |
| Сборка | NDK r25c, clang 14.0.7 (LLD 14.0.7), есть объекты от clang 7 и 8 → статически влинкованы сторонние либы |
| Зависимости | liblog, libz, libEGL, libGLESv2, libGLESv3, libOpenSLES, libm, libdl, libc |
| Build ID | `37577df9233de12d13be009dab48c71b3d15785f` |
| SHA-256 | `bcadf08208903253df399fbdf7d8b5841f8717155f21875512c4a02fb969a166` |

Целостность файла в порядке: секции на месте, `.init_array` (72 записи) обнулён в файле и заполняется
релокациями (`RELACOUNT 3115`) — это штатное поведение, а не «подчистка». Энтропия `.rodata` 7.38 высокая,
но это из-за огромных JSON/шрифтов внутри, а не из-за упаковки: в файле нет вложенных ELF/ZIP/GZIP.
Один экспорт + динамическая регистрация методов (`RegisterNatives`, в строках видны сигнатуры `()V`, `([BJ)Z`)
— то есть имена JNI-функций (`nativeDecide`, `nativePrepare`, `nativeSnapshot`, `nativeValidate`, `nativeStatus`,
`nativeGameFocus`, `nativeCancel`, `nativeSubmit`, `nativeReady`, `nativeReserve`, `nativeText`, `nativeNumber`,
`nativeActivity`) намеренно не видны в таблице символов.

Ключевые импорты, по которым видно назначение: `pthread*`, `mmap`/`mprotect`, `dlopen`/`dlsym`/`dl_iterate_phdr`,
`syscall`, `sendto`/`recvfrom`, `inotify_*`, `inflate`/`deflate`/`crc32`, `getauxval`, `__system_property_get`,
полный набор GLES2 (шейдеры, буферы, текстуры) и `eglGetCurrentContext` — типичный инжект-оверлей в чужой GL-контекст.

Внутри статически влинкованы: **Dear ImGui 1.90.9** (`imgui_impl_opengl3`, `imgui.ini`, `imgui_log.txt`),
**libunwind** (`_Unwind_*`, `DW_EH_PE_*`), **nlohmann::json 3.11.3**, **Font Awesome 6.7.2** (иконки меню),
OpenGL-бэкенд для ImGui.

## 2. Что нативно реализовано (по внутренним namespace'ам)

Символов экспорта нет, но отладочные RTTI-имена раскрывают модули:

- `Sborks::` — система скинов/моделей: `Models::{Plan,Payload,TextureSet,CollisionRecord,MemoryLimit}`,
  `Animations::{Plan,Clip,Skeleton,Association}`, `Environment::Plan`, `Stock::CacheInventory`, `ChatFont::Plan`,
  `BankAudio` (свои звуки). Работает с архивами `.bpc` / `.astc.zip` / `.tmb`.
- `AimTrainDetail::{Plan,Spawn}` + `TrainingSession` — встроенный «аим-тренажёр» (спавн целей, сессии).
- `Hitbox::Shot` — хитбоксы и попадания (`hitbox-hits`, `hitbox-misses`, `hitbox.json`).
- `CustomMenu::Card/Preview`, `SkyBoxDetail::Image`, «NEIZZIR SkyBox» шейдеры — кастомное меню, превью, небо/погода.
- `WeaponAdmission::IsStock`, `read weapon.json: bytes=%zu stock=%d nativeStock=%d policy=%u` —
  проверка «стоковости» оружия и подмена `weapon.json` (урон, разброс, отдача).
- Хук-движок: `inline_install_failed`, `hook mprotect failed`, `fhook.ss01`, `loader hooks ready: pointerBits=…`,
  `login_hooks:ready`, `login_hooks:%s rva=%llx`, `CURRENT hooks ready (%zu-bit), guest home/picker and new/legacy Play installed`,
  `endpoint profile applied: protected=%d ok=%d generation=%llu`, чтение `/proc/self/maps`.
  То есть нативно патчатся `libblackrussia-client.so` (by RVA) и подменяются проверки логина/гостевого режима.
- Свои файлы: `/storage/emulated/0/Android/data/com.br.top/kolson_crash_last.txt` (крэш-лог),
  `NEIZZIR/DMNEIZZIR.bpc`, `NEIZZIR/custom_active.astc.zip`, `config/sborks-resources/state.json`, `data/texdb.dat`,
  `data/particle.cfg`, `/data/timecyc.json`.

## 3. `classes8.dex` — Kotlin-лаунчер «NEIZZIR» / BlackHub

- DEX 038, 3.54 МБ, **2105 классов**, checksum (adler32) и SHA-1 в заголовке **валидны** (не пересобраны «на глаз»).
- Пакет: `com.blackhub.bronline.neizzir` (крупнейшие группы: `activities/main/util` 253, `fragments/custom` ~600,
  `gui/editor` 125, `network` 65, `umbrella` 58, `fragments/sborks` 69).
- Наличие только `classes8/9` подтверждает, что это **патченный split** оригинального APK: `classes.dex…7` (в т.ч.
  игровые классы BR) в набор не входят, сверху докинут `classes9.dex`.

### 3.1 Инфраструктура и эндпоинты

```
https://cdn.kolson.online  |  https://cdnru.kolson.online
  /servers.json, /servers.json.sig, /version.txt, /update.apk
  /api/, /api/open/, /api/fetch_file/
  /api/skins   /api/models   /api/modules   /api/accessories   /api/gunpuck   /api/online
  /api/subscription/check        /api/umbrella/access      /api/umbrella/catalog
  /api/get_android_id_count      /api/track/banner
  /api/fetch_file/{models,modules,accessories}/…
https://dl.blackcdn.me/patch_index.json   |   https://rsv.br-dl.com/patch_index.json
http://85.193.87.60:5012  |  http://162.19.254.18:5012
ws://85.193.87.60:5012/fast/ws/notifications   (WebSocketService, heartbeat, reconnect)
ws://162.19.254.18:5012/fast/ws/notifications
t.me/MrKolson, t.me/umbrella_br, t.me/launcherkeys_bot, t.me/+xO9pZEWOLVcxYTky
```

### 3.2 Лицензирование / «ключи»

- `KeyManager` → `VerifyKeyRequest(android_id=…)`, `$apiKey`, `AuthProto`, `AUTH_PROTO`, `KolsonAuth`,
  результат `KeyManager$VerifyResult$Unauthorized`, UI — `KeyInputDialog`.
- `CustomAccess`, `UmbrellaManager.checkAccess`, `SubscriptionRequiredDialog`, `MenuFragment.showPremiumDialog`,
  `AccessoriesManager.checkSubscriptionAndMaybeShowPicker` — платный доступ к модулям через ключ/подписку.
- `DeviceInfoSender` (`DeviceInfoPayloadV2(android_id=…, device=…, device_name=…, device_supports_64bit=…)`,
  `readGetprop`, `getHwid`, `getFriendlyDeviceName`) шлёт на сервер `android_id`, `ro.*` пропсы и имя устройства;
  `android_id_count`, `android_id_mismatch`, `unknown_android_id` — учёт «шаринга» ключей по устройству.
- Aндроид-идентификатор + бетонная привязка к девайсу; **шифрования трафика нет** для WS (plain `ws://`),
  HTTPS — только на CDN-хостах. Ключи/HMAC-секреты в открытом виде не найдены (есть только AES/GCM-примитивы
  для ресурсов: `AES/GCM/NoPadding`, `GCMParameterSpec`, `KeyAgreement`, `HmacSHA256`, `decodeKtx1WithLegacyPath`).

### 3.3 Подмена игры (то, ради чего оно нужно)

- `WeaponEditorFragment` (+ `applyAntiSpreadStaticAimPreset`, `applyAntiReloadPreset`), `WeaponDatRepository`,
  `WeaponJsonRepository`, `WeaponFileSync`, `WeaponArchive`, `WeaponAdmission` — правка `weapon.json`/`weapon.dat`
  (урон, разброс, отдача, скорость перезарядки), с бэкапом и «resetToStock».
- `CommonBpcPatcher` (+ `xorFile`, `decryptOffsetPack`), `BtxPngConverter`, `BtxArchiveToolController`,
  `BpcMetaGenerator`, `GuiBpcRepository` — пересборка текстурных архивов `.bpc/.btx/.astc`.
- `ServerAntiCheatZipManager.apply` / `renameBySuffix` — переименование/подмена файлов, затрагивающих
  серверный античит BR (античит-зип игры). Отдельно: `CacheValidator`, `CachePolicy`, `StockCacheIdentity` (SHA-256),
  `SummerManager.updateTexDb`, `DmAnimationFiles.disable/restore`, `StanManager.md5` — правка `texdb.dat`,
  анимаций, звуков.
- `UmbrellaManager` / `UmbrellaPolicy` / `UmbrellaBuild` + `/libumbrella.so`, `/api/umbrella/access|catalog`,
  `UmbrellaRestartActivity`, `beforeGame`, `checkAccess` — отдельный загружаемый перед игрой нативный модуль
  с собственным платным доступом (судя по строкам — вторая ступень подгрузки функционала).
- `HitboxEditorFragment`, `AimTrainDetail`, `SkySettingsManager`, `NeizzirSborksFragment` (скины/модели),
  `AccessoriesManager`, `ModulesManager` (`download.so`), `NativeLibraryLoader` (грузит `.so` из `Custom/modules/`).
- `GuiEditorActivity`/`HudEditorActivity` — редактор HUD (нужен `SYSTEM_ALERT_WINDOW` / `canDrawOverlays`).

### 3.4 Самообновление и «приватность»

- `UpdateManager.checkForUpdate` → `/version.txt` + `expectedApkSha256`, скачивание `update.apk`, `installApk`
  (через `FileProvider`), зеркала `UpdateMirror` — обновление в обход Google Play.
- `InstallerManager`, `NeizzirInstaller.apk`, `Installer.apk` — установка сопроводительного APK.
- `BannerManager.sendTrack` → `/api/track/banner`, `trackOncePerCooldown`.
- `CrashHandler` → `kolson_crash_last.txt`, `FailureReporter`, `NativeRenderDispatcher`, `LogHelper.startFullLogging`.
- Проверки окружения: `Magisk` (`/data/adb/magisk`, `/system/app/Magisk.apk`, `com.topjohnwu.magisk`),
  `microvirtd`/`microvirt-prop`/`nemuVM-prop`/`libhoudini.so`/`libndk_translation.so`,
  `isProbablyEmulator`, `knownDesktopEmulator`, `/system/bin/su`, `/system/bin/which`.
- Разрешения, которые код ожидает от манифеста: `READ_/WRITE_EXTERNAL_STORAGE`; оверлей — `canDrawOverlays`.
  Опасных вещей вроде `Runtime.exec`/`ProcessBuilder`/`addJavascriptInterface` в DEX **нет** (строки `exec`
  относятся к `KolsonCustomBridge.execute` — это вызов команд внутри собственного JNI-моста, а не shell).

## 4. `classes9.dex`

127 КБ, 76 классов, целиком `org.java_websocket.*` (клиент + `permessage-deflate` + `server`). Добавлен
исключительно под `WebSocketService` из лаунчера (канал уведомлений/команд). Checksum и SHA-1 тоже валидны.

## 5. Оценка риска для пользователя

| Область | Наблюдение |
|---|---|
| Бан в игре | Прямое вмешательство в `libblackrussia-client.so` (RVA-хуки) + правка античит-файлов → гарантированный бан при детекте |
| Данные | `android_id` + список `ro.*` пропсов + модель устройства уходят на `cdn.kolson.online`; трекинг баннеров |
| Сеть | Уведомления по **незашифрованному** `ws://` на IP-адреса (85.193.87.60 / 162.19.254.18) — MITM/подмена команд тривиальны |
| Обновления | APK с `update.apk` на стороннем CDN, проверка только по SHA-256 из того же канала → полный контроль над устройством у владельца CDN |
| Приватность | Ключи/подписка привязаны к `android_id`; сервер считает «чужие» устройства (`android_id_count`) |

## 6. Технические «чистые» факты (если нужно для отчёта/детекта)

```
sha256:
  bcadf08208903253df399fbdf7d8b5841f8717155f21875512c4a02fb969a166  libkolson.so
  a5ec7aea2ae47c839a92b0b82a8ba9c87bfbb3d17f7de0cd6283d83b0282834f  classes8.dex
  fc5b469e8f0e10c113dff89c910d486e6380a8db99bf37b96edd95318d2ae70b  classes9.dex
build-id: 37577df9233de12d13be009dab48c71b3d15785f
versioned symbol: JNI_OnLoad@@KOLSON_6
строки-маркеры: "loader hooks ready", "login_hooks:ready", "KOLSON_SBORKS", "KOLSON_WEAPON", "KOLSON_BOOTSTRAP",
                "NEIZZIR/custom_active.astc.zip", "/storage/emulated/0/Android/data/com.br.top/kolson_crash_last.txt"
```

## 7. Что не проверено

- `classes.dex…7`, `AndroidManifest.xml`, `libblackrussia-client.so` и `libumbrella.so` в репозитории отсутствуют —
  полный список разрешений, подпись APK и точные хукаемые RVA подтвердить нельзя.
- Нативные хендлеры `native*` не дизассемблировались построчно (только строки/импорты/структура), так что
  конкретные смещения патчей в игровом клиенте не извлечены.
