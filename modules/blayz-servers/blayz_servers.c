/*
 * libblayzservers.so - отдельная библиотека, никак не связанная с libkolson.
 *
 * Что делает при загрузке в процесс лаунчера:
 *   1) скачивает список серверов по URL (Java: java.net.URL.openStream);
 *   2) ПЕРЕСОБИРАЕТ его в формат, который лаунчер реально принимает;
 *   3) пишет результат в два места:
 *        /storage/emulated/0/1NEIZZIR/servers/servers.json   (импорт лаунчера)
 *        <app files>/NEIZZIR/servers.json                    (тот файл, что читает UI)
 *   4) пишет отчёт /storage/emulated/0/1NEIZZIR/servers/_blayz_fetch.txt
 *
 * Почему нужна пересборка формата (проверено дизасмом classes8.dex):
 *   CustomServerConfigImporter.importIfExist(Context) копирует
 *     <ext>/1NEIZZIR/servers/servers.json -> <files>/NEIZZIR/servers.json
 *   только если CustomServerConfigImporter.isValidServerList(byte[]) == true, а он требует:
 *     - корень = JSON-МАССИВ, непустой;
 *     - каждый элемент - объект;
 *     - "id" (trim) непустое;
 *     - "ip" (или "address") непустое;
 *     - "port" число 1..65536.
 *   В servers-2.json с Dropbox поля "id" нет вообще, поэтому ЛЮБАЯ запись невалидна,
 *   файл игнорируется ("Ignored invalid custom servers.json at ...") и серверов нет.
 *   Поэтому библиотека сама строит записи в схеме официального
 *   cdn.kolson.online/servers.json: ip, serverId, minimumBuildId, expiresAt,
 *   featureMask, port, onlineMin, onlineMax, color, password, mapX, mapY, id,
 *   name, description, label, address, iconId, lastCheck, lastOnline.
 *
 * Собрано freestanding (без libc): все внешние вызовы идут через JNI-таблицу,
 * поэтому у .so нет ни DT_NEEDED, ни неразрешённых символов.
 */

typedef unsigned long size_t;
typedef int jint;

#define JNI_OK          0
#define JNI_VERSION_1_6 0x00010006

/* ------------------------------------------------------------------ */
/* JNI: обращение к таблице функций по индексам из jni.h               */
/* ------------------------------------------------------------------ */
enum {
    J_FindClass             = 6,
    J_ExceptionClear        = 17,
    J_NewObject             = 28,
    J_GetMethodID           = 33,
    J_CallObjectMethod      = 34,
    J_CallBooleanMethod     = 37,
    J_CallIntMethod         = 49,
    J_CallVoidMethod        = 61,
    J_NewStringUTF          = 167,
    J_GetStringUTFChars     = 169,
    J_ReleaseStringUTFChars = 170,
    J_ExceptionCheck        = 228
};

static void *jfn(void *env, int idx)
{
    return (*((void ***)env))[idx];
}

static int pending(void *env)
{
    int (*check)(void *) = (int (*)(void *))jfn(env, J_ExceptionCheck);
    return check(env) ? 1 : 0;
}

static void clear(void *env)
{
    void (*clr)(void *) = (void (*)(void *))jfn(env, J_ExceptionClear);
    clr(env);
}

static void *find_class(void *env, const char *name)
{
    void *(*f)(void *, const char *) = (void *(*)(void *, const char *))jfn(env, J_FindClass);
    void *c = f(env, name);
    if (pending(env)) { clear(env); return 0; }
    return c;
}

static void *get_method(void *env, void *cls, const char *name, const char *sig)
{
    void *(*f)(void *, void *, const char *, const char *) =
        (void *(*)(void *, void *, const char *, const char *))jfn(env, J_GetMethodID);
    void *m = f(env, cls, name, sig);
    if (pending(env)) { clear(env); return 0; }
    return m;
}

static void *new_object(void *env, void *cls, void *ctor, void *arg)
{
    void *(*f)(void *, void *, void *, void *) =
        (void *(*)(void *, void *, void *, void *))jfn(env, J_NewObject);
    void *o = f(env, cls, ctor, arg);
    if (pending(env)) { clear(env); return 0; }
    return o;
}

static void *call_obj(void *env, void *obj, void *mid, void *arg)
{
    void *(*f)(void *, void *, void *, void *) =
        (void *(*)(void *, void *, void *, void *))jfn(env, J_CallObjectMethod);
    void *o = f(env, obj, mid, arg);
    if (pending(env)) { clear(env); return 0; }
    return o;
}

static int call_int(void *env, void *obj, void *mid)
{
    jint (*f)(void *, void *, void *) = (jint (*)(void *, void *, void *))jfn(env, J_CallIntMethod);
    jint v = f(env, obj, mid);
    if (pending(env)) { clear(env); return -2; }
    return v;
}

static void call_void1(void *env, void *obj, void *mid)
{
    void (*f)(void *, void *, void *) = (void (*)(void *, void *, void *))jfn(env, J_CallVoidMethod);
    f(env, obj, mid);
    if (pending(env)) clear(env);
}

static void call_void2(void *env, void *obj, void *mid, void *arg)
{
    void (*f)(void *, void *, void *, void *) =
        (void (*)(void *, void *, void *, void *))jfn(env, J_CallVoidMethod);
    f(env, obj, mid, arg);
    if (pending(env)) clear(env);
}

static void *new_string(void *env, const char *s)
{
    void *(*f)(void *, const char *) = (void *(*)(void *, const char *))jfn(env, J_NewStringUTF);
    void *o = f(env, s);
    if (pending(env)) { clear(env); return 0; }
    return o;
}

static void ensure_dir_java(void *env, const char *path)
{
    void *cFile = find_class(env, "java/io/File");
    if (!cFile) return;
    void *fileCtor = get_method(env, cFile, "<init>", "(Ljava/lang/String;)V");
    void *mkdirs = get_method(env, cFile, "mkdirs", "()Z");
    if (!fileCtor || !mkdirs) return;
    void *sDir = new_string(env, path);
    if (!sDir) return;
    void *dir = new_object(env, cFile, fileCtor, sDir);
    if (!dir) return;
    int (*callBool)(void *, void *, void *) = (int (*)(void *, void *, void *))jfn(env, J_CallBooleanMethod);
    callBool(env, dir, mkdirs);
    if (pending(env)) clear(env);
}

/* запись строки в файл: 1 = успех */
static int write_text(void *env, const char *path, void *str_obj)
{
    void *cFW = find_class(env, "java/io/FileWriter");
    if (!cFW) return 0;
    void *fwCtor = get_method(env, cFW, "<init>", "(Ljava/lang/String;)V");
    void *writeS = get_method(env, cFW, "write", "(Ljava/lang/String;)V");
    void *flushM = get_method(env, cFW, "flush", "()V");
    void *closeM = get_method(env, cFW, "close", "()V");
    if (!fwCtor || !writeS) return 0;
    void *sPath = new_string(env, path);
    if (!sPath) return 0;
    void *fw = new_object(env, cFW, fwCtor, sPath);
    if (!fw) return 0;
    call_void2(env, fw, writeS, str_obj);
    if (flushM) call_void1(env, fw, flushM);
    if (closeM) call_void1(env, fw, closeM);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Параметры                                                           */
/* ------------------------------------------------------------------ */
#define SERVER_URL                                                              \
    "https://www.dropbox.com/scl/fi/cbse6hrwe6308xbbu5new/servers-2.json"       \
    "?rlkey=b1yw3qtal3xg3ppcmndziz83q&st=u5zhl7bl&dl=1"

#define EXT_DIR   "/storage/emulated/0/1NEIZZIR/servers"
#define EXT_FILE  "/storage/emulated/0/1NEIZZIR/servers/servers.json"
#define STATUS    "/storage/emulated/0/1NEIZZIR/servers/_blayz_fetch.txt"

#define IN_MAX    262144
#define OUT_MAX   1048576
#define URL_MAX   768

/* те же значения, что в официальном cdn.kolson.online/servers.json */
#define MIN_BUILD "2026080501"
#define EXPIRES   "1817337600"

static char inbuf[IN_MAX];
static char outbuf[OUT_MAX];
static char pkgbuf[160];
static char path_dir[URL_MAX];
static char path_file[URL_MAX];
static char statusbuf[512];

/* ------------------------------------------------------------------ */
/* Примитивная строковая арифметика (libc нет)                         */
/* ------------------------------------------------------------------ */
static int slen(const char *s)
{
    int n = 0;
    while (s[n]) n++;
    return n;
}

static void scpy(char *d, const char *s, int cap)
{
    int i = 0;
    if (cap <= 0) return;
    while (s[i] && i < cap - 1) { d[i] = s[i]; i++; }
    d[i] = 0;
}

static int app(char *d, int *pos, int cap, const char *s)
{
    int i = 0;
    while (s[i]) {
        if (*pos >= cap - 1) return 0;
        d[(*pos)++] = s[i++];
    }
    d[*pos] = 0;
    return 1;
}

static int app_int(char *d, int *pos, int cap, int v)
{
    char t[16];
    int k = 0, neg = 0;
    if (v < 0) { neg = 1; v = -v; }
    if (v == 0) t[k++] = '0';
    while (v > 0 && k < 15) { t[k++] = (char)('0' + (v % 10)); v /= 10; }
    if (neg && *pos < cap - 1) d[(*pos)++] = '-';
    while (k > 0) {
        if (*pos >= cap - 1) return 0;
        d[(*pos)++] = t[--k];
    }
    d[*pos] = 0;
    return 1;
}

/* вывод значения с корректным JSON-экранированием */
static int app_esc(char *d, int *pos, int cap, const char *s)
{
    for (int i = 0; s[i]; i++) {
        char c = s[i];
        if (c == '"' || c == '\\') {
            if (*pos >= cap - 2) return 0;
            d[(*pos)++] = '\\';
            d[(*pos)++] = c;
        } else if ((unsigned char)c < 0x20) {
            continue;
        } else {
            if (*pos >= cap - 1) return 0;
            d[(*pos)++] = c;
        }
    }
    d[*pos] = 0;
    return 1;
}

static int is_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static int to_int(const char *s)
{
    int v = 0, i = 0, neg = 0;
    if (s[0] == '-') { neg = 1; i = 1; }
    if (!s[i]) return -1;
    for (; s[i]; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = v * 10 + (s[i] - '0');
        if (v > 100000000) return -1;
    }
    return neg ? -v : v;
}

/* ------------------------------------------------------------------ */
/* Мини-разбор JSON (нужен только один уровень вложенности)            */
/* ------------------------------------------------------------------ */
static int lit_end(const char *s, int n, int i)   /* i стоит на '"' ; вернуть индекс за закрывающей */
{
    i++;
    while (i < n) {
        if (s[i] == '\\') { i += 2; continue; }
        if (s[i] == '"') return i + 1;
        i++;
    }
    return -1;
}

static int skip_ws(const char *s, int n, int i)
{
    while (i < n && is_ws(s[i])) i++;
    return i;
}

/* копирование содержимого строки с нормализацией экранирования */
static void copy_esc(const char *s, int from, int to, char *dst, int cap)
{
    int i = from, k = 0;
    while (i < to && k < cap - 1) {
        char c = s[i];
        if (c == '\\' && i + 1 < to) {
            char e = s[i + 1];
            if (e == '"' || e == '\\' || e == '/') { dst[k++] = e; i += 2; continue; }
            if (e == 'n' || e == 'r' || e == 't') { dst[k++] = ' '; i += 2; continue; }
            if (e == 'u') { i += 2; while (i < to && ((s[i] >= '0' && s[i] <= '9') ||
                             (s[i] >= 'a' && s[i] <= 'f') || (s[i] >= 'A' && s[i] <= 'F'))) i++; continue; }
            dst[k++] = e; i += 2;          /* неизвестный escape (например \|) - просто снимаем */
            continue;
        }
        if ((unsigned char)c < 0x20) { i++; continue; }
        dst[k++] = c;
        i++;
    }
    dst[k] = 0;
}

/* значение поля key внутри объекта [ob, oe); 1 = найдено */
static int field(const char *s, int ob, int oe, const char *key, char *dst, int cap)
{
    int klen = slen(key), i = ob;
    dst[0] = 0;
    while (i < oe) {
        if (s[i] != '"') { i++; continue; }
        int e = lit_end(s, oe, i);
        if (e < 0) return 0;
        int match = (e - 1 - (i + 1) == klen);
        for (int m = 0; m < klen && match; m++)
            if (s[i + 1 + m] != key[m]) match = 0;
        int j = skip_ws(s, oe, e);
        if (j < oe && s[j] == ':') {
            j = skip_ws(s, oe, j + 1);
            if (match) {
                if (j < oe && s[j] == '"') {
                    int ve = lit_end(s, oe, j);
                    if (ve < 0) return 0;
                    copy_esc(s, j + 1, ve - 1, dst, cap);
                    return 1;
                }
                int k = j;
                while (k < oe && s[k] != ',' && s[k] != '}') k++;
                copy_esc(s, j, k, dst, cap);
                int c = slen(dst);
                while (c > 0 && is_ws(dst[c - 1])) dst[--c] = 0;
                return 1;
            }
            i = j;
            continue;
        }
        i = e;
    }
    return 0;
}

/* следующий объект верхнего уровня: *ob = '{', *oe = '}' */
static int next_object(const char *s, int n, int from, int *ob, int *oe)
{
    int depth = 0, i = from, start = -1;
    while (i < n) {
        char c = s[i];
        if (c == '"') { int e = lit_end(s, n, i); if (e < 0) return 0; i = e; continue; }
        if (c == '{') { if (depth == 0) start = i; depth++; i++; continue; }
        if (c == '}') {
            depth--;
            if (depth == 0 && start >= 0) { *ob = start; *oe = i; return 1; }
            if (depth < 0) return 0;
            i++;
            continue;
        }
        i++;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Пересборка списка в формат лаунчера; возвращает число записей       */
/* ------------------------------------------------------------------ */
static int transform(const char *s, int n, char *o, int cap)
{
    int pos = 0, count = 0, i, ob, oe;
    int root = -1;
    for (int k = 0; k < n; k++) {
        if (!is_ws(s[k])) { root = k; break; }
    }
    if (root < 0) return -1;
    if (s[root] != '[') {
        int k = root;
        while (k < n && s[k] != '[') k++;
        if (k >= n) return -1;
        root = k;
    }
    if (!app(o, &pos, cap, "[\n")) return -2;

    i = root + 1;
    while (next_object(s, n, i, &ob, &oe)) {
        char ip[64], addr[64], port[16], name[96], fname[96];
        char online[16], maxon[16], color[16], title[96];
        i = oe + 1;

        ip[0] = addr[0] = port[0] = name[0] = fname[0] = 0;
        online[0] = maxon[0] = color[0] = 0;

        field(s, ob, oe, "ip", ip, sizeof ip);
        field(s, ob, oe, "address", addr, sizeof addr);
        field(s, ob, oe, "port", port, sizeof port);
        field(s, ob, oe, "name", name, sizeof name);
        field(s, ob, oe, "firstname", fname, sizeof fname);
        field(s, ob, oe, "online", online, sizeof online);
        field(s, ob, oe, "maxonline", maxon, sizeof maxon);
        field(s, ob, oe, "color", color, sizeof color);

        if (!ip[0]) scpy(ip, addr, sizeof ip);
        int pv = to_int(port);
        if (!ip[0] || pv < 1 || pv > 65536) continue;      /* лаунчер такие всё равно отбросит */

        if (name[0]) scpy(title, name, sizeof title);
        else if (fname[0]) scpy(title, fname, sizeof title);
        else scpy(title, ip, sizeof title);
        if (!online[0]) scpy(online, "0", sizeof online);
        if (!maxon[0]) scpy(maxon, "1300", sizeof maxon);
        if (!color[0]) scpy(color, "00FF00", sizeof color);

        int id = 900 + count;

        if (count && !app(o, &pos, cap, ",\n")) return -2;
        app(o, &pos, cap, "  {\n    \"ip\": \"");
        app_esc(o, &pos, cap, ip);
        app(o, &pos, cap, "\",\n    \"serverId\": \"blayz_");
        app_int(o, &pos, cap, id);
        app(o, &pos, cap, "\",\n    \"minimumBuildId\": " MIN_BUILD
                          ",\n    \"expiresAt\": " EXPIRES
                          ",\n    \"featureMask\": 1,\n    \"port\": \"");
        app_esc(o, &pos, cap, port);
        app(o, &pos, cap, "\",\n    \"onlineMin\": \"");
        app_esc(o, &pos, cap, online);
        app(o, &pos, cap, "\",\n    \"onlineMax\": \"");
        app_esc(o, &pos, cap, maxon);
        app(o, &pos, cap, "\",\n    \"color\": \"");
        app_esc(o, &pos, cap, color);
        app(o, &pos, cap, "\",\n    \"password\": false,\n    \"mapX\": 72.73,\n    \"mapY\": 408.9,"
                          "\n    \"id\": \"");
        app_int(o, &pos, cap, id);
        app(o, &pos, cap, "\",\n    \"name\": \"");
        app_esc(o, &pos, cap, title);
        app(o, &pos, cap, "\",\n    \"description\": \"");
        app_esc(o, &pos, cap, title);
        app(o, &pos, cap, "\",\n    \"label\": \"");
        app_esc(o, &pos, cap, title);
        app(o, &pos, cap, "\",\n    \"address\": \"");
        app_esc(o, &pos, cap, ip);
        app(o, &pos, cap, "\",\n    \"iconId\": ");
        app_int(o, &pos, cap, id);
        app(o, &pos, cap, ",\n    \"lastCheck\": \"\",\n    \"lastOnline\": \"");
        app_esc(o, &pos, cap, online);
        app(o, &pos, cap, "\"\n  }");
        if (pos >= cap - 8) return -3;
        count++;
    }
    if (!app(o, &pos, cap, "\n]\n")) return -2;
    return count;
}

/* ------------------------------------------------------------------ */
/* Сеть: URL.openStream + побайтовое чтение прямо в inbuf              */
/* ------------------------------------------------------------------ */
static int download(void *env, char *dst, int cap)
{
    void *cURL = find_class(env, "java/net/URL");
    if (!cURL) return -1;
    void *urlCtor = get_method(env, cURL, "<init>", "(Ljava/lang/String;)V");
    void *openStream = get_method(env, cURL, "openStream", "()Ljava/io/InputStream;");
    if (!urlCtor || !openStream) return -2;
    void *sUrl = new_string(env, SERVER_URL);
    if (!sUrl) return -3;
    void *url = new_object(env, cURL, urlCtor, sUrl);
    if (!url) return -4;
    void *in = call_obj(env, url, openStream, 0);
    if (!in) return -5;

    void *cIS = find_class(env, "java/io/InputStream");
    if (!cIS) return -6;
    void *readI = get_method(env, cIS, "read", "()I");
    void *closeM = get_method(env, cIS, "close", "()V");
    if (!readI) return -7;

    int k = 0;
    for (;;) {
        int b = call_int(env, in, readI);
        if (b == -2) { if (closeM) call_void1(env, in, closeM); return -9; }
        if (b < 0) break;
        if (k < cap - 1) dst[k++] = (char)b;
        else { if (closeM) call_void1(env, in, closeM); return -10; }
    }
    dst[k] = 0;
    if (closeM) call_void1(env, in, closeM);
    if (k < 16) return -11;
    return k;
}

/* ------------------------------------------------------------------ */
/* Имя пакета (нужно, чтобы попасть в «внутренний» файл лаунчера)      */
/* ------------------------------------------------------------------ */
static int read_pkg(void *env, char *dst, int cap)
{
    void *cFIS = find_class(env, "java/io/FileInputStream");
    void *cIS = find_class(env, "java/io/InputStream");
    if (!cFIS || !cIS) return 0;
    void *ctor = get_method(env, cFIS, "<init>", "(Ljava/lang/String;)V");
    void *readI = get_method(env, cIS, "read", "()I");
    void *closeM = get_method(env, cIS, "close", "()V");
    if (!ctor || !readI) return 0;
    void *sPath = new_string(env, "/proc/self/cmdline");
    if (!sPath) return 0;
    void *in = new_object(env, cFIS, ctor, sPath);
    if (!in) return 0;
    int k = 0;
    for (;;) {
        int b = call_int(env, in, readI);
        if (b <= 0) break;
        if (k < cap - 1) dst[k++] = (char)b;
    }
    dst[k] = 0;
    if (closeM) call_void1(env, in, closeM);
    for (int i = 0; i < k; i++) if (dst[i] == ':' || dst[i] == '/') { dst[i] = 0; break; }
    return k > 0;
}

/* ------------------------------------------------------------------ */
/* Установка                                                           */
/* ------------------------------------------------------------------ */
static int install(void *env)
{
    int n = download(env, inbuf, IN_MAX);
    int code = n;
    int entries = 0, ext_ok = 0, int_ok = 0, pkg_ok = 0;

    if (n > 0) {
        entries = transform(inbuf, n, outbuf, OUT_MAX);
        if (entries > 0) {
            void *body = new_string(env, outbuf);
            if (body) {
                ensure_dir_java(env, EXT_DIR);
                ext_ok = write_text(env, EXT_FILE, body);

                pkg_ok = read_pkg(env, pkgbuf, sizeof pkgbuf);
                if (pkg_ok) {
                    path_dir[0] = 0;
                    path_file[0] = 0;
                    int p = 0;
                    app(path_dir, &p, sizeof path_dir, "/data/user/0/");
                    app(path_dir, &p, sizeof path_dir, pkgbuf);
                    app(path_dir, &p, sizeof path_dir, "/files/NEIZZIR");
                    int q = 0;
                    app(path_file, &q, sizeof path_file, "/data/user/0/");
                    app(path_file, &q, sizeof path_file, pkgbuf);
                    app(path_file, &q, sizeof path_file, "/files/NEIZZIR/servers.json");
                    ensure_dir_java(env, path_dir);
                    int_ok = write_text(env, path_file, body);
                }
            }
        } else {
            code = entries * 100;            /* -1xx: данные не разобрались */
        }
    }

    /* отчёт, чтобы всё было видно без logcat */
    {
        int p = 0;
        statusbuf[0] = 0;
        if (entries > 0) {
            app(statusbuf, &p, sizeof statusbuf, "ok entries=");
            app_int(statusbuf, &p, sizeof statusbuf, entries);
            app(statusbuf, &p, sizeof statusbuf, " bytes=");
            app_int(statusbuf, &p, sizeof statusbuf, n);
            app(statusbuf, &p, sizeof statusbuf, "\next=");
            app_int(statusbuf, &p, sizeof statusbuf, ext_ok);
            app(statusbuf, &p, sizeof statusbuf, " int=");
            app_int(statusbuf, &p, sizeof statusbuf, int_ok);
        } else {
            app(statusbuf, &p, sizeof statusbuf, "error code=");
            app_int(statusbuf, &p, sizeof statusbuf, code);
        }
        app(statusbuf, &p, sizeof statusbuf, "\npkg=");
        if (pkg_ok) app(statusbuf, &p, sizeof statusbuf, pkgbuf);
        else app(statusbuf, &p, sizeof statusbuf, "?");
        app(statusbuf, &p, sizeof statusbuf, "\nfile=");
        app(statusbuf, &p, sizeof statusbuf, path_file);
        app(statusbuf, &p, sizeof statusbuf, "\n");
        void *sMsg = new_string(env, statusbuf);
        if (sMsg) {
            ensure_dir_java(env, EXT_DIR);
            write_text(env, STATUS, sMsg);
        }
    }
    return entries > 0 ? entries : code;
}

/* ------------------------------------------------------------------ */
/* Точка входа                                                         */
/* ------------------------------------------------------------------ */
__attribute__((visibility("default")))
jint JNI_OnLoad(void *vm, void *reserved)
{
    (void)reserved;
    void *env = 0;
    jint (*getEnv)(void *, void **, jint) =
        (jint (*)(void *, void **, jint))(*((void ***)vm))[6];   /* JavaVM: GetEnv = 6 */
    if (getEnv(vm, &env, JNI_VERSION_1_6) != 0 || !env)
        return JNI_VERSION_1_6;

    install(env);
    return JNI_VERSION_1_6;
}

/* freestanding: на случай, если компилятор всё же вставит вызовы */
__attribute__((used)) void *memset(void *s, int c, size_t n)
{
    unsigned char *p = (unsigned char *)s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}

__attribute__((used)) void *memcpy(void *d, const void *s, size_t n)
{
    unsigned char *a = (unsigned char *)d;
    const unsigned char *b = (const unsigned char *)s;
    while (n--) *a++ = *b++;
    return d;
}
