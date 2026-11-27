/*
 * libblayzservers.so - отдельная библиотека, никак не связанная с libkolson.
 *
 * Задача одна: при загрузке в процесс лаунчера скачать JSON со списком
 * серверов по URL и положить его в файл, который читает лаунчер:
 *
 *     /storage/emulated/0/1NEIZZIR/servers/servers.json
 *
 * Ни libkolson, ни APK не трогаются: ни патчей, ни хуков, ни smali.
 * Сеть и файлы - средствами Java (java.net.URL, java.io.FileWriter), поэтому
 * HTTPS, редиректы Dropbox и проверка сертификатов работают штатно; своего
 * TLS-кода и зависимостей у библиотеки нет.
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
    J_FindClass            = 6,
    J_ExceptionClear       = 17,
    J_NewObject            = 28,
    J_GetMethodID          = 33,
    J_CallObjectMethod     = 34,
    J_CallBooleanMethod    = 37,
    J_CallIntMethod        = 49,
    J_CallVoidMethod       = 61,
    J_NewStringUTF         = 167,
    J_GetStringUTFChars    = 169,
    J_ReleaseStringUTFChars= 170,
    J_ExceptionCheck       = 228
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

static void call_void2(void *env, void *obj, void *mid, void *arg)
{
    void (*f)(void *, void *, void *, void *) =
        (void (*)(void *, void *, void *, void *))jfn(env, J_CallVoidMethod);
    f(env, obj, mid, arg);
    if (pending(env)) clear(env);
}

static void call_void1(void *env, void *obj, void *mid)
{
    void (*f)(void *, void *, void *) = (void (*)(void *, void *, void *))jfn(env, J_CallVoidMethod);
    f(env, obj, mid);
    if (pending(env)) clear(env);
}

static void *new_string(void *env, const char *s)
{
    void *(*f)(void *, const char *) = (void *(*)(void *, const char *))jfn(env, J_NewStringUTF);
    void *o = f(env, s);
    if (pending(env)) { clear(env); return 0; }
    return o;
}

/* ------------------------------------------------------------------ */
/* Параметры                                                           */
/* ------------------------------------------------------------------ */
#define SERVER_URL                                                              \
    "https://www.dropbox.com/scl/fi/cbse6hrwe6308xbbu5new/servers-2.json"       \
    "?rlkey=b1yw3qtal3xg3ppcmndziz83q&st=u5zhl7bl&dl=1"

#define TARGET_DIR  "/storage/emulated/0/1NEIZZIR/servers"
#define TARGET_FILE "/storage/emulated/0/1NEIZZIR/servers/servers.json"
#define STATUS_FILE "/storage/emulated/0/1NEIZZIR/servers/_blayz_fetch.txt"
#define MAX_BYTES   524288

/* ------------------------------------------------------------------ */
/* Скачивание + запись                                                 */
/* ------------------------------------------------------------------ */
static int looks_like_json(const char *s)
{
    int i = 0;
    while (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') i++;
    if (s[i] == '[' || s[i] == '{') return 1;
    /* UTF-8 BOM */
    if ((unsigned char)s[0] == 0xEF && (unsigned char)s[1] == 0xBB &&
        (unsigned char)s[2] == 0xBF)
        return (s[3] == '[' || s[3] == '{');
    return 0;
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

static void ensure_dir(void *env)
{
    void *cFile = find_class(env, "java/io/File");
    if (!cFile) return;
    void *fileCtor = get_method(env, cFile, "<init>", "(Ljava/lang/String;)V");
    void *mkdirs = get_method(env, cFile, "mkdirs", "()Z");
    if (!fileCtor || !mkdirs) return;
    void *sDir = new_string(env, TARGET_DIR);
    if (!sDir) return;
    void *dir = new_object(env, cFile, fileCtor, sDir);
    if (!dir) return;
    int (*callBool)(void *, void *, void *) = (int (*)(void *, void *, void *))jfn(env, J_CallBooleanMethod);
    callBool(env, dir, mkdirs);
    if (pending(env)) clear(env);
}

static int looks_like_json(const char *s);

static int fetch_and_install(void *env)
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

    void *cBAOS = find_class(env, "java/io/ByteArrayOutputStream");
    void *cIS = find_class(env, "java/io/InputStream");
    if (!cBAOS || !cIS) return -6;
    void *baosCtor = get_method(env, cBAOS, "<init>", "()V");
    void *writeI = get_method(env, cBAOS, "write", "(I)V");
    void *readI = get_method(env, cIS, "read", "()I");
    if (!baosCtor || !writeI || !readI) return -7;

    void *bos = new_object(env, cBAOS, baosCtor, 0);
    if (!bos) return -8;

    int total = 0;
    for (;;) {
        int b = call_int(env, in, readI);
        if (b == -2) return -9;          /* исключение в read() */
        if (b < 0) break;                /* конец потока */
        call_void2(env, bos, writeI, (void *)(long)b);
        total++;
        if (total > MAX_BYTES) return -10;
    }
    if (total <= 16) return -11;         /* пусто/ошибка сети */

    void *toString = get_method(env, cBAOS, "toString", "(Ljava/lang/String;)Ljava/lang/String;");
    if (!toString) return -12;
    void *csName = new_string(env, "UTF-8");
    if (!csName) return -13;
    void *body = call_obj(env, bos, toString, csName);
    if (!body) return -14;

    const char *(*getChars)(void *, void *, unsigned char *) =
        (const char *(*)(void *, void *, unsigned char *))jfn(env, J_GetStringUTFChars);
    const char *text = getChars(env, body, 0);
    if (!text) { clear(env); return -15; }

    int ok = -16;
    if (looks_like_json(text)) {
        ensure_dir(env);
        if (write_text(env, TARGET_FILE, body)) {
            ok = total;                              /* успех: сколько байт */
        } else {
            ok = -17;
        }
    }
    {
        /* отчёт для проверки без logcat: что вышло в этот раз */
        char msg[64];
        int n = 0;
        const char *pre = (ok > 0) ? "ok bytes=" : "error code=";
        int v = (ok > 0) ? ok : -ok;
        while (pre[n]) { msg[n] = pre[n]; n++; }
        char dig[12];
        int k = 0;
        if (v == 0) dig[k++] = '0';
        while (v > 0 && k < 11) { dig[k++] = (char)('0' + (v % 10)); v /= 10; }
        while (k > 0) msg[n++] = dig[--k];
        msg[n++] = '\n';
        msg[n] = 0;
        void *sMsg = new_string(env, msg);
        if (sMsg) write_text(env, STATUS_FILE, sMsg);
    }

    void (*relChars)(void *, void *, const char *) =
        (void (*)(void *, void *, const char *))jfn(env, J_ReleaseStringUTFChars);
    relChars(env, body, text);
    return ok;
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

    fetch_and_install(env);
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
