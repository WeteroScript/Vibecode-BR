/*
 * kolson_one.c - ОДНА библиотека вместо трёх файлов.
 *
 *   libkolson_patch.so
 *     - грузится в процесс как обычная JNI-библиотека (System.load / loadLibrary);
 *     - находит или подгружает штатную libkolson.so (файл на диске не трогаем:
 *       в APK остаётся оригинал, sha256 совпадает);
 *     - патчит 25 kill-switch-слов уже в отображённой памяти (mprotect + i-cache);
 *     - отдаёт статус в Java: apply()/applyDir()/patched()/failed()/report().
 *
 * Зачем именно так:
 *   - нет второй копии игровой библиотеки, а значит нет конфликта SONAME
 *     (той самой причины, из-за которой раньше требовался `-n libklnc.so`);
 *   - в 1NEIZZIR/Modules и Custom/modules ничего не появляется - сканер
 *     сторонних модулей нечего находить;
 *   - патч применяется между `loadLibrary("kolson")` и первым нативным вызовом,
 *     а проверки внутри libkolson ленивые, поэтому вердикт «чисто» не меняется.
 *
 * Хост-проверка (без Android): см. kolson_one_test.c, `make one-test` -
 * доказывает, что runtime-патч даёт побайтово тот же образ, что offline-патчер.
 *
 * Сборка NDK:  make one        (= build/libkolson_patch.so)
 * Сборка вручную:
 *   aarch64-linux-android21-clang -O2 -fPIC -shared -I. \
 *       -Wl,-soname,libkolson_patch.so -o libkolson_patch.so kolson_one.c -llog -ldl
 *
 * Единственный источник истины по адресам и словам - kolson_patches.h.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "kolson_patches.h"

#if !defined(KOLSON_HOST)
#include <android/log.h>
#include <dlfcn.h>
#include <jni.h>
#include <link.h>
#include <pthread.h>
#define LOG_TAG "kolson_patch"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define KOLSON_ANDROID 1
#else
#define LOGI(...) do { fprintf(stderr, "kolson_patch: " __VA_ARGS__); fputc('\n', stderr); } while (0)
#define LOGE(...) LOGI(__VA_ARGS__)
#endif

/* --------------------------------------------------------------- состояние */

#if !defined(KOLSON_HOST)
static uintptr_t g_base;         /* адрес загрузки libkolson.so        */
static char      g_path[256];    /* откуда именно она загружена        */
#endif
static int       g_patched;      /* сколько слов применено             */
static int       g_failed;       /* сколько сайтов не совпало          */
#if !defined(KOLSON_HOST)
static int       g_done;         /* 1 - попытка уже была               */
#endif

int kolson_patched_count(void) { return g_patched; }
int kolson_failed_count(void)  { return g_failed; }
#if !defined(KOLSON_HOST)
const char *kolson_module_path(void) { return g_path; }
#endif

/* ------------------------------------------------------- i-cache / страницы */

static void dcache_ivac(uintptr_t start, uintptr_t end) {
#if defined(__aarch64__)
    uintptr_t ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    const int dline = 4 << ((ctr >> 16) & 0xf);
    for (uintptr_t p = start & ~(uintptr_t)(dline - 1); p < end; p += (uintptr_t)dline)
        __asm__ volatile("dc ivac, %0" : : "r"(p) : "memory");
    __asm__ volatile("dsb ish" : : : "memory");
    const int iline = 4 << (ctr & 0xf);
    for (uintptr_t p = start & ~(uintptr_t)(iline - 1); p < end; p += (uintptr_t)iline)
        __asm__ volatile("ic ivau, %0" : : "r"(p) : "memory");
    __asm__ volatile("dsb ish\n\tisb" : : : "memory");
#else
    __builtin___clear_cache((char *)start, (char *)end);
#endif
}

/* Группа подряд идущих слов: сверяем эталоны, пишем замену.
   Сайт не пересекает границу страницы (VA выровнен на 8 байт). */
static int patch_group(uintptr_t base, unsigned va, const uint32_t *expect,
                       const uint32_t *repl, int n) {
    unsigned char *target = (unsigned char *)(base + va);
    uint32_t *words = (uint32_t *)target;

    for (int i = 0; i < n; i++) {
        if (words[i] == repl[i]) continue;                /* уже пропатчено */
        if (words[i] != expect[i]) {
            LOGE("+%#x: word %d is %#010x, expected %#010x - site skipped",
                 va + 4u * (unsigned)i, i, words[i], expect[i]);
            return -1;
        }
    }

    const long page = sysconf(_SC_PAGESIZE);
    uintptr_t page0 = (uintptr_t)target & ~(uintptr_t)(page - 1);
    uintptr_t page1 = ((uintptr_t)target + 4u * (unsigned)n - 1) & ~(uintptr_t)(page - 1);

    for (uintptr_t pg = page0; pg <= page1; pg += (uintptr_t)page)
        if (mprotect((void *)pg, (size_t)page, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            LOGE("mprotect rwx %p failed", (void *)pg);
            return -1;
        }

    for (int i = 0; i < n; i++) words[i] = repl[i];
    dcache_ivac((uintptr_t)target, (uintptr_t)target + 4u * (unsigned)n);

    for (uintptr_t pg = page0; pg <= page1; pg += (uintptr_t)page)
        mprotect((void *)pg, (size_t)page, PROT_READ | PROT_EXEC);   /* назад в r-x */
    return 0;
}

/* --------------------------------------------------- весь набор по таблице */

int kolson_patch_image(uintptr_t base, int *patched, int *failed) {
    int ok = 0, bad = 0;
    for (int i = 0; i < KOLSON_PATCH_COUNT; ) {
        int group = 1;
        while (i + group < KOLSON_PATCH_COUNT &&
               kKolsonPatches[i + group].va == kKolsonPatches[i].va + 4u * (unsigned)group)
            group++;

        uint32_t expect[8], repl[8];
        for (int k = 0; k < group; k++) {
            expect[k] = kKolsonPatches[i + k].expect;
            repl[k]   = kKolsonPatches[i + k].replace;
        }
        if (patch_group(base, kKolsonPatches[i].va, expect, repl, group) == 0) ok += group;
        else bad += group;
        i += group;
    }
    if (patched) *patched = ok;
    if (failed)  *failed = bad;
    return bad == 0 ? 0 : -1;
}

#if defined(KOLSON_ANDROID)

/* -------------------------------------------- поиск / подгрузка libkolson.so */

static int find_module(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    (void)data;
    if (!info->dlpi_name || !*info->dlpi_name) return 0;
    const char *slash = strrchr(info->dlpi_name, '/');
    const char *leaf = slash ? slash + 1 : info->dlpi_name;
    if (strcmp(leaf, "libkolson.so") != 0) return 0;
    g_base = (uintptr_t)info->dlpi_addr;
    snprintf(g_path, sizeof g_path, "%s", info->dlpi_name);
    return 1;
}

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* Ровно то же, что делает System.loadLibrary: имена и абсолютные пути по
   порядку, пока один не откроется. dir может быть NULL. */
static int dlopen_kolson(const char *dir) {
    static char abs[512];
    const char *cand[4] = { "libkolson.so", NULL, NULL, NULL };
    if (dir && *dir) {
        snprintf(abs, sizeof abs, "%s/libkolson.so", dir);
        cand[1] = abs;
    }
    for (int i = 0; i < 4; i++) {
        if (!cand[i]) continue;
        void *h = dlopen(cand[i], RTLD_NOW | RTLD_GLOBAL);
        if (h) {
            LOGI("dlopen(%s) ok", cand[i]);
            return 0;
        }
        LOGE("dlopen(%s): %s", cand[i], dlerror());
    }
    return -1;
}

/* Основная операция: один раз за жизнь процесса найти libkolson, подгрузить
   её при необходимости и пропатчить. Возвращает число применённых слов. */
static int kolson_run(const char *dir) {
    pthread_mutex_lock(&g_lock);
    if (g_done && (g_patched || g_failed)) {
        int rc = g_failed ? -1 : 0;
        pthread_mutex_unlock(&g_lock);
        return rc;
    }
    g_done = 1;

    if (!dl_iterate_phdr(find_module, NULL)) {
        if (dlopen_kolson(dir) != 0) {
            /* ещё не установлена/не распакована - не беда, попробуем позже */
            LOGI("libkolson.so is neither mapped nor dlopen-able yet");
            g_done = 0;
            pthread_mutex_unlock(&g_lock);
            return -1;
        }
        if (!dl_iterate_phdr(find_module, NULL)) {
            LOGE("dlopen succeeded but phdr walk did not find libkolson.so");
            g_failed = KOLSON_PATCH_COUNT;
            pthread_mutex_unlock(&g_lock);
            return -1;
        }
    }

    kolson_patch_image(g_base, &g_patched, &g_failed);
    LOGI("%s base=%p patched=%d failed=%d", g_path, (void *)g_base, g_patched, g_failed);
    int rc = g_failed ? -1 : 0;
    pthread_mutex_unlock(&g_lock);
    return rc;
}

/* Конструктор: если библиотека уже в памяти (LD_PRELOAD / инжект / обычная
   загрузка после неё) - патчим сразу, до первого нативного вызова. */
__attribute__((constructor)) static void kolson_ctor(void) { kolson_run(NULL); }

/* --------------------------------------------------------------- JNI-часть */

/* Экспортируем методы обычными JNI-именами: класс не нужно искать через
   FindClass (а значит, нет зависимости от ClassLoader и от момента, когда
   smali-класс появится в процессе). */
JNIEXPORT jint JNICALL
Java_com_klnc_native_KolsonPatch_nativeApply(JNIEnv *env, jclass cls) {
    (void)env; (void)cls;
    kolson_run(NULL);
    return (jint)g_patched;
}

JNIEXPORT jint JNICALL
Java_com_klnc_native_KolsonPatch_nativeApplyDir(JNIEnv *env, jclass cls, jstring dir) {
    (void)cls;
    const char *c = dir ? (*env)->GetStringUTFChars(env, dir, NULL) : NULL;
    kolson_run(c);
    if (c) (*env)->ReleaseStringUTFChars(env, dir, c);
    return (jint)g_patched;
}

JNIEXPORT jint JNICALL
Java_com_klnc_native_KolsonPatch_nativePatched(JNIEnv *env, jclass cls) {
    (void)env; (void)cls;
    return (jint)g_patched;
}

JNIEXPORT jint JNICALL
Java_com_klnc_native_KolsonPatch_nativeFailed(JNIEnv *env, jclass cls) {
    (void)env; (void)cls;
    return (jint)g_failed;
}

JNIEXPORT jstring JNICALL
Java_com_klnc_native_KolsonPatch_nativeReport(JNIEnv *env, jclass cls) {
    (void)cls;
    char buf[512];
    snprintf(buf, sizeof buf, "patched=%d failed=%d base=%p path=%s",
             g_patched, g_failed, (void *)g_base, g_path[0] ? g_path : "(not loaded)");
    return (*env)->NewStringUTF(env, buf);
}

/* Если libkolson уже в памяти - патчим прямо здесь, до первого нативного
   вызова приложения. Если нет - сделаем это из nativeApply()/конструктора. */
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    kolson_run(NULL);
    return JNI_VERSION_1_6;
}

#endif /* KOLSON_ANDROID */
