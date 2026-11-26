/*
 * kolson_unlock_rt.c - runtime kill-switch shim for a *pristine* libkolson.so
 *
 * Build:  see Makefile (aarch64 / android ndk / clang cross)
 * Use:    dlopen this .so before the game loads libkolson (LD_PRELOAD on
 *         debuggable builds, or `System.loadLibrary` right after the launcher),
 *         or feed it to any injector:
 *
 *             adb push libkolson_unlock_rt.so /data/local/tmp/
 *             adb shell su -c "LD_PRELOAD=/data/local/tmp/libkolson_unlock_rt.so \
 *                              am start -n com.br.top/...MainActivity"
 *
 * How it works: the constructor resolves the already-mapped libkolson image,
 * validates each site against the reference word, mprotects the page rwx,
 * writes mov w0,wzr/mov w0,#1 + ret (or nop), flushes the i-cache per page and
 * restores the original protection.  Nothing is loaded from disk, so it also
 * works when the .so lives in an APK with uncompressed/aligned native libs.
 *
 * Why it is safe to run late: the anti-tamper verdict is computed lazily on
 * first use (checker 0x166c54 has exactly one caller, the first native entry)
 * and cached; the hook gate 0x243bb4 is re-read every call - after the patch it
 * takes the success path, so already-installed hooks keep working.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "kolson_patches.h"

#define LOG_TAG "kolson_unlock_rt"
#ifdef __ANDROID__
#include <android/log.h>
#define LOGI(...) __android_log_print(6, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(6, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) do { fprintf(stderr, LOG_TAG ": " __VA_ARGS__); fputc('\n', stderr); } while (0)
#define LOGE(...) LOGI(__VA_ARGS__)
#endif

static uintptr_t g_base;
static char      g_name[256];

static int find_module(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    const char *want = (const char *)data;
    if (!info->dlpi_name || !*info->dlpi_name) return 0;
    const char *slash = strrchr(info->dlpi_name, '/');
    const char *leaf = slash ? slash + 1 : info->dlpi_name;
    if (strcmp(leaf, want) != 0) return 0;
    g_base = (uintptr_t)info->dlpi_addr;
    snprintf(g_name, sizeof g_name, "%s", info->dlpi_name);
    return 1;
}

static void dcache_ivac(uintptr_t start, uintptr_t end) {
#if defined(__aarch64__)
    uintptr_t line;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(line));
    const int dline = 4 << ((line >> 16) & 0xf);
    for (uintptr_t p = start & ~(uintptr_t)(dline - 1); p < end; p += (uintptr_t)dline)
        __asm__ volatile("dc ivac, %0" : : "r"(p) : "memory");
    __asm__ volatile("dsb ish" : : : "memory");
    const int iline = 4 << (line & 0xf);
    for (uintptr_t p = start & ~(uintptr_t)(iline - 1); p < end; p += (uintptr_t)iline)
        __asm__ volatile("ic ivau, %0" : : "r"(p) : "memory");
    __asm__ volatile("dsb ish\n\tisb" : : : "memory");
#else
    (void)start; (void)end;
    __builtin___clear_cache((char *)start, (char *)end);
#endif
}

/* patch words [va, va+8*n) after verifying the expected ones, per page */
static int patch_group(unsigned va, const uint32_t *expect, const uint32_t *repl, int n) {
    unsigned char *target = (unsigned char *)(g_base + va);
    uint32_t *words = (uint32_t *)target;

    for (int i = 0; i < n; i++) {
        if (words[i] == repl[i]) continue;                    /* already applied */
        if (words[i] != expect[i]) {
            LOGE("%s+%#x: word %d is %#010x, expected %#010x - skipped",
                 g_name, va + 4u * i, i, words[i], expect[i]);
            return -1;
        }
    }

    const long page = sysconf(_SC_PAGESIZE);
    /* the two words of a site never straddle a page (VA is 8-byte aligned) */
    uintptr_t page0 = (uintptr_t)target & ~(uintptr_t)(page - 1);
    uintptr_t page1 = ((uintptr_t)target + 4u * n - 1) & ~(uintptr_t)(page - 1);

    for (uintptr_t pg = page0; pg <= page1; pg += (uintptr_t)page) {
        if (mprotect((void *)pg, (size_t)page, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            LOGE("mprotect rwx %p failed", (void *)pg);
            return -1;
        }
    }
    for (int i = 0; i < n; i++) words[i] = repl[i];
    dcache_ivac((uintptr_t)target, (uintptr_t)target + 4u * n);

    for (uintptr_t pg = page0; pg <= page1; pg += (uintptr_t)page)
        mprotect((void *)pg, (size_t)page, PROT_READ | PROT_EXEC);   /* back to r-x */
    return 0;
}

__attribute__((constructor))
static void kolson_unlock_init(void) {
    if (!dl_iterate_phdr(find_module, (void *)"libkolson.so")) {
        LOGI("libkolson.so not loaded yet - nothing to patch in this process");
        return;
    }

    int patched = 0, failed = 0;
    for (int i = 0; i < KOLSON_PATCH_COUNT; ) {
        /* collapse consecutive entries into one 8-byte (2-word) group */
        int group = 1;
        while (i + group < KOLSON_PATCH_COUNT &&
               kKolsonPatches[i + group].va == kKolsonPatches[i].va + 4u * (unsigned)group)
            group++;

        uint32_t expect[8], repl[8];
        for (int k = 0; k < group; k++) {
            expect[k] = kKolsonPatches[i + k].expect;
            repl[k]   = kKolsonPatches[i + k].replace;
        }
        if (patch_group(kKolsonPatches[i].va, expect, repl, group) == 0) patched += group;
        else failed += group;
        i += group;
    }
    LOGI("%s base=%p patched=%d failed=%d", g_name, (void *)g_base, patched, failed);
}
