/*
 * kolson_stealth.c - самоконспирация обходчика: лаунчер не должен видеть саму
 * библиотеку в списке загруженных модулей и в /proc/self/maps.
 *
 * Зачем: проверка "сторонние библиотеки" перечисляет либо загруженные модули
 * (dl_iterate_phdr), либо строки /proc/self/maps, и наш обходчик для неё - такой
 * же посторонний файл, как любой мод. Здесь подменяются GOT-записи во всех уже
 * загруженных модулях:
 *
 *   dl_iterate_phdr(...)  -> обёртка, выкидывает наши записи из списка
 *   open/open64/openat()  -> на "/proc/self/maps" отдаётся отфильтрованная копия
 *   fopen/fopen64()       -> то же самое
 *
 * Ничего не пишется на диск: отфильтрованная копия живёт в memfd.
 * Файл libkolson.so при этом не изменяется ни на байт.
 *
 * Маркеры (что прятать) по умолчанию: libklnc.so, libkolson_patch.so,
 * libkolson.unlock. Дополнительно можно задать env KOLSON_STEALTH_MARKS
 * (через ':' или пробел) - удобно и для теста, и для переименованных сборок.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "kolson_stealth.h"

#ifndef KOLSON_ANDROID
#define LOGI(...) do { fprintf(stderr, "kolson_stealth: " __VA_ARGS__); fputc('\n', stderr); } while (0)
#else
#include <android/log.h>
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "kolson_stealth", __VA_ARGS__)
#endif

#define MAX_MARKS 8

static const char *const DEFAULT_MARKS[] = {
    "libklnc.so", "libkolson_patch.so", "libkolson.unlock", NULL
};
static const char *g_marks[MAX_MARKS];
static size_t g_marks_n;
static int g_installed;         /* сколько GOT-записей подменено */
static int g_busy;              /* защита от рекурсии               */
static int g_inited;

static int (*real_open)(const char *, int, ...);
static int (*real_open64)(const char *, int, ...);
static int (*real_openat)(int, const char *, int, ...);
static FILE *(*real_fopen)(const char *, const char *);
static FILE *(*real_fopen64)(const char *, const char *);
static int (*real_iterate)(int (*)(struct dl_phdr_info *, size_t, void *), void *);

/* ------------------------------------------------------------------ маркеры */
static void marks_init(void) {
    if (g_inited) return;
    g_inited = 1;
    for (size_t i = 0; DEFAULT_MARKS[i] && g_marks_n < MAX_MARKS; i++)
        g_marks[g_marks_n++] = DEFAULT_MARKS[i];
    const char *env = getenv("KOLSON_STEALTH_MARKS");
    if (env && *env) {
        char *dup = strdup(env);
        if (dup) {
            for (char *tok = strtok(dup, ": ;,"); tok && g_marks_n < MAX_MARKS;
                 tok = strtok(NULL, ": ;,"))
                g_marks[g_marks_n++] = strdup(tok);
        }
    }
}

static int is_hidden_name(const char *name) {
    if (!name || !*name) return 0;
    marks_init();
    for (size_t i = 0; i < g_marks_n; i++)
        if (g_marks[i] && strstr(name, g_marks[i])) return 1;
    return 0;
}

/* ------------------------------------------------------- фильтр /proc/maps */
static int write_all(int fd, const char *p, size_t n) {
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

/* Отфильтрованная копия /proc/self/maps в memfd (позиция 0). -1 при ошибке. */
static int sanitized_maps_fd(void) {
    marks_init();
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t cap = 1 << 18, len = 0;
    char *buf = malloc(cap);
    if (!buf) { close(fd); return -1; }
    for (;;) {
        if (len + (1 << 16) > cap) {
            size_t ncap = cap * 2;
            char *nb = realloc(buf, ncap);
            if (!nb) { free(buf); close(fd); return -1; }
            buf = nb;
            cap = ncap;
        }
        ssize_t n = read(fd, buf + len, (1 << 16));
        if (n < 0) { free(buf); close(fd); return -1; }
        if (n == 0) break;
        len += (size_t)n;
        if (len > (64u << 20)) break;              /* sanity */
    }
    close(fd);

    int mfd = (int)syscall(SYS_memfd_create, "maps", 0);
    if (mfd < 0) { free(buf); return -1; }

    size_t i = 0, kept = 0, dropped = 0;
    while (i < len) {
        size_t j = i;
        while (j < len && buf[j] != '\n') j++;
        size_t end = (j < len) ? j + 1 : j;
        int skip = 0;
        for (size_t m = 0; m < g_marks_n && !skip; m++) {
            const char *mark = g_marks[m];
            if (!mark) continue;
            size_t ml = strlen(mark);
            for (size_t k = i; k + ml <= j; k++)
                if (memcmp(buf + k, mark, ml) == 0) { skip = 1; break; }
        }
        if (!skip && end > i) {
            if (write_all(mfd, buf + i, end - i) == 0) kept++;
        } else if (skip) {
            dropped++;
        }
        i = end;
    }
    free(buf);
    lseek(mfd, 0, SEEK_SET);
    LOGI("maps: отдано %zu строк, скрыто %zu", kept, dropped);
    return mfd;
}

static int is_maps_path(const char *p) {
    if (!p) return 0;
    if (strcmp(p, "/proc/self/maps") == 0) return 1;
    if (strcmp(p, "/proc/thread-self/maps") == 0) return 1;
    return 0;
}

/* ------------------------------------------------------------ обёртки libc */
int open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (!real_open) real_open = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open");
    if (is_maps_path(path)) {
        int fd = sanitized_maps_fd();
        if (fd >= 0) return fd;
    }
    return real_open(path, flags, mode);
}

int open64(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (!real_open64) real_open64 = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open64");
    if (is_maps_path(path)) {
        int fd = sanitized_maps_fd();
        if (fd >= 0) return fd;
    }
    return real_open64 ? real_open64(path, flags, mode) : open(path, flags, mode);
}

int openat(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (!real_openat) real_openat = (int (*)(int, const char *, int, ...))dlsym(RTLD_NEXT, "openat");
    if (is_maps_path(path) || strcmp(path, "maps") == 0) {
        int fd = sanitized_maps_fd();
        if (fd >= 0) return fd;
    }
    return real_openat(dirfd, path, flags, mode);
}

FILE *fopen(const char *path, const char *mode) {
    if (!real_fopen) real_fopen = (FILE * (*)(const char *, const char *)) dlsym(RTLD_NEXT, "fopen");
    if (is_maps_path(path)) {
        int fd = sanitized_maps_fd();
        if (fd >= 0) {
            FILE *f = fdopen(fd, mode ? mode : "r");
            if (f) return f;
            close(fd);
        }
    }
    return real_fopen(path, mode);
}

FILE *fopen64(const char *path, const char *mode) {
    if (!real_fopen64) real_fopen64 = (FILE * (*)(const char *, const char *)) dlsym(RTLD_NEXT, "fopen64");
    if (!real_fopen64) return fopen(path, mode);
    if (is_maps_path(path)) {
        int fd = sanitized_maps_fd();
        if (fd >= 0) {
            FILE *f = fdopen(fd, mode ? mode : "r");
            if (f) return f;
            close(fd);
        }
    }
    return real_fopen64(path, mode);
}

struct iterate_wrap {
    int (*cb)(struct dl_phdr_info *, size_t, void *);
    void *arg;
};

static int iterate_filter(struct dl_phdr_info *info, size_t size, void *data) {
    struct iterate_wrap *w = (struct iterate_wrap *)data;
    if (info && is_hidden_name(info->dlpi_name)) return 0;   /* не показываем */
    return w->cb(info, size, w->arg);
}

int dl_iterate_phdr(int (*cb)(struct dl_phdr_info *, size_t, void *), void *data) {
    if (!real_iterate)
        real_iterate = (int (*)(int (*)(struct dl_phdr_info *, size_t, void *), void *))
                           dlsym(RTLD_NEXT, "dl_iterate_phdr");
    if (!real_iterate) return 0;
    struct iterate_wrap w = { cb, data };
    return real_iterate(iterate_filter, &w);
}

/* ------------------------------------------------------------ GOT-патчинг */
struct target {
    const char *name;
    void *ours;
};

static void *resolve_ours(const char *name) {
    if (strcmp(name, "dl_iterate_phdr") == 0) return (void *)&dl_iterate_phdr;
    if (strcmp(name, "fopen") == 0) return (void *)&fopen;
    if (strcmp(name, "fopen64") == 0) return (void *)&fopen64;
    if (strcmp(name, "open") == 0) return (void *)&open;
    if (strcmp(name, "open64") == 0) return (void *)&open64;
    if (strcmp(name, "openat") == 0) return (void *)&openat;
    return NULL;
}

static const char *const TARGETS[] = {
    "dl_iterate_phdr", "fopen", "fopen64", "open", "open64", "openat", NULL
};

static ElfW(Addr) dyn_lookup(const ElfW(Dyn) *d, ElfW(Sxword) tag) {
    for (; d && d->d_tag != DT_NULL; d++)
        if (d->d_tag == tag) return d->d_un.d_val;
    return 0;
}

static int patch_module(uintptr_t base, const ElfW(Phdr) *ph, int phnum) {
    const ElfW(Dyn) *dyn = NULL;
    for (int i = 0; i < phnum; i++)
        if (ph[i].p_type == PT_DYNAMIC) {
            dyn = (const ElfW(Dyn) *)(base + ph[i].p_vaddr);
            break;
        }
    if (!dyn) return 0;
    ElfW(Addr) jmprel = dyn_lookup(dyn, DT_JMPREL);
    ElfW(Addr) pltrelsz = dyn_lookup(dyn, DT_PLTRELSZ);
    ElfW(Addr) rel = dyn_lookup(dyn, DT_PLTREL);
    ElfW(Addr) symtab = dyn_lookup(dyn, DT_SYMTAB);
    ElfW(Addr) strtab = dyn_lookup(dyn, DT_STRTAB);
    if (!jmprel || !pltrelsz || !symtab || !strtab) return 0;

    size_t n = pltrelsz / sizeof(ElfW(Rela));
    if (rel != DT_RELA) n = pltrelsz / sizeof(ElfW(Rel));
    int patched = 0;
    for (size_t i = 0; i < n; i++) {
        ElfW(Addr) off = 0, symidx = 0;
        if (rel == DT_RELA) {
            const ElfW(Rela) *r = (const ElfW(Rela) *)jmprel + i;
            off = r->r_offset;
            symidx = ELF64_R_SYM(r->r_info);
        } else {
            const ElfW(Rel) *r = (const ElfW(Rel) *)jmprel + i;
            off = r->r_offset;
            symidx = ELF64_R_SYM(r->r_info);
        }
        const char *sname = (const char *)(strtab + ((const ElfW(Sym) *)symtab)[symidx].st_name);
        if (!sname || !*sname) continue;
        void *ours = NULL;
        for (int t = 0; TARGETS[t]; t++)
            if (strcmp(sname, TARGETS[t]) == 0) { ours = resolve_ours(sname); break; }
        if (!ours) continue;
        void **slot = (void **)(base + off);
        if (*slot == ours) continue;
        long pg = sysconf(_SC_PAGESIZE);
        void *page = (void *)((uintptr_t)slot & ~(uintptr_t)(pg - 1));
        if (mprotect(page, (size_t)pg, PROT_READ | PROT_WRITE) != 0) continue;
        *slot = ours;
        mprotect(page, (size_t)pg, PROT_READ);
        patched++;
    }
    return patched;
}

static int self_base_ok(uintptr_t base) {
    Dl_info info;
    if (!dladdr((void *)&kolson_stealth_install, &info) || !info.dli_fbase) return 1;
    return (uintptr_t)info.dli_fbase != base;
}

struct install_ctx { int count; };

static int install_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    struct install_ctx *ctx = (struct install_ctx *)data;
    uintptr_t base = (uintptr_t)info->dlpi_addr;
    if (!base) return 0;                       /* сам ld.so / main - не трогаем */
    if (!self_base_ok(base)) return 0;
    int got = patch_module(base, info->dlpi_phdr, info->dlpi_phnum);
    ctx->count += got;
    return 0;
}

int kolson_stealth_install(void) {
    if (g_busy) return g_installed;
    g_busy = 1;
    marks_init();
    int (*it)(int (*)(struct dl_phdr_info *, size_t, void *), void *) =
        (int (*)(int (*)(struct dl_phdr_info *, size_t, void *), void *))
            dlsym(RTLD_NEXT, "dl_iterate_phdr");
    struct install_ctx ctx = { 0 };
    if (it) {
        it(install_cb, &ctx);
        g_installed += ctx.count;
        LOGI("GOT подменено: +%d (всего %d)", ctx.count, g_installed);
    }
    g_busy = 0;
    return g_installed;
}

int kolson_stealth_installed(void) { return g_installed; }

/* Поднять себя в глобальную область видимости: тогда библиотека, загруженная
   ПОСЛЕ нас (libkolson.so), при биндинге своих импортов open/fopen/
   dl_iterate_phdr возьмёт наши функции. Это основной путь на Android; GOT-патч
   выше нужен только для модулей, загруженных раньше. */
int kolson_stealth_promote(void) {
    Dl_info info;
    if (!dladdr((void *)&kolson_stealth_promote, &info) || !info.dli_fname) return -1;
    if (!dlopen(info.dli_fname, RTLD_NOW | RTLD_GLOBAL | RTLD_NOLOAD)) {
        if (!dlopen(info.dli_fname, RTLD_NOW | RTLD_GLOBAL)) {
            LOGI("promote failed: %s", dlerror());
            return -1;
        }
    }
    LOGI("promoted to RTLD_GLOBAL: %s", info.dli_fname);
    return 0;
}

/* ------------------------------------------------------------- самопроверка */
int kolson_stealth_selftest(void) {
    marks_init();
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t cap = 1 << 20, len = 0;
    char *buf = malloc(cap);
    if (!buf) { close(fd); return -1; }
    ssize_t n;
    while ((n = read(fd, buf + len, cap - len)) > 0) {
        len += (size_t)n;
        if (len + 1 >= cap) {
            char *nb = realloc(buf, cap * 2);
            if (!nb) break;
            buf = nb;
            cap *= 2;
        }
    }
    close(fd);
    int hidden = 0, visible = 0;
    for (size_t i = 0; i < g_marks_n; i++) {
        if (!g_marks[i]) continue;
        size_t ml = strlen(g_marks[i]);
        for (size_t k = 0; k + ml <= len; k++)
            if (memcmp(buf + k, g_marks[i], ml) == 0) { hidden++; break; }
    }
    /* сами мы в maps точно есть - считаем, что видимых строк >= 1 */
    visible = len > 0;
    free(buf);
    /* всё, что нашли в сырых maps, обёртка обязана выкинуть */
    return visible ? hidden : -1;
}
