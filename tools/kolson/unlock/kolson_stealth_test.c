/* host-проверка механизма: сырые /proc/self/maps содержат наш маркер, а через
   наши обёртки open()/fopen() его уже нет. Плюс промоушен в RTLD_GLOBAL и
   GOT-патч не должны падать. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int hits(const char *buf, size_t n, const char *mark) {
    size_t m = strlen(mark), c = 0;
    for (size_t i = 0; i + m <= n; i++) if (memcmp(buf + i, mark, m) == 0) c++;
    return (int)c;
}

static int raw_hits(const char *mark) {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return -1;
    static char buf[1 << 20];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    return n > 0 ? hits(buf, (size_t)n, mark) : -1;
}

int main(int argc, char **argv) {
    if (argc < 3) { printf("usage: %s <our_lib.so> <mark>\n", argv[0]); return 2; }
    void *h = dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL);
    if (!h) { printf("dlopen: %s\n", dlerror()); return 2; }
    const char *mark = argv[2];

    int (*install)(void) = (int (*)(void))dlsym(h, "kolson_stealth_install");
    int (*promote)(void) = (int (*)(void))dlsym(h, "kolson_stealth_promote");
    int (*selftest)(void) = (int (*)(void))dlsym(h, "kolson_stealth_selftest");
    int (*our_open)(const char *, int, ...) = (int (*)(const char *, int, ...))dlsym(h, "open");
    FILE *(*our_fopen)(const char *, const char *) =
        (FILE * (*)(const char *, const char *)) dlsym(h, "fopen");
    if (!install || !promote || !selftest || !our_open || !our_fopen) {
        printf("нет символов\n");
        return 2;
    }

    int raw = raw_hits(mark);
    printf("сырые maps: маркер встречается %d раз\n", raw);

    int fd = our_open("/proc/self/maps", O_RDONLY);
    static char buf[1 << 20];
    ssize_t n = fd >= 0 ? read(fd, buf, sizeof buf - 1) : -1;
    if (fd >= 0) close(fd);
    int via_open = n > 0 ? hits(buf, (size_t)n, mark) : -1;

    FILE *f = our_fopen("/proc/self/maps", "r");
    int via_fopen = -1;
    if (f) {
        n = (ssize_t)fread(buf, 1, sizeof buf - 1, f);
        fclose(f);
        via_fopen = n > 0 ? hits(buf, (size_t)n, mark) : -1;
    }

    int promoted = promote();
    int patched = install();
    int st = selftest();
    printf("через open(): %d, через fopen(): %d\n", via_open, via_fopen);
    printf("promote=%d, GOT подменено=%d, маркеров видно в сырых maps=%d\n",
           promoted, patched, st);

    /* selftest возвращает число видимых в сырых maps маркеров, не вхождений */
    int ok = raw > 0 && via_open == 0 && via_fopen == 0 && promoted == 0 && st >= 1;
    printf("RESULT: %s\n", ok ? "OK (обёртки прячут наш модуль)" : "FAIL");
    return ok ? 0 : 1;
}
