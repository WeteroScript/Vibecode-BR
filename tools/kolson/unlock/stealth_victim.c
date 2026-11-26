/* как выглядит "проверка сторонних библиотек" со стороны лаунчера */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#ifndef VICTIM_MARK
#define VICTIM_MARK "kolson_stealth_target"
#endif
static const char *MARK = VICTIM_MARK;

static int hits_str(const char *s, size_t n) {
    size_t m = strlen(MARK), c = 0;
    for (size_t i = 0; i + m <= n; i++) if (memcmp(s + i, MARK, m) == 0) c++;
    return (int)c;
}

int victim_maps_fopen(void) {                 /* fopen("/proc/self/maps") */
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return -1;
    char buf[65536];
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    return hits_str(buf, n);
}

int victim_maps_open(void) {                  /* open + read */
    int fd = open("/proc/self/maps", 0);
    if (fd < 0) return -1;
    char buf[65536];
    ssize_t n = read(fd, buf, sizeof buf);
    close(fd);
    return n > 0 ? hits_str(buf, (size_t)n) : -1;
}

static int cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size; (void)data;
    if (info->dlpi_name) return hits_str(info->dlpi_name, strlen(info->dlpi_name));
    return 0;
}

int victim_phdr(void) {                       /* dl_iterate_phdr */
    return dl_iterate_phdr(cb, NULL);
}
