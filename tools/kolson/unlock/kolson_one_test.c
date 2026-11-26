/*
 * kolson_one_test.c - хост-проверка kolson_one.c без Android и без NDK.
 *
 * Читает .so, ЗАГРУЖАЕТ его через host dlopen (так, чтобы VA == файловому
 * смещению: нужен эльф с p_vaddr == p_offset, как у libkolson), прогоняет
 * kolson_patch_image() и сравнивает побайтово с offline-патчем - это и есть
 * доказательство, что на одном и том же входе runtime-патч даёт ровно тот же
 * результат, что и offline-патчер.
 *
 *   cc -O2 -DKOLSON_HOST -I. -o test_one kolson_one.c kolson_one_test.c -ldl
 *   ./test_one libkolson.so build/libkolson.unlocked.so
 */
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int kolson_patch_image(uintptr_t base, int *patched, int *failed);
int kolson_patch_image_sized(uintptr_t base, size_t size, int *patched, int *failed);
const char *kolson_build_name(void);
int kolson_site_count(void);
unsigned kolson_blob_bytes(void);

static unsigned char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc((size_t)n);
    if (fread(b, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(b); return NULL; }
    fclose(f);
    *len = (size_t)n;
    return b;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <pristine.so> [expected-patched.so] [dump-out.so]\n", argv[0]);
        return 2;
    }
    size_t plen = 0;
    unsigned char *file = slurp(argv[1], &plen);
    if (!file) { perror("read"); return 2; }

    /* MAP_PRIVATE anonymous + copy: страницы принадлежат нам и writable,
       mprotect внутри патча работает без хитростей. */
    long page = sysconf(_SC_PAGESIZE);
    size_t map = (plen + (size_t)page - 1) & ~((size_t)page - 1);
    unsigned char *img = mmap(NULL, map, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (img == MAP_FAILED) { perror("mmap"); return 2; }
    memcpy(img, file, plen);

    int patched = 0, failed = 0;
    int rc = kolson_patch_image_sized((uintptr_t)img, plen, &patched, &failed);
    int want = kolson_site_count();
    printf("kolson_patch_image: rc=%d build=%s patched=%d failed=%d (сайтов %d)\n",
           rc, kolson_build_name(), patched, failed, want);

    int bad = 0;
    if (patched != want || failed != 0 || want == 0) {
        printf("FAIL: expected patched=%d failed=0\n", want);
        bad++;
    }

    /* все прочие байты обязаны совпасть с оригиналом */
    size_t diff = 0;
    for (size_t i = 0; i < plen; i++)
        if (img[i] != file[i]) diff++;
    size_t allowed = (size_t)want * 4 + kolson_blob_bytes();
    printf("bytes changed vs pristine: %zu (<= %zu Б: %d слов + %u Б пейлоада)\n",
           diff, allowed, want, kolson_blob_bytes());
    if (diff == 0 || diff > allowed) { printf("FAIL: diff out of range\n"); bad++; }

    if (argc > 2) {
        size_t elen = 0;
        unsigned char *exp = slurp(argv[2], &elen);
        if (!exp) { perror("read expected"); return 2; }
        if (elen != plen) { printf("FAIL: expected size %zu != %zu\n", elen, plen); bad++; }
        size_t mism = 0;
        for (size_t i = 0; i < plen && i < elen; i++)
            if (img[i] != exp[i]) mism++;
        printf("bytes differing from %s: %zu\n", argv[2], mism);
        if (mism) { printf("FAIL: runtime patch != offline patch\n"); bad++; }
        else printf("OK: runtime patch == offline patch\n");
        free(exp);
    }

    if (argc > 3) {
        FILE *o = fopen(argv[3], "wb");
        if (!o) { perror("dump"); return 2; }
        fwrite(img, 1, plen, o);
        fclose(o);
        printf("patched image written to %s\n", argv[3]);
    }

    /* идемпотентность: второй прогон не должен ничего сломать */
    int p2 = 0, f2 = 0;
    kolson_patch_image_sized((uintptr_t)img, plen, &p2, &f2);
    printf("second pass: patched=%d failed=%d (ожидаем %d/0)\n", p2, f2, want);
    if (p2 != want || f2 != 0) bad++;

    printf("%s\n", bad ? "RESULT: FAIL" : "RESULT: OK");
    return bad ? 1 : 0;
}
