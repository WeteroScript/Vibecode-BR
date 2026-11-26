/*
 * kolson_unlock.c - offline anti-tamper killer for libkolson.so
 *
 *   ./kolson_unlock -i libkolson.so -o libkolson.unlocked.so          # patch all
 *   ./kolson_unlock -i libkolson.so --list                            # show sites
 *   ./kolson_unlock -i libkolson.so -o out.so --only sig,gate,tracer   # subset
 *   ./kolson_unlock -i libkolson.so --verify                          # check only
 *
 * Every site is validated against the reference word before anything is
 * written; a single mismatch aborts the run (--force downgrades to a warning).
 * File size, section layout and relocations are untouched, so the output
 * replaces the original 1:1 and keeps its 16 KB page alignment.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "kolson_patches.h"

#define EI_NIDENT 16
#define EM_AARCH64 183
#define TEXT_VA_LO 0x137e40u
#define TEXT_VA_HI 0x5e007cu

static int g_force;
static int g_verbose;

static void die(const char *msg) {
    fprintf(stderr, "kolson_unlock: %s: %s\n", msg, strerror(errno));
    exit(1);
}

static uint8_t *slurp(const char *path, size_t *size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) die(path);
    struct stat st;
    if (fstat(fd, &st) < 0) die("fstat");
    if (st.st_size <= 0) { fprintf(stderr, "empty file\n"); exit(1); }
    uint8_t *buf = malloc((size_t)st.st_size);
    if (!buf) die("malloc");
    size_t done = 0;
    while (done < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + done, (size_t)st.st_size - done);
        if (n <= 0) die("read");
        done += (size_t)n;
    }
    close(fd);
    *size = (size_t)st.st_size;
    return buf;
}

static void spit(const char *path, const uint8_t *buf, size_t size) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) die(path);
    size_t done = 0;
    while (done < size) {
        ssize_t n = write(fd, buf + done, size - done);
        if (n <= 0) die("write");
        done += (size_t)n;
    }
    if (fchmod(fd, 0755) < 0) die("fchmod");
    close(fd);
}

static int check_elf64_aarch64(const uint8_t *buf, size_t size) {
    if (size < 64 || memcmp(buf, "\177ELF", 4) != 0) return -1;
    if (buf[4] != 2 /* ELFCLASS64 */ || buf[5] != 1 /* little endian */) return -2;
    uint16_t machine;
    memcpy(&machine, buf + 18, sizeof machine);
    if (machine != EM_AARCH64) return -3;
    return 0;
}

static uint32_t rd32(const uint8_t *buf, unsigned va) {
    uint32_t w;
    memcpy(&w, buf + va, sizeof w);   /* .text: file offset == virtual address */
    return w;
}

static int selected(const char *module, const char *only) {
    if (!only || !*only) return 1;
    const char *p = only;
    size_t mlen = strlen(module);
    while (*p) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        if (len == mlen && strncmp(p, module, len) == 0) return 1;
        if (!comma) break;
        p = comma + 1;
    }
    return 0;
}

enum { MODE_PATCH, MODE_LIST, MODE_VERIFY };

int main(int argc, char **argv) {
    const char *in = NULL, *out = NULL, *only = NULL;
    int mode = MODE_PATCH;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-i") && i + 1 < argc)            in = argv[++i];
        else if (!strcmp(a, "-o") && i + 1 < argc)       out = argv[++i];
        else if (!strcmp(a, "--only") && i + 1 < argc)   only = argv[++i];
        else if (!strcmp(a, "--list"))                   mode = MODE_LIST;
        else if (!strcmp(a, "--verify"))                 mode = MODE_VERIFY;
        else if (!strcmp(a, "--force"))                  g_force = 1;
        else if (!strcmp(a, "-v"))                       g_verbose = 1;
        else {
            fprintf(stderr,
                    "usage: %s -i <lib.so> [-o <out.so>] [--only mod[,mod]]\n"
                    "       %s -i <lib.so> --list | --verify\n"
                    "       modules: ", argv[0], argv[0]);
            for (int k = 0; k < KOLSON_PATCH_COUNT; k++)
                fprintf(stderr, "%s%s", k ? "," : "", kKolsonPatches[k].module);
            fprintf(stderr, "\n");
            return 2;
        }
    }
    if (!in) { fprintf(stderr, "kolson_unlock: -i <libkolson.so> is required\n"); return 2; }
    if (mode == MODE_PATCH && !out) {
        fprintf(stderr, "kolson_unlock: -o <out.so> is required (input is never modified)\n");
        return 2;
    }

    size_t size = 0;
    uint8_t *buf = slurp(in, &size);
    int elf = check_elf64_aarch64(buf, size);
    if (elf) {
        fprintf(stderr, "kolson_unlock: %s: not ELF64/AArch64 (%d)\n", in, elf);
        return 1;
    }
    if (size < TEXT_VA_HI) {
        fprintf(stderr, "kolson_unlock: %s: %zu bytes, expected >= %#x\n",
                in, size, TEXT_VA_HI);
        return 1;
    }

    int applied = 0, skipped = 0, mismatch = 0;
    for (int i = 0; i < KOLSON_PATCH_COUNT; i++) {
        const kolson_patch_t *p = &kKolsonPatches[i];
        if (!selected(p->module, only)) continue;

        uint32_t now = rd32(buf, p->va);
        int already = (now == p->replace);
        int known   = (now == p->expect) || already;

        if (mode == MODE_LIST) {
            printf("%-7s %#010x  now=%#010x  expect=%#010x  -> %#010x%s\n",
                   p->module, p->va, now, p->expect, p->replace,
                   already ? "  [already]" : known ? "" : "  [MISMATCH]");
            if (!known) mismatch++;
            continue;
        }

        if (already) { skipped++; if (g_verbose) printf("skip %#x (already patched)\n", p->va); continue; }
        if (!known) {
            fprintf(stderr, "%s%#010x now=%#010x expect=%#010x (%s)\n",
                    g_force ? "warn: unexpected word " : "error: unexpected word ",
                    p->va, now, p->expect, p->module);
            mismatch++;
            if (!g_force) continue;
            if (mode == MODE_VERIFY) continue;
        }
        if (mode == MODE_VERIFY) continue;

        memcpy(buf + p->va, &p->replace, sizeof p->replace);
        applied++;
        if (g_verbose) printf("patch %-7s %#010x %#010x -> %#010x\n",
                              p->module, p->va, p->expect, p->replace);
    }

    if (mode == MODE_LIST) {
        printf("\n%d sites, %d unexpected%s\n", KOLSON_PATCH_COUNT, mismatch,
               mismatch ? " (other build? use --force)" : "");
        free(buf);
        return mismatch ? 3 : 0;
    }

    if (mode == MODE_VERIFY) {
        printf("%d unexpected word(s), %d site(s) already patched\n", mismatch, skipped);
        free(buf);
        return mismatch ? 3 : 0;
    }

    if (mismatch && !g_force) {
        fprintf(stderr, "kolson_unlock: %d site(s) did not match, nothing written "
                        "(use --force only if you know the build differs)\n", mismatch);
        free(buf);
        return 3;
    }

    spit(out, buf, size);
    printf("%s: patched %d site(s), %d already patched, %d unknown, %zu bytes\n",
           out, applied, skipped, mismatch, size);
    free(buf);
    return 0;
}
