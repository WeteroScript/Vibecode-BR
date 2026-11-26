/*
 * kolson_patches.h - single source of truth for every anti-tamper / anti-debug
 * kill-switch inside libkolson.so (KOLSON_6, AArch64, 6 956 216 bytes).
 *
 * Each entry is ONE 32-bit instruction word:
 *
 *      X(module, va, expect, replace)
 *
 *   module   grouping tag, also the --modules selector
 *   va       link-time virtual address of the word (.text: VA == file offset)
 *   expect   the word found in the reference build - hard integrity gate,
 *            a build with a different word is refused, never blindly patched
 *   replace  word written instead
 *
 * What gets neutralised:
 *
 *   core   0x166c54  protection checker  -> mov w0,wzr ; ret   (flags = 0)
 *          0x166c74  its inner collector (inside the same function)
 *   tracer 0x170528  inotify tracer-watch spawner -> mov w0,wzr ; ret
 *          0x170638  watch thread body          -> mov w0,wzr ; ret
 *   weapon 0x2129cc  weapon_tamper cached flag -> always 0
 *          0x212b60  digest check #1 (weapons-JSON pointer)   -> fall through
 *          0x212b94  digest check #2 (weapon table pointer)  -> fall through
 *
 * Note on the weapon path: 0x2129cc is only a getter (two callers, both read
 * it into the flag accumulator).  The install-vs-abort decision that actually
 * matters is the pair at 0x212b60 / 0x212b94 - cbnz to the abort label - so
 * those are neutralised too, and the whole KOLSON_WEAPON handler completes
 * instead of leaving 0x6ba118/0x6ba120 half-initialised.
 *   gate   0x243bb4  "is the game lib ours"    -> return 1 (ok)
 *   sig    0x244278..0x2443dc  18-RVA fingerprint table + 5 identity
 *                    constants in 0x243efc -> all b.ne/tbz/cbnz nop'd,
 *                    so every check falls through into the success path
 *          0x244800  command/digest reader   -> return 1 (ok)
 *   crash  0x5244f8  crash handler installer  -> mov w0,wzr ; ret
 *          0x524640  sigaction/sigprocmask block -> mov w0,wzr ; ret
 */
#ifndef KOLSON_PATCHES_H
#define KOLSON_PATCHES_H

#include <stddef.h>
#include <string.h>

#include "../payload/hello_blob.h"

/* AArch64 encodings used below */
#define KOLSON_I_RET            0xd65f03c0u  /* ret                */
#define KOLSON_I_MOV_W0_ZR      0x2a1f03e0u  /* mov w0, wzr        */
#define KOLSON_I_MOV_W8_ZR      0x2a1f03e8u  /* mov w8, wzr        */
#define KOLSON_I_MOV_W0_1       0x52800020u  /* mov w0, #1         */
#define KOLSON_I_NOP            0xd503201fu  /* nop                */
#define KOLSON_I_PACIASP        0xd503233fu  /* paciasp (entry tag) */

#define KOLSON_PATCHES_A(X)                                                           \
    /* ---- core: the whole protection checker ---------------------------------- */\
    X("core",   0x0166c54u, KOLSON_I_PACIASP,   KOLSON_I_MOV_W0_ZR)                 \
    X("core",   0x0166c58u, 0xa9ba7bfdu,        KOLSON_I_RET)                       \
    /* ---- tracer: inotify watch on /proc (tracer detection) -------------------- */\
    X("tracer", 0x0170528u, KOLSON_I_PACIASP,   KOLSON_I_MOV_W0_ZR)                 \
    X("tracer", 0x017052cu, 0xd10103ffu,        KOLSON_I_RET)                       \
    X("tracer", 0x0170638u, KOLSON_I_PACIASP,   KOLSON_I_MOV_W0_ZR)                 \
    X("tracer", 0x017063cu, 0xa9ba7bfdu,        KOLSON_I_RET)                       \
    /* ---- weapon: weapon_tamper flag ------------------------------------------- */\
    X("weapon", 0x02129ccu, 0xb9411100u,        KOLSON_I_MOV_W0_ZR)                 \
    X("weapon", 0x0212b60u, 0xb5fff628u,        KOLSON_I_NOP)   /* cbnz -> abort     */\
    X("weapon", 0x0212b94u, 0xb5fff488u,        KOLSON_I_NOP)   /* cbnz -> abort     */\
    /* ---- gate: "client lib present / ours" ------------------------------------ */\
    X("gate",   0x0243bb4u, KOLSON_I_PACIASP,   KOLSON_I_MOV_W0_1)                  \
    X("gate",   0x0243bb8u, 0xd10343ffu,        KOLSON_I_RET)                       \
    X("gate",   0x0244800u, KOLSON_I_PACIASP,   KOLSON_I_MOV_W0_1)                  \
    X("gate",   0x0244804u, 0xd10283ffu,        KOLSON_I_RET)                       \
    /* ---- sig: 18 x {rva,e0,e1} fingerprint table + identity constants ---------- */\
    X("sig",    0x0244278u, 0x36000c60u,        KOLSON_I_NOP)   /* tbz -> mismatch  */\
    X("sig",    0x02442acu, 0x36000ec0u,        KOLSON_I_NOP)   /* tbz -> mismatch  */\
    X("sig",    0x02442ccu, 0xb5000dc8u,        KOLSON_I_NOP)   /* cbnz -> mismatch */\
    X("sig",    0x0244388u, 0x54000d41u,        KOLSON_I_NOP)   /* b.ne -> mismatch */\
    X("sig",    0x02443a4u, 0x54000c61u,        KOLSON_I_NOP)   /* b.ne -> mismatch */\
    X("sig",    0x02443b8u, 0x54000bc1u,        KOLSON_I_NOP)   /* b.ne -> mismatch */\
    X("sig",    0x02443c8u, 0x54000b41u,        KOLSON_I_NOP)   /* b.ne -> mismatch */\
    X("sig",    0x02443dcu, 0x54000aa1u,        KOLSON_I_NOP)   /* b.ne -> mismatch */\
    /* ---- crash: signal handler installation and the dumping block -------------- */\
    X("crash",  0x05244f8u, KOLSON_I_PACIASP,   KOLSON_I_MOV_W0_ZR)                 \
    X("crash",  0x05244fcu, 0xa9bd7bfdu,        KOLSON_I_RET)                       \
    X("crash",  0x0524640u, KOLSON_I_PACIASP,   KOLSON_I_MOV_W0_ZR)                 \
    X("crash",  0x0524644u, 0xd10203ffu,        KOLSON_I_RET)

/* ------------------------------------------------------------------------- *
 * сборка 16.116.0 (8 609 952 Б, sha256 9e9fae28…): функции переписаны, старые
 * адреса недействительны. Найдено заново по якорям-строкам:
 *
 *   build_mismatch / signature_mismatch / command_unreadable / command_mismatch
 *   + login_hooks:ready  -> одна функция проверки команд/подписи входа,
 *   рядом с 0x2fca24..0x2fcdc0. Проверок там 10: пять «tbz w0,#0» (результат
 *   сверки через bl 0x2fd094) и пять «b.ne» (сверка указателей с эталонами в
 *   образе). Все ведут в ветки отказа, успешная ветка (0x2fcc84) ставит хуки.
 *
 *   nop на каждой проверке -> исполнение идёт в успешную ветку, хуки ставятся,
 *   ровно как в сборке KOLSON_6.
 * ------------------------------------------------------------------------- */
#define KOLSON_PATCHES_B(X)                                                       \
    X("auth", 0x02fcba4u, 0x36000c20u, KOLSON_I_NOP)  /* tbz w0,#0 -> unread.  */ \
    X("auth", 0x02fcbc4u, 0x36000b20u, KOLSON_I_NOP)                            \
    X("auth", 0x02fcbe0u, 0x36000a40u, KOLSON_I_NOP)                            \
    X("auth", 0x02fcbf4u, 0x360009a0u, KOLSON_I_NOP)                            \
    X("auth", 0x02fcc10u, 0x360008c0u, KOLSON_I_NOP)                            \
    X("auth", 0x02fcc2cu, 0x54000c81u, KOLSON_I_NOP)  /* b.ne -> build_mismatch */ \
    X("auth", 0x02fcc48u, 0x54000ba1u, KOLSON_I_NOP)                            \
    X("auth", 0x02fcc5cu, 0x54000b01u, KOLSON_I_NOP)                            \
    X("auth", 0x02fcc6cu, 0x54000a81u, KOLSON_I_NOP)                            \
    X("auth", 0x02fcc80u, 0x540009e1u, KOLSON_I_NOP)                            \
    /* weapon: флаг "weapon_tamper" — геттер 0x2c927c (bti; adrp; ldr w0,[x8,#0xed0]; ret),
       оба его вызывающих (0x1f26a4, 0x1f4f34) решают, включать ли политику оружия */ \
    X("weapon", 0x02c9284u, 0xb94ed100u, KOLSON_I_MOV_W0_ZR)                       \
    /* ---- dm: гейт самой записи сервера в 0x29bdb0 (загрузчик списка) ---------- */ \
    /* cmp entry.minimumBuildId, 2026080701 (0x78c389bd) -> слишком новый билд    */ \
    X("dm",     0x029c794u, 0x54000a08u, KOLSON_I_NOP)   /* b.hi -> отбраковка     */ \
    /* cmp featureMask, #0x40 */                                                   \
    X("dm",     0x029c79cu, 0x540009c8u, KOLSON_I_NOP)   /* b.hi -> отбраковка     */ \
    /* диапазон low-32 от build id */                                              \
    X("dm",     0x029c7bcu, 0x540008c3u, KOLSON_I_NOP)   /* b.lo -> отбраковка     */ \
    /* cmp entry.expiresAt, time(NULL) */                                          \
    X("dm",     0x029c7c4u, 0x5400088du, KOLSON_I_NOP)   /* b.le -> отбраковка     */ \
    /* ---- blob: проверка целостности вкомпилированного списка серверов --------- */ \
    /* 0x1fcbac(key @0x7cedc, tag @0x7ce9c, json @0x7cc9a, 0x202): истина всегда  */ \
    X("blob",   0x01fcbacu, KOLSON_I_PACIASP, KOLSON_I_MOV_W0_1)                   \
    X("blob",   0x01fcbb0u, 0xa9ba7bfdu,      KOLSON_I_RET)                        \
    /* ---- hello: детур JNI_OnLoad -> пейлоад в код-пещере 0xa8f5c --------------- */ \
    /* при загрузке библиотеки показываем "Library Loaded" (пейлоад собирает     */ \
    /* tools/kolson/payload/build.py, байты - в ../payload/hello_blob.h)         */ \
    X("hello",  KOLSON_HELLO_HOOK, KOLSON_HELLO_EXPECT, KOLSON_HELLO_WORD)

typedef struct {
    const char *module;
    unsigned    va;
    unsigned    expect;
    unsigned    replace;
} kolson_patch_t;

#define KOLSON_X(mod, va, exp, rep) { (mod), (va), (exp), (rep) },
static const kolson_patch_t kKolsonSitesA[] = { KOLSON_PATCHES_A(KOLSON_X) };
static const kolson_patch_t kKolsonSitesB[] = { KOLSON_PATCHES_B(KOLSON_X) };
#undef KOLSON_X

/* Блобы - куски кода/данных, которые надо записать целиком (не одно слово).
   Регион должен быть нулевым в оригинале (проверяется) - иначе не пишем. */
typedef struct {
    const char          *name;
    unsigned             va;
    const unsigned char *data;
    unsigned             len;
} kolson_blob_t;

static const kolson_blob_t kKolsonBlobsA[] = { { 0, 0, 0, 0 } };
static const kolson_blob_t kKolsonBlobsB[] = {
    { "hello", KOLSON_HELLO_VA, kKolsonHello, KOLSON_HELLO_SIZE },
};

#define KOLSON_N(a) ((int)(sizeof(a) / sizeof((a)[0])))

/* Сборка узнаётся по одному слову в характерном месте: ни один сайт не
   применяется к чужой сборке, а таблицы могут сосуществовать. */
typedef struct {
    const char *name;
    unsigned    probe_va;
    unsigned    probe_expect;
    const kolson_patch_t *sites;
    int         count;
    const kolson_blob_t  *blobs;
    int         nblobs;
} kolson_build_t;

static const kolson_build_t kKolsonBuilds[] = {
    /* probe - слово, которое мы НЕ патчим: иначе повторный прогон на уже
       пропатченном образе не узнает сборку */
    { "KOLSON_6 (6 956 216 B)",  0x0166c60u, 0x910003fdu, kKolsonSitesA, KOLSON_N(kKolsonSitesA),
      kKolsonBlobsA, KOLSON_N(kKolsonBlobsA) },
    { "16.116.0 (8 609 952 B)",  0x02fcc84u, 0x2a1f03f3u, kKolsonSitesB, KOLSON_N(kKolsonSitesB),
      kKolsonBlobsB, KOLSON_N(kKolsonBlobsB) },
};
#define KOLSON_BUILD_COUNT KOLSON_N(kKolsonBuilds)

static inline int kolson_detect_build(const void *img, size_t size) {
    for (int i = 0; i < KOLSON_BUILD_COUNT; i++) {
        const kolson_build_t *b = &kKolsonBuilds[i];
        if ((size_t)b->probe_va + sizeof(unsigned) > size) continue;
        unsigned w = 0;
        memcpy(&w, (const unsigned char *)img + b->probe_va, sizeof w);
        if (w == b->probe_expect) return i;
    }
    return -1;
}

/* обратная совместимость для старого кода/скриптов */
#define kKolsonPatches      kKolsonSitesA
#define KOLSON_PATCH_COUNT  KOLSON_N(kKolsonSitesA)

#endif /* KOLSON_PATCHES_H */
