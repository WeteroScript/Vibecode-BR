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

/* AArch64 encodings used below */
#define KOLSON_I_RET            0xd65f03c0u  /* ret                */
#define KOLSON_I_MOV_W0_ZR      0x2a1f03e0u  /* mov w0, wzr        */
#define KOLSON_I_MOV_W8_ZR      0x2a1f03e8u  /* mov w8, wzr        */
#define KOLSON_I_MOV_W0_1       0x52800020u  /* mov w0, #1         */
#define KOLSON_I_NOP            0xd503201fu  /* nop                */
#define KOLSON_I_PACIASP        0xd503233fu  /* paciasp (entry tag) */

#define KOLSON_PATCHES(X)                                                           \
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

typedef struct {
    const char *module;
    unsigned    va;
    unsigned    expect;
    unsigned    replace;
} kolson_patch_t;

#define KOLSON_X(mod, va, exp, rep) { (mod), (va), (exp), (rep) },
static const kolson_patch_t kKolsonPatches[] = { KOLSON_PATCHES(KOLSON_X) };
#undef KOLSON_X

#define KOLSON_PATCH_COUNT ((int)(sizeof(kKolsonPatches) / sizeof(kKolsonPatches[0])))

#endif /* KOLSON_PATCHES_H */
