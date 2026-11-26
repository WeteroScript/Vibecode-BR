#!/usr/bin/env python3
"""Собирает пейлоад «Library Loaded» и генерирует hello_blob.h.

Пейлоад кладётся в код-пещеру libkolson.so (нули с 0xa8f59, 1031 байт) и
вызывается детуром с JNI_OnLoad (0x3a8684): detour -> payload -> оригинал.

Сборка:
    .venv-re/bin/python tools/kolson/payload/build.py
"""
import os
import struct
import sys

import keystone as ks_mod

# --- адреса сборки 16.116.0 (8 609 952 B) ------------------------------------
CAVE_VA       = 0xA8F5C      # пещера выровнена по 4 (в .text, VA == файловый офсет)
CAVE_SIZE     = 1028
JNI_ONLOAD_VA = 0x3A8684     # paciasp; sub sp,sp,#0x80; ...
LOG_STUB      = 0x771690     # PLT: __android_log_print

# индексы JNI-таблицы (с учётом 4 зарезервированных слотов в jni.h)
J_FindClass              = 6
J_GetObjectClass         = 31
J_GetMethodID            = 33
J_GetStaticMethodID      = 117
J_CallStaticObjectMethod = 118
J_NewStringUTF           = 171
J_CallVoidMethod         = 61
J_ExceptionCheck         = 228
J_ExceptionClear         = 17
VM_GetEnv                = 6

ASM = r"""
// ----   JNI_OnLoad: x0 = JavaVM* -------------------------------------
detour:
    sub  sp, sp, #0x70
    stp  x0, x1, [sp, #0x00]
    stp  x2, x3, [sp, #0x10]
    stp  x4, x5, [sp, #0x20]
    stp  x6, x7, [sp, #0x30]
    stp  x8, x9, [sp, #0x40]
    stp  x10, x11, [sp, #0x50]
    str  x30, [sp, #0x60]
    adr  x8, detour
    movz x9, #0x8f5c
    movk x9, #0x000a, lsl #16
    sub  x8, x8, x9            // x8 =  
    mov  x0, x8
    ldr  x1, [sp]              // vm
    bl   payload
    ldr  x30, [sp, #0x60]
    ldp  x10, x11, [sp, #0x50]
    ldp  x8, x9, [sp, #0x40]
    ldp  x6, x7, [sp, #0x30]
    ldp  x4, x5, [sp, #0x20]
    ldp  x2, x3, [sp, #0x10]
    ldp  x0, x1, [sp, #0x00]
    add  sp, sp, #0x70
    .word 0xd503233f          // paciasp
    b    #0x3a8688            //   JNI_OnLoad

// ----  : toast "KOLSON: Library Loaded" ----------------------
// x0 =  , x1 = JavaVM*
payload:
    sub  sp, sp, #0x90
    stp  x29, x30, [sp, #0x70]
    stp  x19, x20, [sp, #0x60]
    stp  x21, x22, [sp, #0x50]
    stp  x23, x24, [sp, #0x40]
    mov  x23, x0
    mov  x19, x0
    mov  x20, x1
    mov  x21, xzr
    mov  x29, sp
    adr  x0, m_enter
    bl   log_helper
    // env = vm->GetEnv(vm, &env, 1.6)
    ldr  x8, [x20]
    ldr  x8, [x8, #48]         // VM_GetEnv=6 -> 6*8
    mov  x0, x20
    add  x1, sp, #0x20          // env out-param: free slot
    movz w2, #0x0006
    movk w2, #0x0001, lsl #16
    blr  x8
    cbnz w0, payload_done
    ldr  x21, [sp, #0x20]      // env
    cbz  x21, payload_done

    // Application
    mov  x0, x21
    adr  x1, s_activitythread
    bl   call_findclass
    cbnz x0, have_class
    adr  x0, m_noclass
    bl   log_helper
    b    payload_done
have_class:
    mov  x22, x0
    mov  x0, x21
    mov  x1, x22
    adr  x2, s_currentapp
    adr  x3, s_currentapp_sig
    bl   call_getstaticmid
    cbz  x0, payload_done
    mov  x1, x22
    mov  x2, x0
    mov  x0, x21
    bl   call_staticobj
    cbnz x0, have_app
    adr  x0, m_noapp
    bl   log_helper
    b    payload_done
have_app:
    mov  x22, x0               // Application*

    // Toast.makeText(app, "KOLSON: Library Loaded", 1)
    mov  x0, x21
    adr  x1, s_toast
    bl   call_findclass
    cbz  x0, payload_done
    mov  x19, x0
    mov  x0, x21
    mov  x1, x19
    adr  x2, s_maketext
    adr  x3, s_maketext_sig
    bl   call_getstaticmid
    cbz  x0, payload_done
    mov  x20, x0               // mid
    mov  x0, x21
    adr  x1, s_text
    bl   call_newstring
    cbz  x0, payload_done
    mov  x1, x19
    mov  x2, x20
    mov  x3, x22
    mov  x4, x0
    mov  w5, #1
    mov  x0, x21
    bl   call_staticobj_n
    cbz  x0, payload_done
    mov  x19, x0               // toast

    // toast.show()
    mov  x0, x21
    mov  x1, x19
    bl   call_getobjclass
    cbz  x0, payload_done
    mov  x1, x0
    mov  x0, x21
    adr  x2, s_show
    adr  x3, s_show_sig
    bl   call_getmid
    cbz  x0, payload_done
    mov  x1, x19
    mov  x2, x0
    mov  x0, x21
    bl   call_callvoid
    adr  x0, m_shown
    bl   log_helper

payload_done:
    //  JNI    -  ,  VM 
    cbz  x21, payload_exit
    ldr  x8, [x21]
    ldr  x8, [x8, #1824]       // ExceptionCheck = 228*8
    mov  x0, x21
    blr  x8
    cbz  w0, payload_exit
    ldr  x8, [x21]
    ldr  x8, [x8, #136]        // ExceptionClear = 17*8
    mov  x0, x21
    blr  x8
payload_exit:
    ldp  x23, x24, [sp, #0x40]
    ldp  x21, x22, [sp, #0x50]
    ldp  x19, x20, [sp, #0x60]
    ldp  x29, x30, [sp, #0x70]
    add  sp, sp, #0x90
    ret

// ----  JNI -----------------------------------------------------------
log_helper:
    mov  x3, x0
    mov  w0, #4
    adr  x1, s_tag
    adr  x2, s_fmt
    movz x9, #0x1690
    movk x9, #0x0077, lsl #16
    add  x9, x23, x9
    br   x9

call_findclass:                // (env, name) -> cls
    ldr  x8, [x0]
    ldr  x8, [x8, #48]         // 6*8
    br   x8

call_getstaticmid:             // (env, cls, name, sig) -> mid
    ldr  x8, [x0]
    ldr  x8, [x8, #904]        // GetStaticMethodID = 113*8
    br   x8

call_getmid:                   // (env, cls, name, sig) -> mid
    ldr  x8, [x0]
    ldr  x8, [x8, #264]        // 33*8
    br   x8

call_getobjclass:              // (env, obj) -> cls
    ldr  x8, [x0]
    ldr  x8, [x8, #248]        // 31*8
    br   x8

call_staticobj:                // (env, cls, mid) -> obj
    ldr  x8, [x0]
    ldr  x8, [x8, #1064]       // CallStaticObjectMethod = 133*8
    br   x8

call_staticobj_n:              // (env, cls, mid, a, b, c) -> obj
    ldr  x8, [x0]
    ldr  x8, [x8, #1064]       // CallStaticObjectMethod = 133*8
    br   x8

call_newstring:                // (env, utf) -> jstring
    ldr  x8, [x0]
    ldr  x8, [x8, #1336]       // NewStringUTF = 167*8
    br   x8

call_callvoid:                 // (env, obj, mid)
    ldr  x8, [x0]
    ldr  x8, [x8, #488]        // 61*8
    br   x8

// ----  ---------------------------------------------------------------
s_tag:             .asciz "KOLSON"
s_fmt:             .asciz "%s"
m_enter:           .asciz "payload: enter"
m_noclass:         .asciz "payload: ActivityThread not found"
m_noapp:           .asciz "payload: no application"
m_shown:           .asciz "payload: toast shown"
s_activitythread:  .asciz "android/app/ActivityThread"
s_currentapp:      .asciz "currentApplication"
s_currentapp_sig:  .asciz "()Landroid/app/Application;"
s_toast:           .asciz "android/widget/Toast"
s_maketext:        .asciz "makeText"
s_maketext_sig:    .asciz "(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;"
s_text:            .asciz "KOLSON: Library Loaded"
s_show:            .asciz "show"
s_show_sig:        .asciz "()V"
"""


def build():
    asm = ASM
    k = ks_mod.Ks(ks_mod.KS_ARCH_ARM64, ks_mod.KS_MODE_LITTLE_ENDIAN)
    code, _ = k.asm(asm, addr=CAVE_VA)
    # выравнивание до 4 байт
    if len(code) % 4:
        code += b"\0" * (4 - len(code) % 4)
    if len(code) > CAVE_SIZE:
        print("ПЕРЕПОЛНЕНИЕ пещеры: %d > %d байт" % (len(code), CAVE_SIZE))
        return 1
    # слово детура на входе JNI_OnLoad: paciasp -> b cave
    off = (CAVE_VA - JNI_ONLOAD_VA) // 4
    word = 0x14000000 | (off & 0x3FFFFFF)
    print("детур:  0x%08x  b 0x%x   (было 0xd503233f)" % (word, CAVE_VA))
    print("пейлоад: %d байт из %d доступных" % (len(code), CAVE_SIZE))
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hello_blob.h")
    with open(out, "w") as f:
        f.write("/* СГЕНЕРИРОВАНО tools/kolson/payload/build.py — не править вручную.\n"
                "   Пейлоад «Library Loaded» (toast) для сборки 16.116.0. */\n"
                "#ifndef KOLSON_HELLO_BLOB_H\n#define KOLSON_HELLO_BLOB_H\n\n"
                "#define KOLSON_HELLO_VA    0x%08Xu\n"
                "#define KOLSON_HELLO_HOOK  0x%08Xu\n"
                "#define KOLSON_HELLO_WORD  0x%08Xu\n"
                "#define KOLSON_HELLO_EXPECT 0xd503233fu\n"
                "#define KOLSON_HELLO_SIZE  %du\n\n"
                "static const unsigned char kKolsonHello[] = {\n" % (
                    CAVE_VA, JNI_ONLOAD_VA, word, len(code)))
        for i in range(0, len(code), 12):
            f.write("    " + " ".join("0x%02x," % b for b in code[i:i + 12]) + "\n")
        f.write("};\n\n#endif\n")
    print("записан", out)
    return 0


if __name__ == "__main__":
    sys.exit(build())
