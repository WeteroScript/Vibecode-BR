/* Колсон: индикатор загрузки библиотеки (AArch64, freestanding, без libc).
   Вызывается из detour'а на JNI_OnLoad: hello(base, vm). */
typedef unsigned long u64;

typedef struct { void **f; } Env;

#define JNI(env, idx) ((*(void ***)(env))[idx])
typedef void *(*jfn)(void *, ...);
#define JF(env, idx)  ((jfn)JNI(env, idx))

#define J_FindClass              6
#define J_ExceptionClear         17
#define J_NewStringUTF           171
#define J_GetObjectClass         31
#define J_GetMethodID            33
#define J_GetFieldID             98
#define J_GetObjectField         99
#define J_GetStaticMethodID      117
#define J_CallStaticObjectMethod 118
#define J_CallObjectMethod       34
#define J_CallIntMethod          49
#define J_CallVoidMethod         61
#define J_ExceptionCheck         228

#define VM_GetEnv              6
#define VM_AttachCurrentThread 4

#define LOGI 4
#define LOGE 6

static void logmsg(u64 base, int prio, const char *msg) {
    void (*p)(int, const char *, const char *, ...) = (void *)(base + 0x771690);
    p(prio, "KOLSON", "%s", msg);
}

static int exc(Env *e) {
    if (((int (*)(Env *))JNI(e, J_ExceptionCheck))(e)) {
        ((void (*)(Env *))JNI(e, J_ExceptionClear))(e);
        return 1;
    }
    return 0;
}

static void *call(Env *e, int idx, ...) { return ((jfn)JNI(e, idx))(e, 0); }

/* ActivityThread.currentActivityThread().mActivities.valueAt(0).activity */
static void *get_activity(Env *e) {
    void *cls = JF(e, J_FindClass)(e, "android/app/ActivityThread");
    if (!cls || exc(e)) return 0;
    void *mid = JF(e, J_GetStaticMethodID)(e, cls, "currentActivityThread",
                                           "()Landroid/app/ActivityThread;");
    if (!mid || exc(e)) return 0;
    void *at = JF(e, J_CallStaticObjectMethod)(e, cls, mid);
    if (!at || exc(e)) return 0;
    void *fid = JF(e, J_GetFieldID)(e, cls, "mActivities", "Landroid/util/ArrayMap;");
    if (!fid || exc(e)) return 0;
    void *map = JF(e, J_GetObjectField)(e, at, fid);
    if (!map || exc(e)) return 0;
    void *mcls = JF(e, J_GetObjectClass)(e, map);
    void *m_size = JF(e, J_GetMethodID)(e, mcls, "size", "()I");
    void *m_at   = JF(e, J_GetMethodID)(e, mcls, "valueAt", "(I)Ljava/lang/Object;");
    if (!m_size || !m_at || exc(e)) return 0;
    int n = (int)(long)JF(e, J_CallIntMethod)(e, map, m_size);
    if (n <= 0) return 0;
    void *rec = JF(e, J_CallObjectMethod)(e, map, m_at, 0);
    if (!rec || exc(e)) return 0;
    void *rcls = JF(e, J_GetObjectClass)(e, rec);
    void *a_fid = JF(e, J_GetFieldID)(e, rcls, "activity", "Landroid/app/Activity;");
    if (!a_fid || exc(e)) return 0;
    void *act = JF(e, J_GetObjectField)(e, rec, a_fid);
    if (!act || exc(e)) return 0;
    return act;
}

static int show_dialog(Env *e, void *act, u64 base) {
    void *bl = JF(e, J_FindClass)(e, "android/app/AlertDialog$Builder");
    if (!bl || exc(e)) return 0;
    void *ctor  = JF(e, J_GetMethodID)(e, bl, "<init>", "(Landroid/content/Context;)V");
    void *title = JF(e, J_GetMethodID)(e, bl, "setTitle",
                        "(Ljava/lang/CharSequence;)Landroid/app/AlertDialog$Builder;");
    void *pos   = JF(e, J_GetMethodID)(e, bl, "setPositiveButton",
                        "(Ljava/lang/CharSequence;Landroid/content/DialogInterface$OnClickListener;)"
                        "Landroid/app/AlertDialog$Builder;");
    void *mk    = JF(e, J_GetMethodID)(e, bl, "create", "()Landroid/app/AlertDialog;");
    if (!ctor || !title || !pos || !mk || exc(e)) return 0;

    void *s_title = JF(e, J_NewStringUTF)(e, "Library Loaded");
    void *s_ok    = JF(e, J_NewStringUTF)(e, "Ok");
    void *b = JF(e, 28 /*NewObject*/)(e, bl, ctor, act);
    if (!b || exc(e)) return 0;
    JF(e, J_CallObjectMethod)(e, b, title, s_title);
    JF(e, J_CallObjectMethod)(e, b, pos, s_ok, (void *)0);
    void *dlg = JF(e, J_CallObjectMethod)(e, b, mk);
    if (!dlg || exc(e)) return 0;

    void *dcls = JF(e, J_GetObjectClass)(e, dlg);
    void *show = JF(e, J_GetMethodID)(e, dcls, "show", "()V");
    if (!show) return 0;
    JF(e, J_CallVoidMethod)(e, dlg, show);
    logmsg(base, LOGI, "Library Loaded: диалог показан");

    void *getb = JF(e, J_GetMethodID)(e, dcls, "getButton", "(I)Landroid/widget/Button;");
    if (getb && !exc(e)) {
        void *btn = JF(e, J_CallObjectMethod)(e, dlg, getb, (void *)(long)-1);
        if (btn && !exc(e)) {
            void *bcls = JF(e, J_GetObjectClass)(e, btn);
            void *bg = JF(e, J_GetMethodID)(e, bcls, "setBackgroundColor", "(I)V");
            void *tc = JF(e, J_GetMethodID)(e, bcls, "setTextColor", "(I)V");
            if (bg) JF(e, J_CallVoidMethod)(e, btn, bg, (void *)(long)0xFF43A047u);
            if (tc) JF(e, J_CallVoidMethod)(e, btn, tc, (void *)(long)0xFFFFFFFFu);
            exc(e);
            logmsg(base, LOGI, "кнопка Ok покрашена");
        }
    }
    exc(e);
    return 1;
}

static int show_toast(Env *e, u64 base) {
    void *cls = JF(e, J_FindClass)(e, "android/app/ActivityThread");
    if (!cls || exc(e)) return 0;
    void *mid = JF(e, J_GetStaticMethodID)(e, cls, "currentApplication",
                                           "()Landroid/app/Application;");
    if (!mid) return 0;
    void *app = JF(e, J_CallStaticObjectMethod)(e, cls, mid);
    if (!app || exc(e)) { logmsg(base, LOGE, "нет Application"); return 0; }
    void *t = JF(e, J_FindClass)(e, "android/widget/Toast");
    if (!t || exc(e)) return 0;
    void *mk = JF(e, J_GetStaticMethodID)(e, t, "makeText",
                    "(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;");
    void *txt = JF(e, J_NewStringUTF)(e, "KOLSON: Library Loaded");
    if (!mk || !txt || exc(e)) return 0;
    void *tt = JF(e, J_CallStaticObjectMethod)(e, t, mk, app, txt, (void *)(long)1);
    if (!tt || exc(e)) return 0;
    void *tcls = JF(e, J_GetObjectClass)(e, tt);
    void *show = JF(e, J_GetMethodID)(e, tcls, "show", "()V");
    if (!show) return 0;
    JF(e, J_CallVoidMethod)(e, tt, show);
    logmsg(base, LOGI, "тост показан");
    return 1;
}

int hello(u64 base, void *vm) {
    logmsg(base, LOGI, "пейлоад запущен");
    Env *e = 0;
    int (*get_env)(void *, Env **, int) = (void *)((*(void ***)vm)[VM_GetEnv]);
    if (get_env(vm, &e, 0x00010006) != 0 || !e) {
        int (*attach)(void *, Env **, void *) = (void *)((*(void ***)vm)[VM_AttachCurrentThread]);
        if (attach(vm, &e, 0) != 0 || !e) { logmsg(base, LOGE, "attach к VM не удался"); return 0; }
    }
    void *act = get_activity(e);
    if (act) {
        logmsg(base, LOGI, "Activity найдена");
        if (show_dialog(e, act, base)) return 1;
        logmsg(base, LOGE, "диалог не создался, пробую тост");
    } else {
        logmsg(base, LOGE, "Activity нет, пробую тост");
    }
    show_toast(e, base);
    return 1;
}
