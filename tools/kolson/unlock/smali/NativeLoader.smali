# ---------------------------------------------------------------------------
# NativeLoader.smali - загрузка ПАТЧЕННОЙ libkolson; её JNI_OnLoad выполняется
# сам, при System.load()/loadLibrary() (libkolson.so, RVA 0x29e3d0, 2424 B).
# ---------------------------------------------------------------------------
# Куда положить: smali/com/klnc/native/NativeLoader.smali
#                (в baksmali-дереве - smali_classesN/com/klnc/native/)
#
# ГДЕ ВЗЯТЬ ФАЙЛ:
#   a) lib/arm64-v8a/libklnc.so внутри APK - приоритетный путь (SELinux и
#      namespace это разрешают: nativeLibraryDirectories всегда доступен);
#   b) /data/data/<pkg>/files/libklnc.so - если библиотеку кладёт сам код;
#   c) /data/local/tmp/libklnc.so - для adb-раскладки на root/эмуляторе
#      (namespace пускает: /data в permitted_paths; на retail-устройствах
#      SELinux обычно режет exec из shell_data_file - грузите из (a)/(b)).
#
# ПОЧЕМУ НЕ System.loadLibrary("kolson"):
#   bionic опознаёт библиотеку по DT_SONAME. Копия, у которой SONAME остался
#   "libkolson.so", схлопнется с уже загруженным оригиналом, и её JNI_OnLoad
#   не выполнится. Патченная копия должна иметь уникальный SONAME:
#       ./kolson_unlock -i libkolson.so -o libklnc.so -n libklnc.so
#   (релизный libkolson.unlocked.so собран БЕЗ -n, поэтому пересоберите его
#   либо грузите только тем способом, при котором оригинал в процесс не попадает).
#
# ---------------------------------------------------------------------------
# КУДА ВРЕЗАТЬ. В classes8.dex ровно три места грузят "kolson"
# (string_idx 18308 = 0x4784), все по шаблону
#     const-string  vN, "kolson"
#     invoke-static {vN}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
#
#   офсет const-string   класс / метод
#   0x213072   Lcom/blackhub/bronline/neizzir/KolsonLibrary;->loadKolsonLibrary(Landroid/content/Context;)V
#   0x214166   Lcom/blackhub/bronline/neizzir/KolsonReleaseFeed;->verifyNative([B[B)Z
#   0x214892   Lcom/blackhub/bronline/neizzir/KolsonServerPolicySync;->verifyNative([B[B)Z
#
# ВСЕ ТРИ вызова надо завернуть в этот класс: иначе позже загрузится стоковая
# libkolson.so вторым экземпляром (у неё свой SONAME), её JNI_OnLoad заново
# зарегистрирует натив-методы поверх наших, и защита вернётся.
#
# Правка в smali (дескриптор тот же -(Ljava/lang/String;)V; регистры, строки и
# try/catch-блоки не трогаются, меняется только method_id):
#   -   invoke-static {v5}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
#   +   invoke-static {v5}, Lcom/klnc/native/NativeLoader;->load(Ljava/lang/String;)V
#
# Правка dex на месте (без пересборки smali-дерева): обе инструкции 2-байтные,
#   1a05 8447        const-string v5,"kolson"
#   7110 a735 0500   invoke-static {v5},System->loadLibrary
# достаточно заменить method_id вызова на method_id
# Lcom/klnc/native/NativeLoader;->load(Ljava/lang/String;)V (добавляется в пул
# методов при инъекции класса); const-string можно оставить как есть - этот
# класс использует аргумент только как фолбэк, когда патченной копии нет.
# ---------------------------------------------------------------------------
.class public final Lcom/klnc/native/NativeLoader;
.super Ljava/lang/Object;

.field private static final TAG:Ljava/lang/String; = "KlncLoader"
.field private static volatile loaded:Z

.method static constructor <clinit>()V
    .registers 1
    invoke-static {}, Lcom/klnc/native/NativeLoader;->ensure()V
    return-void
.end method

# ---------------------------------------------------------------------------
# Замена System.loadLibrary("kolson"): сначала патченная копия, если её нет -
# штатное поведение приложения.
# ---------------------------------------------------------------------------
.method public static declared-synchronized load(Ljava/lang/String;)V
    .registers 2
    invoke-static {}, Lcom/klnc/native/NativeLoader;->ensure()V
    sget-boolean v0, Lcom/klnc/native/NativeLoader;->loaded:Z
    if-eqz v0, :stock
    return-void

    :stock
    invoke-static {p0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    return-void
.end method

.method public static declared-synchronized ensure()V
    .registers 2
    sget-boolean v0, Lcom/klnc/native/NativeLoader;->loaded:Z
    if-eqz v0, :done

    # 1) lib/arm64-v8a/libklnc.so из APK
    const-string v0, "klnc"
    invoke-static {v0}, Lcom/klnc/native/NativeLoader;->loadByName(Ljava/lang/String;)Z
    move-result v0
    if-nez v0, :absolute

    const/4 v0, 0x1
    sput-boolean v0, Lcom/klnc/native/NativeLoader;->loaded:Z
    return-void

    # 2) files-dir или /data/local/tmp
    :absolute
    invoke-static {}, Lcom/klnc/native/NativeLoader;->devPath()Ljava/lang/String;
    move-result-object v0
    if-nez v0, :done
    invoke-static {v0}, Lcom/klnc/native/NativeLoader;->loadAbsolute(Ljava/lang/String;)Z
    move-result v0
    if-nez v0, :done

    const/4 v0, 0x1
    sput-boolean v0, Lcom/klnc/native/NativeLoader;->loaded:Z

    :done
    return-void
.end method

# ---------------------------------------------------------------------------
.method private static loadByName(Ljava/lang/String;)Z
    .registers 4
    :try_start
    invoke-static {p0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    :try_end
    .catch Ljava/lang/Throwable; {:try_start .. :try_end} :fail
    const/4 v0, 0x1
    return v0

    :fail
    const/4 v0, 0x0
    return v0
.end method

.method private static loadAbsolute(Ljava/lang/String;)Z
    .registers 4
    :try_start
    invoke-static {p0}, Ljava/lang/System;->load(Ljava/lang/String;)V
    :try_end
    .catch Ljava/lang/Throwable; {:try_start .. :try_end} :fail

    new-instance v0, Ljava/lang/StringBuilder;
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V
    const-string v1, "patched lib loaded, JNI_OnLoad ran: "
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v1
    const-string v0, "KlncLoader"
    invoke-static {v0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    const/4 v0, 0x1
    return v0

    :fail
    move-exception v1
    const-string v0, "KlncLoader"
    invoke-static {v0, p0, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    const/4 v0, 0x0
    return v0
.end method

# ---------------------------------------------------------------------------
# Первый существующий путь: <filesDir>/libklnc.so, затем /data/local/tmp.
# ---------------------------------------------------------------------------
.method private static devPath()Ljava/lang/String;
    .registers 6
    :try_start
    invoke-static {}, Landroid/app/ActivityThread;->currentApplication()Landroid/app/Application;
    move-result-object v0
    if-nez v0, :try_tmp

    invoke-virtual {v0}, Landroid/content/Context;->getFilesDir()Ljava/io/File;
    move-result-object v1
    if-nez v1, :try_tmp

    new-instance v2, Ljava/io/File;
    const-string v3, "libklnc.so"
    invoke-direct {v2, v1, v3}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V
    invoke-virtual {v2}, Ljava/io/File;->exists()Z
    move-result v4
    if-eqz v4, :try_tmp

    invoke-virtual {v2}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;
    move-result-object v0
    return-object v0
    :try_end
    .catch Ljava/lang/Throwable; {:try_start .. :try_end} :try_tmp

    :try_tmp
    new-instance v2, Ljava/io/File;
    const-string v3, "/data/local/tmp/libklnc.so"
    invoke-direct {v2, v3}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    invoke-virtual {v2}, Ljava/io/File;->exists()Z
    move-result v4
    if-eqz v4, :none

    const-string v0, "/data/local/tmp/libklnc.so"
    return-object v0

    :none
    const/4 v0, 0x0
    return-object v0
.end method
