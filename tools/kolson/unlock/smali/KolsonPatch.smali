# ---------------------------------------------------------------------------
# KolsonPatch.smali - Java-обёртка вокруг ОДНОЙ библиотеки libkolson_patch.so
# ---------------------------------------------------------------------------
# Куда положить: smali_classesN/com/klnc/native/KolsonPatch.smali
#
# Что происходит:
#   1) NativeLibraryLoader грузит штатную libkolson.so (её и оставляем!);
#   2) мы грузим libkolson_patch.so и патчим УЖЕ загруженную libkolson в памяти;
#   3) файлы в 1NEIZZIR/Modules и Custom/modules не нужны - сканер сторонних
#      модулей ничего не находит, sha256 libkolson.so остаётся оригинальным.
#
# Куда вставлять вызов: в NativeLibraryLoader$load$2.invokeSuspend после
# успешной загрузки (там же, где пишется "Loaded: "), либо в
# KolsonLibrary.loadKolsonLibrary() сразу после invoke-static loadLibrary("kolson").
#
#   invoke-static {}, Lcom/klnc/native/KolsonPatch;->apply()I
#   move-result v0
#
# Библиотеку положить как lib/arm64-v8a/libkolson_patch.so (или пушить в
# /data/local/tmp и звать KolsonPatch.applyFrom("/data/local/tmp")).
#
# Про SONAME: у патча свой SONAME (libkolson_patch.so), вторая копия игровой
# библиотеки не грузится вообще - конфликт имён, из-за которого раньше нужен
# был `-n libklnc.so`, здесь невозможен по построению.
# ---------------------------------------------------------------------------
.class public final Lcom/klnc/native/KolsonPatch;
.super Ljava/lang/Object;

.field private static final TAG:Ljava/lang/String; = "KolsonPatch"
.field private static loaded:Z

.method static constructor <clinit>()V
    .registers 1
    const/4 v0, 0x0
    sput-boolean v0, Lcom/klnc/native/KolsonPatch;->loaded:Z
    return-void
.end method

# ---------------------------------------------------------------------------
# Основной вход: загрузить нашу библиотеку (она сама найдёт/подгрузит
# libkolson.so и пропатчит её в памяти) и вернуть число применённых слов.
# ---------------------------------------------------------------------------
.method public static apply()I
    .registers 3
    invoke-static {}, Lcom/klnc/native/KolsonPatch;->loadNative()Z
    move-result v0
    if-nez v0, :fail

    :try_start
    invoke-static {}, Lcom/klnc/native/KolsonPatch;->nativeApply()I
    move-result v0
    :try_end
    .catch Ljava/lang/Throwable; {:try_start .. :try_end} :fail

    new-instance v1, Ljava/lang/StringBuilder;
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V
    const-string v2, "kolson patch applied, sites="
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v1
    const-string v2, "KolsonPatch"
    invoke-static {v2, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    return v0

    :fail
    const/4 v0, 0x0
    return v0
.end method

# То же, но с явным каталогом, где лежит libkolson.so (например /data/local/tmp).
.method public static applyFrom(Ljava/lang/String;)I
    .registers 3
    invoke-static {}, Lcom/klnc/native/KolsonPatch;->loadNative()Z
    move-result v0
    if-nez v0, :fail

    :try_start
    invoke-static {p0}, Lcom/klnc/native/KolsonPatch;->nativeApplyDir(Ljava/lang/String;)I
    move-result v0
    :try_end
    .catch Ljava/lang/Throwable; {:try_start .. :try_end} :fail
    return v0

    :fail
    const/4 v0, 0x0
    return v0
.end method

# ---------------------------------------------------------------------------
.method public static status()Ljava/lang/String;
    .registers 2
    invoke-static {}, Lcom/klnc/native/KolsonPatch;->loadNative()Z
    move-result v0
    if-nez v0, :fail

    :try_start
    invoke-static {}, Lcom/klnc/native/KolsonPatch;->nativeReport()Ljava/lang/String;
    move-result-object v0
    :try_end
    .catch Ljava/lang/Throwable; {:try_start .. :try_end} :fail
    return-object v0

    :fail
    const-string v0, "libkolson_patch.so not loaded"
    return-object v0
.end method

.method public static patchedCount()I
    .registers 1
    invoke-static {}, Lcom/klnc/native/KolsonPatch;->loadNative()Z
    move-result v0
    if-eqz v0, :zero

    :try_start
    invoke-static {}, Lcom/klnc/native/KolsonPatch;->nativePatched()I
    move-result v0
    return v0
    :try_end
    .catch Ljava/lang/Throwable; {:try_start .. :try_end} :zero

    :zero
    const/4 v0, 0x0
    return v0
.end method

# ---------------------------------------------------------------------------
.method private static declared-synchronized loadNative()Z
    .registers 2
    sget-boolean v0, Lcom/klnc/native/KolsonPatch;->loaded:Z
    if-eqz v0, :already

    :try_start
    const-string v0, "kolson_patch"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    const/4 v0, 0x1
    sput-boolean v0, Lcom/klnc/native/KolsonPatch;->loaded:Z
    return v0
    :try_end
    .catch Ljava/lang/Throwable; {:try_start .. :try_end} :catch_all

    :catch_all
    move-exception v1
    const-string v0, "KolsonPatch"
    const-string v1, "loadLibrary(kolson_patch) failed"
    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    const/4 v0, 0x0
    return v0

    :already
    const/4 v0, 0x1
    return v0
.end method

# --------------------------------------------------------------- natives
.method private static native nativeApply()I
.end method

.method private static native nativeApplyDir(Ljava/lang/String;)I
.end method

.method private static native nativePatched()I
.end method

.method private static native nativeFailed()I
.end method

.method private static native nativeReport()Ljava/lang/String;
.end method
