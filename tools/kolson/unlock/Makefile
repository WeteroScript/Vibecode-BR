# kolson unlock - build + patch + verify
#
#   make                -> build/kolson_unlock (host) and, if an NDK is found,
#                          build/libkolson_unlock_rt.so (arm64-v8a)
#   make patch          -> build/libkolson.unlocked.so from ../../libkolson.so
#   make patch-klnc     -> build/libklnc.so: same patches, SONAME libklnc.so
#   make one            -> build/libkolson_patch.so: ONE library, patches in memory
#   make one-test       -> host proof that runtime patch == offline patch
#   make verify         -> audit the patched library
#   make clean
#
# Override paths:
#   make KOLSON_SO=/path/to/libkolson.so
#   make NDK=/opt/android-ndk-r26d      (or export ANDROID_NDK_HOME)

KOLSON_SO ?= ../../../libkolson.so
OUT       ?= build
CC        ?= cc
CFLAGS    ?= -O2 -Wall -Wextra -std=c11
PYTHON    ?= python3

NDK ?= $(if $(ANDROID_NDK_HOME),$(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT))
NDK_API    ?= 21
RT_TOOLCHAIN := $(NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin
RT_CC        := $(RT_TOOLCHAIN)/aarch64-linux-android$(NDK_API)-clang

PATCHED := $(OUT)/libkolson.unlocked.so
# Второй артефакт: те же патчи, но с уникальным SONAME. Нужен, когда оригинал
# libkolson.so мог быть загружен раньше нашей копии - иначе bionic схлопнет их
# по DT_SONAME и JNI_OnLoad патченной копии не выполнится.
PATCHED_KLNC := $(OUT)/libklnc.so
# Одна библиотека: сама грузит/находит libkolson.so и патчит её в памяти.
ONE       := $(OUT)/libkolson_patch.so
ONE_SRCS  := kolson_one.c kolson_patches.h kolson_stealth.c kolson_stealth.h

.PHONY: all patch patch-klnc one one-test stealth-test verify list rt clean

all: $(OUT)/kolson_unlock
	@if [ -n "$(NDK)" ] && [ -x "$(RT_CC)" ]; then \
		$(MAKE) rt; \
	else \
		echo "note: no NDK found (set NDK= or ANDROID_NDK_HOME) - skipping runtime shim"; \
	fi

$(OUT)/kolson_unlock: kolson_unlock.c kolson_patches.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -I. -o $@ kolson_unlock.c

rt: $(OUT)/libkolson_unlock_rt.so

$(OUT)/libkolson_unlock_rt.so: kolson_unlock_rt.c kolson_patches.h
	@mkdir -p $(OUT)
	$(RT_CC) -O2 -Wall -Wextra -std=gnu11 -fPIC -shared -I. \
		-Wl,-soname,libkolson_unlock_rt.so -o $@ kolson_unlock_rt.c -llog -ldl

# host-проверка самоконспирации обходчика (без устройства)
STEALTH_HOST := $(OUT)/host/libkolson_patch.so
STEALTH_TEST := $(OUT)/kolson_stealth_test

stealth-test: $(STEALTH_TEST) $(STEALTH_HOST)
	KOLSON_STEALTH_MARKS=libkolson_patch.so $(STEALTH_TEST) $(STEALTH_HOST) libkolson_patch

$(STEALTH_HOST): kolson_stealth.c kolson_stealth.h
	@mkdir -p $(OUT)/host
	$(CC) $(CFLAGS) -fPIC -shared -I. -o $@ kolson_stealth.c

$(STEALTH_TEST): kolson_stealth_test.c
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -I. -o $@ kolson_stealth_test.c -ldl

list: $(OUT)/kolson_unlock
	$(OUT)/kolson_unlock -i $(KOLSON_SO) --list

patch: $(PATCHED)

$(PATCHED): $(OUT)/kolson_unlock
	$(OUT)/kolson_unlock -i $(KOLSON_SO) -o $@ -v

patch-klnc: $(PATCHED_KLNC)

$(PATCHED_KLNC): $(OUT)/kolson_unlock
	$(OUT)/kolson_unlock -i $(KOLSON_SO) -o $@ -n libklnc.so -v

one: $(ONE)

$(ONE): $(ONE_SRCS)
	@mkdir -p $(OUT)
	@if [ -x "$(RT_CC)" ]; then \
		$(RT_CC) -O2 -Wall -Wextra -std=gnu11 -fPIC -shared -I. \
			-Wl,-soname,libkolson_patch.so -o $@ kolson_one.c kolson_stealth.c -llog -ldl; \
	else \
		echo "note: NDK toolchain not found (set NDK= or ANDROID_NDK_HOME) - cannot build $(ONE)"; \
		exit 1; \
	fi

# Хост-проверка: runtime-патч в памяти должен дать ровно тот же файл, что и
# offline-патчер. Собирается обычным cc, устройство не нужно.
one-test: $(OUT)/kolson_unlock_one_test $(PATCHED)
	$(OUT)/kolson_unlock_one_test $(KOLSON_SO) $(PATCHED) $(OUT)/one-dump.so
	@cmp $(OUT)/one-dump.so $(PATCHED) && echo "one-test: runtime patch == offline patch (byte-for-byte)"

$(OUT)/kolson_unlock_one_test: kolson_one.c kolson_one_test.c kolson_patches.h \
                               kolson_stealth.c kolson_stealth.h
	@mkdir -p $(OUT)
	$(CC) -O2 -Wall -Wextra -DKOLSON_HOST -I. -o $@ kolson_one.c kolson_stealth.c \
		kolson_one_test.c -ldl

verify: $(OUT)/kolson_unlock
	$(OUT)/kolson_unlock -i $(PATCHED) --verify
	$(PYTHON) kolson_verify.py $(KOLSON_SO) $(PATCHED)

clean:
	rm -rf $(OUT)
