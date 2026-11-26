# libkolson.so — patch layer: what it hooks in `libblackrussia-client.so`

Static analysis of the build in the repo (`sha256 bcadf08…`, build-id `37577df9…`, `JNI_OnLoad@@KOLSON_6`).
Everything below is recovered from code, not guessed: disassembly with capstone, relocs with pyelftools,
table walk + hand verification of each handler.

Two artifacts carry the whole picture:

- **`re/out/hooks.json`** — machine-readable manifest (18 fingerprints, 9 attributed handlers, 8 JNI natives).
  Regenerate with `tools/kolson/kolson_hooks.py`.
- **`tools/kolson/kscheck.py`** — live checker: reads that manifest and reports per-site
  "intact / already stubbed / drifted" against a running client (`/proc/<pid>/mem` or a gdb remote).

---

## 1. The install primitive

`sub_0x5908fc(void *target, void *handler, void **orig)` — argument order proven from the call sites
(site `0x212a8c`: `x0 = game_base + 0x17c6258`, `x1 = 0x21307c`, `x2 = &0x6ba120`; the handler stores `x2`'s
pointer back into the game's import slot, i.e. `x2` is the original).

```
0x5906f8  mprotect(page, 7)                 ; per-region, 8-byte aligned
0x590830  str  x21, [x8, #8]                ; slot+8 = handler VA  (literally the address)
0x590838  ldr  d0,  [x9, #0xd8]             ; .rodata 0x560d8 = {0x58000051, 0xD61F0220}
0x59083c  str  d0,  [x8]                    ; slot   = ldr x17,#8 ; br x17
0x590894  ... 0x14000000 | bfxi(...)        ; or b <trampoline> when the slot is outside +-128 MB
0x5932c8  cacheflush(..)                    ; log tag "A64_HOOK"
```

So the on-target patch is a 16-byte stub:

```
target+0:  0x58000051   ldr x17, #8
target+4:  0xD61F0220   br  x17
target+8:  <handler VA>
```

`target` is always `module_base + RVA`, resolved from `dl_iterate_phdr` matches on
`libblackrussia-client.so` (`sub_0x212e34`), with `libhoudini.so` / `libndk_translation.so` as the
"is this an x86-translated build" discriminator.

## 2. The pre-patch gate (what makes it version-safe)

`.rodata` `0x74180`, 18 entries × 24 bytes: `{u64 game_rva, u64 expected_bytes[0..7], u64 expected_bytes[8..15]}`.
Before patching, the loader compares **16 bytes** at `base+rva` against the stored pair:

```
0x2442b8  ldp  x9, x11, [x23, #8]!
0x2442bc  ldp  x10, x8,  [x8]
0x2442c0  eor  x9, x10, x9
0x2442c4  eor  x8, x8,  x11
0x2442c8  orr  x8, x9, x8
0x2442cc  cbnz x8, 0x244484          ; -> log "signature_mismatch", site left unpatched
```

Every entry starts either at a function prologue (`stp x29,x30,[sp,#-N]!` / `sub sp,sp,#N`) or at a
`b <x>` / `ldr` seed, so the RVAs are stable offsets from the start of the library. That table is the
cleanest fingerprint the client has — match it against any BR build to know whether the launcher
will accept that build.

## 3. The mapped hooks

9 of the 18 table entries have an attributed handler; the other 9 are gated by later checks in the same
routine (`sub_0x243efc`) and are installed on demand. `handler_logs` is what the handler itself prints,
so the names are the payload's own, not my labels.

| game RVA | fp# | expected first word | handler | what the handler does / logs |
|---|---|---|---|---|
| 0xaa48cc | 14 | `0xd10103ff` | — | gated, no attributed handler |
| 0xc2497c | 4 | `0xd10143ff` | — | gated |
| 0xc3b090 | 0 | `0xb4000141` | — | gated |
| 0xd579f4 | 5 | `0xa9ba7bfd` | — | gated |
| 0xd57f70 | 17 | `0xd101c3ff` | — | gated |
| 0xd90f04 | 6 | `0xf9400400` | — | gated (mid-function, `ldr x0,[x0,#8]`; `b` in word 2) |
| **0x13198b0** | 8 | `0xd100c3ff` | `0x245cd0` | **native auth getter** → forces RPC 67 mode=1 path (`join RPC=67 endpoint=%s:%u nickLength=%zu generation=%llu`) |
| **0x1319a08** | 3 | `0xa9be7bfd` | `0x245d90` | **custom home** → `Account / CurrentServer / Characters / CharactersCount / IsServerChangePossible`, refresh of Play + server picker |
| **0x131b524** | 9 | `0xd10143ff` | `0x245fbc` | auth chain, no strings (pure value/flag patch) |
| **0x131b778** | 2 | `0xd10183ff` | `0x245e1c` | auth chain → after `sub_0x248f8c` passes, writes `1` into `[sp+4]` and calls through the getter at `0x6bde68` |
| 0x131eae0 | 1 | `0x17ffeb96` | — | gated |
| 0x131ecec | 7 | `0xa9be7bfd` | — | gated |
| 0x1322d58 | 13 | `0xd10703ff` | — | gated |
| 0x1323c2c | 12 | `0xd10343ff` | — | gated |
| **0x13298f0** | 10 | `0xd10503ff` | `0x245678` | stale-preparation cleanup, returns `[flag] != 0` |
| **0x132bcec** | 11 | `0xa9bd7bfd` | `0x2460b0` | auth chain, no strings |
| **0x15d1d80** | 16 | `0xa9be7bfd` | `0x2454fc` | state reset when `[0x6bdf0] == 1` — "cancelled/stale preparation ignored" |
| 0x15d1d80 | 16 | same | `0x245678` | second install over the same site (installer dedupes by ctx) |
| **0x15d5ef4** | 15 | `0xa9ba7bfd` | `0x244948` | second stage of the same auth hook as fp#1 (`0x2448ec`) |

The three sites that fire with the same target `0x15d1d80` (`0x243f98`, `0x243fd0`, `0x244008`) all install
`0x2448ec`; the routine then re-checks `[0x6bde38]`-slot and bails to `inline_install_failed` if the
installer refused — that's the visible failure path when the client build doesn't match the fingerprints.

## 4. Weapon layer

- Trigger: the game reads `weapon.json` → handler `0x21307c` logs
  `read weapon.json: bytes=%zu stock=%d nativeStock=%d policy=%u reference=%02x%02x%02x%02x` (tag `KOLSON_WEAPON`).
- It only acts when the filename in the ring buffer is exactly `weapons.json` (length 11, `mov/movk`
  immediates `0x6577…` = `"we"`, `0x6f70…` = `"op"`, `…` → literal compare).
- `policy & 2` → it hands the game a **different** JSON: `mov w0,0x96c0 / malloc` then `memcpy`
  from `.rodata 0x680654` for `0x96b9` bytes = the embedded stock table
  (`re/out/stock_weapon.json`, 40 weapons: `UNARMED dmg 4.5`, `PISTOL dmg 9 / 17 rnd`,
  `M67 dmg 18 / 25`, `SHOTGUN_WILDS dmg 59`, `REVOLVER_OLDY dmg 39`, `CARABINE_WEREWOLF dmg 28 / range 115`).
- Setter it calls with the buffer: `call [0x6baad0 + game_base]`.
- Net effect: the client's own damage/ammo/spread table is replaced server-side-invisibly per launch,
  and `policy`/`nativeStock` decide whether the embedded copy or the user's edited `weapon.json` wins.

## 5. JNI surface (registered from `JNI_OnLoad`, table at `0x5e5e38`)

`JNI_OnLoad` (`0x29e3d0`) → `FindClass("com/blackhub/bronline/neizzir/KolsonCustomBridge")` at `0x6c6d38`,
then `RegisterNatives` with:

| native | signature | VA | Kotlin caller |
|---|---|---|---|
| `prepareGameStartupNative` | `()V` | 0x29faa8 | bootstrap |
| `nativeText` | `(JLjava/lang/String;[BZ)V` | 0x2c1ff4 | `KolsonCustomBridge.invokeSuspend` |
| `nativeValidate` | `(Ljava/lang/String;Ljava/lang/String;I)Ljava/lang/String;` | 0x2c2450 | `KolsonCustomBridge.create` |
| `nativeSnapshot` | `(Ljava/lang/String;J[B)V` | 0x2c2e5c | – (callback from native) |
| `nativeReserve` | `(J)I` | 0x2c3f64 | `access$nativePrepare` |
| `nativePrepare` | `(JLjava/lang/String;[B)Z` | 0x2c3f70 | `access$nativeDecide` |
| `nativeStatus` | `(J)Ljava/lang/String;` | 0x2c409c | `access$nativeReserve` |
| `nativeDecide` | `(JZ[B)V` | 0x2c45fc | `access$getTargets$p` |

Call graph confirms these are **not** the hooking path — they are the launcher↔native control channel
(custom menu state, text/media bridging). The hooking is all done from native init code, invisible to Java.

`KolsonSystemKeyboard` (`nativeActivity/nativeCancel/nativeGameFocus/nativeReady/nativeSubmit`) and
`SettingsDefaults.nativeNumber` are in the DEX but **not** registered by this `JNI_OnLoad` — they belong to
other modules (keyboard overlay / settings cache) loaded later, which is consistent with
`NativeLibraryLoader` pulling `.so` files from `Custom/modules/`.

## 6. Tools shipped

```
tools/kolson/kolson_hooks.py    # extractor, no hard-coded offsets except well-known table VAs (overridable)
tools/kolson/kscheck.py         # live integrity check against a running client
tools/kolson/hooks.example.json # output of the extractor on this build
```

Extractor:

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install pyelftools capstone
python3 tools/kolson/kolson_hooks.py libkolson.so -o out/
# -> out/hooks.json, out/stock_weapon.json
```

Live check (root or same-uid; or through a gdb stub):

```bash
python3 tools/kolson/kscheck.py out/hooks.json --pid $(pidof com.br.top)
python3 tools/kolson/kscheck.py out/hooks.json --backend gdb --serial emulator-5554
```

Output is one row per fingerprint: `intact` (matches expected 16 bytes), `stub` (already contains
`ldr x17,#8 / br x17`), plus the actual words. Exit 1 on drift, so it drops straight into a CI/watch loop:

```bash
while sleep 2; do python3 tools/kolson/kscheck.py out/hooks.json --pid $P --dump /tmp/k.json || \
  cp /proc/$P/mem /tmp/mem.$EPOCHSECONDS; done
```

## 7. Confirmed vs. open

Confirmed by bytes: install primitive and its stub encoding, `mprotect`/cacheflush flow, the 18-entry
fingerprint table layout, 16-byte compare and `signature_mismatch` path, all 9 handler VAs and their
strings, the JNINativeMethod table and class name pointer, the embedded weapon table and its length.

Open: which of the nine gated RVAs are *login/anti-cheat* vs. *UI* — they only install after later
conditionals in `sub_0x243efc` (`0x244264`…`0x2440a8`), and I'd need the matching
`libblackrussia-client.so` build to name the function each RVA lands in. Drop that `.so` in and the
same extractor gives you the hooked function's own prologue + callers.
