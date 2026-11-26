# kolson — static + live tooling for the Kolson/NEIZZIR payload

Two scripts, one manifest. Built against the `libkolson.so` in the repo root
(`sha256 bcadf082…`, `JNI_OnLoad@@KOLSON_6`, NDK r25c).

## kolson_hooks.py — extractor

Walks `libkolson.so` and emits a manifest of everything the native side does to
`libblackrussia-client.so`:

* inline-hook installer VA (`0x5908fc`, `A64_HOOK`) and the 16-byte stub it writes
  (`ldr x17,#8 ; br x17 ; .quad handler`)
* the 18-entry expected-code table at `.rodata 0x74180` (`{rva, 16 bytes}`)
* per hook: game RVA, expected words, handler VA, strings the handler logs
* `JNINativeMethod[]` registered from `JNI_OnLoad`
* the embedded stock `weapon.json` table (40 weapons)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install pyelftools capstone
python3 kolson_hooks.py ../../libkolson.so -o out/
```

Overrides exist for the three table VAs, since a re-packed payload will move them:

```bash
python3 kolson_hooks.py new.so -o out/ --installer 0x5a1234 --fp-table 0x75000 --fp-end 0x75200 --jni-table 0x5f0000
```

Output:

```
out/hooks.json          # {installer_va, fingerprint_table_va, hooks[], natives[]}
out/stock_weapon.json   # the weapon table the hook restores/swaps
```

## kscheck.py — live integrity check

Consumes `hooks.json`, resolves both modules in the **target** process, and reports per site:

* `intact` — 16 bytes at `game_base+rva` equal the fingerprint (payload will patch / client is stock)
* `stub` — site already begins with `ldr x17,#8 ; br x17` (payload armed)
* words — what is actually there

```bash
# same-uid or root
python3 kscheck.py out/hooks.json --pid $(pidof com.br.top)

# through a gdb stub (lldb-server/gdbserver/adb)
python3 kscheck.py out/hooks.json --backend gdb --serial emulator-5554
python3 kscheck.py out/hooks.json --backend gdb --host 127.0.0.1 --port 5039

# machine-readable + exit code for watch loops
python3 kscheck.py out/hooks.json --pid $P --dump /tmp/kolson_state.json
echo $?   # 0 = clean, 1 = drift (patched site or changed code)
```

`hooks.example.json` is the extractor's output for the current build — use it directly if you don't
want to regenerate.

## Caveats

* RVAs are for the `libblackrussia-client.so` build this payload targets; the fingerprint words are
  what identifies that build. Unknown build → 16-byte compare fails → the payload itself refuses to
  install and logs `signature_mismatch`.
* `kscheck.py --backend process` needs `ptrace`-less read access (`/proc/<pid>/mem` is mode 0400 owner).
  On a non-root shell use the gdb backend.
* Nine of the eighteen table entries have no attributed handler in the static call graph: they are
  installed by later branches of `sub_0x243efc` and only fire at runtime. The checker still validates
  their fingerprints.
