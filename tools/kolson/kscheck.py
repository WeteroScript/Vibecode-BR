#!/usr/bin/env python3
"""
kscheck.py - live integrity checker for a running BR client with libkolson.so loaded.

Reads the hook manifest produced by kolson_hooks.py, resolves
libblackrussia-client.so + libkolson.so in the *target* process and reports:
  1. base addresses, module sizes, ELF build-id
  2. whether each fingerprint entry still holds the expected 16 bytes
     (== the payload will accept the patch / == it already got patched)
  3. whether each hooked site already contains the kolson stub
     (ldr x17,#8 ; br x17 ; .quad handler)
  4. whether any handler VA in libkolson sits inside an executable mapping

Two backends:
  --backend process      attach with ptrace-free /proc/<pid>/mem (needs same-uid or root)
  --backend gdb          drive gdb-multiarch/ndk-gdb with a manifest script (works with remote targets)

Examples:
  ./kscheck.py hooks.json --pid $(pidof com.br.top)
  ./kscheck.py hooks.json --pid 1234 --dump /tmp/kolson_state.json
  ./kscheck.py hooks.json --backend gdb --host 127.0.0.1 --port 5039 --serial emulator-5554

Exit code: 0 = nothing patched and all fingerprints intact, 1 = drift found.
"""
import argparse, json, os, re, struct, subprocess, sys, time

STUB0 = 0x58000051   # ldr x17, #8
STUB1 = 0xD61F0220   # br x17


# ---------------------------------------------------------------- /proc backend
class ProcMem:
    """Reads target memory through /proc/<pid>/mem; maps come from /proc/<pid>/maps."""

    def __init__(self, pid):
        self.pid = pid
        self.maps = self._maps()
        self.fd = os.open(f'/proc/{pid}/mem', os.O_RDONLY)

    def _maps(self):
        out = []
        with open(f'/proc/{self.pid}/maps') as f:
            for line in f:
                a, b, perms, off, dev, ino, path = re.match(
                    r'([0-9a-f]+)-([0-9a-f]+) (\S+) ([0-9a-f]+) (\S+) (\d+)\s*(.*)$', line.strip()).groups()
                out.append({'start': int(a, 16), 'end': int(b, 16), 'perms': perms,
                            'off': int(off, 16), 'path': path})
        return out

    def read(self, va, n):
        try:
            os.lseek(self.fd, va, os.SEEK_SET)
            return os.read(self.fd, n)
        except OSError:
            return b''

    def module(self, name):
        hits = [m for m in self.maps if m['path'].endswith(name) and m['off'] == 0]
        if not hits:
            return None
        base = hits[0]['start']
        end = max(m['end'] for m in self.maps if m['path'].endswith(name))
        return {'base': base, 'end': end, 'path': hits[0]['path']}

    def exec_contains(self, va):
        return any(m['start'] <= va < m['end'] and 'x' in m['perms'] for m in self.maps)

    def close(self):
        os.close(self.fd)


# ---------------------------------------------------------------- gdb backend
class GdbMem:
    def __init__(self, gdb, host, port, serial=None):
        self.gdb = gdb
        self.host = host
        self.port = port
        self.serial = serial
        self.maps = []
        self._probe()

    def _run(self, cmds):
        script = '\n'.join(cmds + ['quit']) + '\n'
        p = subprocess.run([self.gdb, '-q', '-batch', '-ex', 'set pagination off']
                           + self._connect_args() + sum([['-ex', c] for c in cmds], []),
                           capture_output=True, text=True, timeout=120)
        return p.stdout + p.stderr

    def _connect_args(self):
        if self.serial:
            return ['-ex', f'target remote {self.serial}']
        return ['-ex', f'target remote {self.host}:{self.port}']

    def _probe(self):
        out = self._run(['info proc mappings'])
        for line in out.splitlines():
            m = re.match(r'\s*(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\S+)\s*(.*)', line)
            if m:
                self.maps.append({'start': int(m.group(1), 16), 'end': int(m.group(2), 16),
                                  'off': int(m.group(4), 16), 'perms': 'r-xp', 'path': m.group(6).strip()})
        if not self.maps:
            raise SystemExit('gdb: no mappings - is the target running and the stub attached?')

    def module(self, name):
        hits = [m for m in self.maps if m['path'].endswith(name) and m['off'] == 0]
        if not hits:
            return None
        end = max(m['end'] for m in self.maps if m['path'].endswith(name))
        return {'base': hits[0]['start'], 'end': end, 'path': hits[0]['path']}

    def read(self, va, n):
        out = self._run([f'dump binary memory /tmp/.kread.bin {va:#x} {va + n:#x}'])
        try:
            return open('/tmp/.kread.bin', 'rb').read()
        except OSError:
            return b''

    def exec_contains(self, va):
        return any(m['start'] <= va < m['end'] for m in self.maps if '.so' in m['path'] or 'x' in m['perms'])

    def close(self):
        pass


def check(manifest, mem, dump=None):
    game = mem.module('libblackrussia-client.so')
    kol = mem.module('libkolson.so')
    if game is None:
        raise SystemExit('libblackrussia-client.so not mapped in the target')
    rep = {'pid_maps': len(mem.maps), 'game': game, 'kolson': kol,
           'fingerprints': [], 'stubs': [], 'handlers': []}
    drift = 0

    for h in manifest['hooks']:
        va = game['base'] + h['game_rva']
        got = mem.read(va, len(h['expected_words']) * 4)
        want = b''.join(struct.pack('<I', w) for w in h['expected_words'])[:len(got)] if got else b''
        intact = got[:16] == want[:16]
        words = list(struct.unpack_from('<4I', got, 0)) if len(got) >= 16 else []
        stubbed = len(words) >= 2 and words[0] == STUB0 and words[1] == STUB1
        rep['fingerprints'].append({'game_rva': h['game_rva'], 'va': va, 'intact': intact,
                                    'stubbed': stubbed, 'words': [hex(w) for w in words]})
        rep['stubs'].append({'game_rva': h['game_rva'], 'stubbed': stubbed})
        if not intact and not stubbed:
            drift += 1
        if stubbed:
            drift += 1

    if kol:
        for h in manifest['hooks']:
            hv = h.get('handler_va')
            if not hv:
                continue
            va = kol["base"] + hv
            rep['handlers'].append({'handler_va': hv, 'resolved': va,
                                    'executable': mem.exec_contains(va)})

    if dump:
        json.dump(rep, open(dump, 'w'), indent=1)

    print(f"game  base={game['base']:#x} end={game['end']:#x} size={game['end'] - game['base']:#x}")
    print(f"kolson {'base=%#x' % kol['base'] if kol else 'NOT LOADED'}")
    print()
    print(f"{'game_rva':>12} {'intact':>7} {'stub':>6}  words")
    for f in rep['fingerprints']:
        print(f"{f['game_rva']:#12x} {str(f['intact']):>7} {str(f['stubbed']):>6}  {' '.join(f['words'])}")
    if rep['handlers']:
        bad = [x for x in rep['handlers'] if not x['executable']]
        print(f"\nhandlers resolved: {len(rep['handlers'])}/{len(rep['handlers']) + len(bad)} executable")
    print(f"\ndrift entries: {drift}")
    return 0 if drift == 0 else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('manifest')
    ap.add_argument('--pid', type=int)
    ap.add_argument('--backend', choices=('process', 'gdb'), default='process')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=5039)
    ap.add_argument('--serial', help='adb serial, targets the on-device stub instead of tcp')
    ap.add_argument('--gdb', default=os.environ.get('GDB', 'gdb-multiarch'))
    ap.add_argument('--dump')
    a = ap.parse_args()

    manifest = json.load(open(a.manifest))
    if a.backend == 'process':
        if not a.pid:
            sys.exit('--pid required for the process backend')
        mem = ProcMem(a.pid)
    else:
        mem = GdbMem(a.gdb, a.host, a.port, a.serial)
    try:
        return check(manifest, mem, a.dump)
    finally:
        mem.close()


if __name__ == '__main__':
    sys.exit(main())
