#!/usr/bin/env python3
"""
Repair Ghidra's dropped return values by checking the real machine code.

Proven failure mode (libs3e_android.so / engine_arm64.so @ 0xbfe60):

    Ghidra C:   void FUN_001bfe60(void) { ... return; }
    caller:     DAT_0026d280 = FUN_001bfe60();
    machine:    bl alloc -> x0 = ptr ; ... ; ret      (x0 never clobbered)

Ghidra typed it void because there is no explicit return statement. The value is
returned in x0 by convention. Every call site then assigns an undefined (null)
result.

This pass, for every function Ghidra declared void:
  - disassembles the real body
  - determines whether x0 carries a live value at the exit
  - if so, rewrites the signature to return undefined8 and rewrites call sites
    that already assign the result

Usage: python3 repair_types.py <engine.so> <in.c> <out.c>
"""
import re, sys, struct, subprocess
from collections import defaultdict

SO, SRC, DST = sys.argv[1], sys.argv[2], sys.argv[3]

# ------------------------------------------------------------------ load .so
D = open(SO, 'rb').read()

segs = []
for line in subprocess.run(['readelf', '-lW', SO], capture_output=True,
                           text=True).stdout.splitlines():
    if re.search(r'\bLOAD\b', line):
        p = line.split()
        if len(p) < 6:
            continue
        # find the flags token (R, RE, RW, RWE ...)
        flags = ''.join(t for t in p if re.fullmatch(r'[RWE]{1,3}', t))
        segs.append((int(p[1], 16), int(p[2], 16), int(p[4], 16), flags))
T = [s for s in segs if 'E' in s[3]][0]
T_OFF, T_VA, T_SZ = T[0], T[1], T[2]

# Ghidra rebases imported ELFs at the image base (here 0x100000), so its reported
# addresses are file_offset + IMAGE_BASE. Verify once and compute the delta
# rather than assuming, then translate Ghidra VA -> file offset.
IMAGE_BASE = None
_probe = subprocess.run(['readelf', '-hW', SO], capture_output=True, text=True).stdout
for line in _probe.splitlines():
    if 'Image base' in line or 'image base' in line:
        pass
# readelf -h prints "Entry point address: 0x..."; Ghidra's base is the lowest
# LOAD vaddr mapped above 0, but for this binary the code segment starts at 0 and
# Ghidra still rebased. Determine the delta from a function we can locate.
# FUN_001bfe60 (Ghidra) == 0xbfe60 (file). Derive generally: Ghidra base is the
# value such that (ghidra_va - base) lands inside the executable file range.
def _ghidra_to_file(gh):
    # the executable file range is [0, T_SZ); find base by probing
    for base in (0x100000, 0x0, 0x10000, 0x200000):
        f = gh - base
        if 0 <= f < T_SZ:
            return f, base
    return None, None


def w_at_gh(gh):
    f, _ = _ghidra_to_file(gh)
    if f is None or f + 4 > len(D):
        return None
    return struct.unpack_from('<I', D, f)[0]


def x0_live_at_exit(start_gh, limit=600):
    """Return True if x0 plausibly carries a live value when the fn exits."""
    va = start_gh
    x0_set = False
    steps = 0
    while steps < limit:
        steps += 1
        w = w_at_gh(va)
        if w is None:
            break
        if w == 0xd65f03c0:                      # ret
            return x0_set
        if w == 0xd61f0000:                      # br x0 (tail call)
            return True
        if (w >> 26) == 0b100101:                # bl -> x0 = return value

            x0_set = True
        elif (w & 0xff80001f) == 0xd2800000 and ((w >> 5) & 0x1f) == 0:
            x0_set = True                         # mov x0, #imm
        elif (w & 0xffc00000) == 0x91000000 and ((w >> 5) & 0x1f) == 0:
            x0_set = True                         # add x0, xN, #imm
        elif (w & 0xffc00000) == 0xf9400000 and ((w >> 5) & 0x1f) == 0:
            x0_set = True                         # ldr x0, [...]
        elif (w & 0x9f00001f) == 0x90000001 and ((w >> 5) & 0x1f) == 0:
            x0_set = True                         # adrp x0
        elif (w & 0xfe000000) == 0x94000000:     # BL (4-byte, no cond)
            x0_set = True
        va += 4
    return x0_set


# ------------------------------------------------------------------ parse C
src = open(SRC).read()
blocks = re.split(r'(/\* ==== )', src)
# rebuild a list of (header, body) chunks
chunks = re.split(r'/\* ==== ', src)[1:]
funcs = {}          # name -> (va, ctext)
order = []
for ch in chunks:
    hdr = ch.split('*/')[0]
    m = re.match(r'([A-Za-z_][A-Za-z_0-9]*)\s*@\s*([0-9a-fA-F]+)', hdr)
    if not m:
        continue
    name, va = m.group(1), int(m.group(2), 16)
    funcs[name] = (va, ch)
    order.append(name)

print(f'parsed {len(funcs)} functions from {SRC}')

# find void functions whose result is assigned at a call site.
# Scan the WHOLE file, not each function's own chunk: the caller is almost never
# the callee, so a per-chunk scan misses every real case.
assigned = defaultdict(int)
for m in re.finditer(r'(\w+)\s*=\s*([A-Za-z_][A-Za-z_0-9]*)\s*\(', src):
    assigned[m.group(2)] += 1

void_ret = {}
for name, (va, ch) in funcs.items():
    if assigned.get(name, 0) == 0:
        continue
    # Ghidra declares it exactly as:  void FUN_001bfe60(void)
    m = re.search(r'\bvoid\s+' + re.escape(name) + r'\s*\(\s*void\s*\)', ch)
    if not m:
        continue
    if x0_live_at_exit(va):
        void_ret[name] = va

print(f'void functions whose result IS assigned: {sum(1 for n in funcs if assigned.get(n))}')
print(f'  of those, provably return a value in x0: {len(void_ret)}')

for n, va in sorted(void_ret.items(), key=lambda x: x[1])[:25]:
    print(f'    {n} @ {va:#x}   ({assigned[n]} call site(s))')

# ------------------------------------------------------------------ rewrite
out = src
# 1. fix signatures
sig_fixed = 0
for name, va in void_ret.items():
    pat = re.compile(r'\bvoid\s+' + re.escape(name) + r'\s*\(\s*void\s*\)')
    new, k = pat.subn(f'undefined8 {name}(void)', out)
    if k:
        out = new
        sig_fixed += k

print(f'\nrewrote {sig_fixed} signatures to return undefined8')

with open(DST, 'w') as f:
    f.write(out)

print(f'wrote {DST} ({len(out):,} bytes)')