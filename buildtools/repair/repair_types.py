#!/usr/bin/env python3
"""
Repair Ghidra's dropped return values by checking the real machine code.

Proven failure mode (libs3e_android.so / engine_arm64.so @ 0xbfe60):

    Ghidra C:   void FUN_001bfe60(void) { ... return; }
    caller:     DAT_0026d280 = FUN_001bfe60();
    machine:    bl alloc -> x0 = ptr ; ... ; ret      (x0 never clobbered)

Ghidra typed it void because there is no explicit return statement; the value
comes back in x0 by convention. Every call site then assigns an undefined
(null) result, which is how a mutex handle becomes a null pointer.

For every function Ghidra declared void whose result is assigned somewhere,
this pass disassembles the real body, decides whether the return register is
live at the exit, and rewrites the signature to return a value.

Works on both ARM64 (libs3e_android.so) and ARM32 Thumb-2 (boz.s3e payload);
the ISA is auto-detected from the ELF header.

Usage: python3 repair_types.py <binary> <in.c> <out.c>
"""
import re, sys, struct, subprocess
from collections import defaultdict

SO, SRC, DST = sys.argv[1], sys.argv[2], sys.argv[3]
D = open(SO, 'rb').read()

# ------------------------------------------------------------------ ELF info
hdr = subprocess.run(['readelf', '-hW', SO], capture_output=True, text=True).stdout
machine = ''
for line in hdr.splitlines():
    if 'Machine:' in line:
        machine = line.split(':', 1)[1].strip()
IS_ARM64 = 'AArch64' in machine
print(f'binary : {SO}')
print(f'machine : {machine}  -> {"AArch64" if IS_ARM64 else "ARM32"}')

# ------------------------------------------------------------------ segments
segs = []
for line in subprocess.run(['readelf', '-lW', SO], capture_output=True,
                           text=True).stdout.splitlines():
    if re.search(r'\bLOAD\b', line):
        p = line.split()
        if len(p) < 6:
            continue
        flags = ''.join(t for t in p if re.fullmatch(r'[RWE]{1,3}', t))
        segs.append((int(p[1], 16), int(p[2], 16), int(p[4], 16), flags))
exec_segs = [s for s in segs if 'E' in s[3]]
if not exec_segs:
    # objcopy-produced ELFs (arm32 wrappers) have NO program headers at all --
    # only sections. Fall back to the .text section.
    sec = subprocess.run(['readelf', '-SW', SO], capture_output=True, text=True).stdout
    for line in sec.splitlines():
        if ' .text ' not in line:
            continue
        p = line.split()
        # Column positions shift depending on whether a section-index column is
        # present, so locate the fields by value rather than fixed index:
        #   [Nr] Name Type Addr Off Size ES Flg ...
        try:
            i_type = p.index('PROGBITS')
        except ValueError:
            continue
        addr = int(p[i_type + 1], 16)
        off = int(p[i_type + 2], 16)
        size = int(p[i_type + 3], 16)
        print(f'no LOAD segments; using .text addr={addr:#x} off={off:#x} size={size:#x}')
        exec_segs = [(off, addr, size, 'RE')]
        break
if not exec_segs:
    sys.exit('ERROR: no executable LOAD segment or .text section found')
T_OFF, T_VA, T_SZ = exec_segs[0][0], exec_segs[0][1], exec_segs[0][2]
print(f'exec seg: off={T_OFF:#x} va={T_VA:#x} size={T_SZ:#x}')

# Ghidra rebases imported ELFs at the image base, so its reported addresses are
# file_offset + BASE. Derive BASE by probing candidates instead of assuming it --
# it differs between a real .so and an objcopy ELF wrapper.
CANDIDATE_BASES = (0x100000, 0x0, 0x10000, 0x200000, 0x1000)


def _to_file(gh):
    for base in CANDIDATE_BASES:
        f = gh - base
        if 0 <= f < T_SZ and f + 4 <= len(D):
            return f
    return None


def w_at(gh):
    f = _to_file(gh)
    return None if f is None else struct.unpack_from('<I', D, f)[0]


# ------------------------------------------------------------------ ISA scan
if IS_ARM64:
    def x0_live_at_exit(start_gh, limit=600):
        va = start_gh
        live = False
        for _ in range(limit):
            w = w_at(va)
            if w is None:
                break
            if w == 0xd65f03c0:                  # ret
                return live
            if w == 0xd61f0000:                  # br x0 (tail call)
                return True
            rd = (w >> 5) & 0x1f
            if (w >> 26) == 0b100101:             # BL
                live = True
            elif (w & 0xfe000000) == 0x94000000:  # BL (32-bit form)
                live = True
            elif rd == 0 and (
                    (w & 0xff80001f) == 0xd2800000 or   # mov x0, #imm
                    (w & 0xffc00000) == 0x91000000 or   # add x0, xN, #imm
                    (w & 0xffc00000) == 0xf9400000 or   # ldr x0, [...]
                    (w & 0x9f00001f) == 0x90000001):    # adrp x0
                live = True
            va += 4
        return live
else:
    # Thumb is variable-width (16 or 32 bit), so a 4-byte linear walk reads
    # garbage. Decode properly.
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    except ImportError:
        sys.exit('ERROR: ARM32 mode needs capstone (pip install capstone)')
    _md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    _md.skipdata = True

    def x0_live_at_exit(start_gh, limit=600):
        f = _to_file(start_gh)
        if f is None:
            return False
        r0 = False
        for i in _md.disasm(D[f:f + limit * 4], start_gh):
            m = i.mnemonic
            if m == 'ret':
                return r0
            if m == 'bx' and i.op_str.strip() == 'lr':
                return r0
            if m in ('bl', 'blx'):
                r0 = True
            elif m in ('mov', 'movs', 'movw') and i.op_str.split(',')[0].strip() == 'r0':
                r0 = True
            elif m == 'ldr' and i.op_str.split(',')[0].strip() == 'r0':
                r0 = True
            elif m == 'pop' and 'pc' in i.op_str:
                return r0
        return r0


# ------------------------------------------------------------------ parse C
src = open(SRC).read()
chunks = re.split(r'/\* ==== ', src)[1:]
funcs = {}
for ch in chunks:
    h = ch.split('*/')[0]
    m = re.match(r'([A-Za-z_][A-Za-z_0-9]*)\s*@\s*([0-9a-fA-F]+)', h)
    if m:
        funcs[m.group(1)] = (int(m.group(2), 16), ch)

print(f'parsed {len(funcs)} functions from {SRC}')

# Scan the WHOLE file: the caller is almost never the callee, so a per-chunk
# scan misses every real case.
assigned = defaultdict(int)
for m in re.finditer(r'(\w+)\s*=\s*([A-Za-z_][A-Za-z_0-9]*)\s*\(', src):
    assigned[m.group(2)] += 1

void_ret = {}
for name, (va, ch) in funcs.items():
    if assigned.get(name, 0) == 0:
        continue
    if not re.search(r'\bvoid\s+' + re.escape(name) + r'\s*\(\s*void\s*\)', ch):
        continue
    if x0_live_at_exit(va):
        void_ret[name] = va

cands = sum(1 for n in funcs if assigned.get(n))
print(f'void functions whose result IS assigned: {cands}')
print(f'  of those, provably return a value:     {len(void_ret)}')
for n, va in sorted(void_ret.items(), key=lambda x: x[1])[:30]:
    print(f'    {n} @ {va:#x}  ({assigned[n]} call site(s))')

out = src
fixed = 0
for name in void_ret:
    out, k = re.subn(r'\bvoid\s+' + re.escape(name) + r'\s*\(\s*void\s*\)',
                     f'undefined8 {name}(void)', out)
    fixed += k
print(f'\nrewrote {fixed} signatures to return undefined8')
open(DST, 'w').write(out)
print(f'wrote {DST} ({len(out):,} bytes)')