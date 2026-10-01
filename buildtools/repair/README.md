# Decompile → Repair → Recompile Pipeline

Tooling for turning the ARM32 `boz.s3e` payload and the `libs3e_android.so`
engine into C that can be corrected against the binary and recompiled for
AArch64.

## Why a repair pass is needed

Ghidra's decompiler drops return values for functions that return in `x0`
without an explicit `return` statement. The result is a function typed `void`
whose call sites assign an undefined — in practice null — value.

This is not hypothetical. Verified instance in `libs3e_android.so`:

```c
/* Ghidra output */
void FUN_001bfe60(void) {
  undefined8 *puVar1;
  puVar1 = (undefined8 *)FUN_001a9878(0x28, 1);
  puVar1[4] = 0;
  *puVar1 = 0x8000;
  ...
  return;
}

/* its only caller */
DAT_0026d280 = FUN_001bfe60();     /* assigns a void function */
```

The machine code is unambiguous:

```
0x0bfe88  bl   #0xa9878     ; x0 = alloc(0x28, 1)
0x0bfe8c  ldp  x4, x5, [x19]
0x0bfe98  str  x6, [x0, #0x20]
0x0bfe9c  stp  x4, x5, [x0]
0x0bfeac  ret               ; x0 never clobbered — it IS the return value
```

and the caller stores it:

```
0x086384  bl   #0xbfe60
0x086388  str  x0, [x19, #0x410]
```

So the engine returns a valid pointer. The `void` type is an artifact of the
decompilation, and every one of that function's 5 call sites silently reads a
null. `DAT_0026d280` is a mutex handle, so this alone can produce
`pthread_mutex_lock` on a null pointer.

## `repair_types.py`

For every function Ghidra declared `void` whose result is assigned somewhere,
the script disassembles the real body and decides whether `x0` carries a live
value at the exit. If so it rewrites the signature to return `undefined8`.

```bash
python3 buildtools/repair/repair_types.py <binary.so> <in.c> <out.c>
```

On `libs3e_android.so`:

```
parsed 3279 functions
void functions whose result IS assigned: 791
  of those, provably return a value in x0: 23
rewrote 29 signatures to return undefined8
```

`FUN_001bfe60` is correctly detected and its signature corrected.

### Address translation

Ghidra rebases imported ELFs at the image base, so its reported addresses are
`file_offset + 0x100000` for these binaries. The script resolves this by
probing candidate bases against the executable segment rather than assuming it.

### Known false positives

The heuristic flags any function that ends with `x0` set, which includes
tail-call wrappers whose result genuinely propagates:

```c
undefined8 FUN_001bc6d8(void) {
  FUN_001bfe20(DAT_00299f70);
  return;
}
```

That one is a tail call, so `void` is arguably correct. Treat the rewrite as a
**candidate list to review**, not a blind fix.

## Ghidra scripts

| Script | Purpose |
|---|---|
| `RecoverElf.java` | Force Thumb context, report function/instruction counts, decompile tally |
| `ExportEngine.java` | Decompile the ARM64 engine to a single `.c` |
| `ExportThumb.java` | Same for the ARM32 payload, with TMode forced to Thumb |
| `ExportC.java` | Generic full export |
| `DumpC.java` | Print a few functions for inspection |

Reproduce the payload export:

```bash
# decompress and carve the code region (offset 0x39483, not the whole container)
python3 -c "import lzma;open('boz.raw','wb').write(lzma.open('app/src/main/assets/boz.s3e').read())"
llvm-objcopy -I binary -O elf32-littlearm -B arm \
  --rename-section .data=.text,alloc,load,readonly,code \
  <slice> boz_payload.elf

analyzeHeadless <projdir> projTHUMB -import boz_payload.elf \
  -scriptPath buildtools/ghidra -postScript ExportThumb.java

python3 buildtools/repair/repair_types.py boz_payload.elf payload_thumb.c payload_fixed.c
```

Two gotchas that cost time:

- Import the **carved code region**, not the whole container. The file starts
  with ICF config and assets; analysis finds nothing there.
- Use the **ELF wrapper**, not `BinaryLoader`. The raw loader creates an
  uninitialized memory block that Ghidra will not disassemble.

## Current state

| Target | Functions | Exported | Repaired |
|---|---|---|---|
| `libs3e_android.so` (ARM64) | 3,533 | 150,715 C lines | 29 signatures |
| `boz.s3e` payload (ARM32 Thumb) | 16,658 | 610,985 C lines | pending |

The pipeline detects and fixes a class of provable decompiler errors. It does
**not** reconstruct struct layouts, infer types from usage, or recover function
names — the binariser stripped every symbol, so `recovered.c` has 104,109
unresolved `FUN_*` call sites and no names. Those remain manual work.