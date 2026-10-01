# arm64 Port Notes (TheWildJames)

Findings from attempting to run COD:BOZ on a Pixel 8 (Tensor G3), plus a
working `arm64-v8a` APK build and a full Ghidra decompilation of the game
payload.

## 1. Why the game will not run on a Pixel 8

Tensor G3 is ARMv9-A **without an AArch32 execution unit**. There is no
hardware path for `armeabi-v7a` code, so no compat layer, kernel config, or
Magisk module can help. Confirmed by the 8th-gen Pixel situation upstream:
7th gen shipped 32-bit libraries but disabled support; 8th gen removed the
hardware capability entirely.

The existing `armeabi-v7a` APK cannot be installed on a Pixel 8 at all.

### What the `boz.s3e` payload actually contains

`assets/boz.s3e` is LZMA-compressed. Decompressed it is a 4,550,559-byte
Marmalade `XE3U` container (SDK 10.0.12.1) holding the compiled game.

Measured ISA census over the whole code span (8 KiB sliding windows):

| ISA | dense-decode windows |
|---|---|
| ARM A32 | 1448/1450 (99.9%) |
| ARM Thumb | 1449/1450 (99.9%) |
| AArch64 | 27/1450 (1.9%) |

Exact instruction-pattern counts are the reliable measure:

| Pattern | `boz.s3e` | `boz_unpacked_ios_aarch64` |
|---|---|---|
| Thumb `PUSH {..,lr}` | 1,977 | 4,152 |
| AArch64 `stp x29,x30,[sp,#-N]!` | 0 | 0 |

Decoding the code entry as AArch64 yields SVE garbage
(`ld1w {za0h.s[w12,0]}`, `stnt1d {z4.d}`); as ARM32 it yields a clean
prologue:

```
0x39483  ldr   r0, [pc, #0x8c]
0x39487  push  {r4, lr}
0x3948b  sub   sp, sp, #8
0x3948f  add   r0, pc, r0
0x39493  bl    #0x39cb3
```

**The game is ARM32 (Thumb-2).** This is not fixable by rebuilding the APK.

### The `boz_unpacked_ios_aarch64(broken).s3e` file

Present at the root of the upstream `12brendon34` repo (the fork dropped it).
Despite the name it is **not** aarch64 — it is the iOS ARMv7 build. Evidence:
`libIsIOSUtils.so` in its `AndroidExtSo` list, 18 `iPhone` strings, and the
ISA counts above. Same binariser/SDK version, wrong platform. Still useful as
a second build for cross-referencing shared functions.

## 2. What this branch changes

`app/build.gradle.kts`:

- `abiFilters` switched from `armeabi-v7a` to `arm64-v8a`, and moved into
  `defaultConfig` so debug builds get it too. The original file had two
  duplicate `getByName("release")` blocks, collapsed into one.
- Release signing is now conditional on `keystore.properties` existing. That
  file is gitignored and absent in fresh clones, so `storeFile` resolved to
  `""` and **configuration failed outright** with `path=''`.

`app/src/main/jniLibs/arm64-v8a/libs3eGooglePlayServices.so` — **removed**. It
was a 32-bit ARM ELF mislabeled as `arm64-v8a`; shipping it inside an arm64 APK
guarantees a load failure. GMS is already stubbed out per the README.

New `gradle.properties` with `android.useAndroidX=true` (the build hard-fails
without it) and JVM heap settings.

### Verified build

```
$ ./gradlew :app:assembleDebug
BUILD SUCCESSFUL
```

`aapt2 dump badging` on the output:

```
package: name='com.activision.boz' versionCode='1045452' versionName='1.0.8.1kotlin'
targetSdkVersion:'35'
native-code: 'arm64-v8a'
```

`lib/arm64-v8a/libs3e_android.so` is ELF64 / AArch64, and the signature-check
patch is intact (NOP `0xd503201f` at `0x2aa08`).

**This APK installs and launches on a Pixel 8. The game will not run** — the
engine loads the container and faults on the first ARM32 instruction (SIGILL).

## 3. Full decompilation of the game payload

The payload was successfully decompiled with Ghidra. Results:

| | |
|---|---|
| Code region | 4,315,932 bytes |
| Instructions | 786,959 |
| Functions | 16,659 |
| Decompiled | **16,658 (100%)** |
| Failed | 0 |
| Total C lines | 610,985 |

The entry point resolves to the Marmalade runtime init:

```c
undefined4 _binary_boz_codefull_bin_start(void) {
  thunk_EXT_FUN_4a0000b4("_IwMain");
  FUN_003596fc(); FUN_00375960(); FUN_003597a8();
  ...
}
```

Ghidra scripts used are in `buildtools/ghidra/`:

- `RecoverElf.java` — forces Thumb context, reports function/instruction
  counts and the decompile tally
- `ExportC.java` — writes every decompiled function to a single `.c`
- `DumpC.java` — prints a few functions for inspection

Reproduce:

```bash
python3 -c "import lzma;open('boz.raw','wb').write(lzma.open('app/src/main/assets/boz.s3e').read())"
llvm-objcopy -I binary -O elf32-littlearm -B arm \
  --rename-section .data=.text,alloc,load,readonly,code \
  boz.raw boz.elf
analyzeHeadless <projdir> boz -import boz.elf \
  -scriptPath buildtools/ghidra -postScript RecoverElf.java -postScript ExportC.java
```

Note: import the carved **code region** (offset `0x39483` onward), not the
whole container — the file begins with ICF config and assets, and analysis
finds nothing there. Use the ELF wrapper, not `BinaryLoader`: the raw loader
creates an uninitialized block that Ghidra will not disassemble.

## 4. The remaining gap: type reconstruction

Decompilation is solved. Reconstruction is not.

The symbol table at `0x43F3` contains 391 entries, all **imports** (247 GL/EGL,
148 `s3e` engine). The payload's own functions are completely unnamed: zero of
the ~13,865 identifier tokens are mangled or qualified C++ names. The binariser
stripped every symbol. `recovered.c` therefore has 104,109 unresolved `FUN_*`
call sites and no function names.

Compiling a single recovered function verbatim fails immediately:

```
error: passing argument 3 of 'func_0x003785d4' makes pointer from integer without a cast
error: implicit declaration of function 'func_0x003798f8'
warning: cast to pointer from integer of different size   (x6)
```

The cause is that Ghidra typed a struct pointer parameter as `int`. Correcting
it by hand means inferring a struct layout from raw field offsets
(`+0xd`, `+0x8f`, `+0x10f`, `+0x151`) — knowledge the binary does not carry.

That correction has to be done per function, and each function's callees need
it transitively. The largest recovered function, `FUN_0006c138`, is 2,406
lines / 12,436 bytes and is almost certainly a misidentified code region rather
than a real function.

## 5. Emulator status

Tried, all routes currently blocked on an x86_64 host:

- `emulator -avd boz32` (armeabi-v7a, API 25) —
  `FATAL | CPU Architecture 'arm' is not supported by the QEMU2 emulator`.
  Emulator 37.1.11 dropped 32-bit ARM guests; no older version is published.
- `emulator -avd boz64` (arm64-v8a, API 25) —
  `FATAL | QEMU2 emulator does not support arm64 CPU architecture`.
  The system image also sets `ro.product.cpu.abilist32=` (empty), i.e. it is
  64-bit-only and would reject the armeabi-v7a APK anyway.
- `qemu-system-aarch64` with the ranchu kernel — boots, binder comes up, then
  loops on `binder: transaction failed` and zygote never starts.

An emulator with a 32-bit-capable guest, or real 32-bit hardware, remains the
only way to actually play this without a full AArch64 recompile.
