[Proofmark_Complete_Writeup.md](https://github.com/user-attachments/files/30522513/Proofmark_Complete_Writeup.md)
# Proofmark CTF Challenge — Complete Solution Writeup

**Author:** Mohammed Ali  
**Challenge:** Proofmark (HTB)  
**Points:** 975  
**Difficulty:** Medium  
**Flag:** `HTB{p3rf3ct_f4c3_tru3_sp1n3}`

---

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Initial Reconnaissance](#initial-reconnaissance)
3. [Reverse Engineering the APK](#reverse-engineering-the-apk)
4. [Disassembling the Native Library](#disassembling-the-native-library)
5. [Cryptographic Analysis](#cryptographic-analysis)
6. [The Attack](#the-attack)
7. [Exploitation](#exploitation)
8. [Complete Solver Code](#complete-solver-code)
9. [Flag Extraction](#flag-extraction)

---

## Challenge Overview

Proofmark is a thematic reverse-engineering challenge wrapped in narrative:

> *"Vaultrune's assay decides which seals are inherited and which were cut from a Signet shard. Elric Ashspar walks in with a ring he filed himself. If the anvil calls his work inherited, it cannot tell the difference, and neither can anyone else. One strike, no second."*

### What We're Solving

The player must forge a cryptographic "certificate" by providing a valid `(state, hallmark)` pair to a native Godot GDExtension library. The real logic is obfuscated inside a tiny ARM64 `.so` file implementing a custom bytecode VM.

### The Mechanics

1. A Godot 4 game maintains three "wards" (0–24 each)
2. These auto-sync a `hallmark` value via hashing
3. Player interacts at the Anvil, calling `ForgeClient.strike(state, hallmark)`
4. This invokes native `Proofmark.submit()` which:
   - Validates the state (requires exact magic numbers)
   - Runs 1.2M-round PRNG avalanche
   - XOR-decrypts a 28-byte ciphertext
   - Returns the plaintext flag if validation passes

---

## Initial Reconnaissance

### Step 1: Extract the APK

```bash
unzip -o proofmark.apk -d extracted/
cd extracted
find . -type f | head -20
```

**Key findings:**
- Android package with embedded Godot 4 game
- Native ARM64 library: `lib/arm64-v8a/libproofmark.arm64.so` (9.8 KB)
- Compiled GDScript bytecode: `assets/scripts/*.gdc` (zstd compressed)
- Game assets: `assets.sparsepck`, `assets/ui/`, `assets/scenes/`

### Step 2: Understand the Game Logic

Install [GDRE Tools](https://github.com/GDRETools/gdsdecomp) to decompile the GDScript:

```bash
wget https://github.com/GDRETools/gdsdecomp/releases/download/v2.4.0/GDRE_tools-v2.4.0-linux.zip
unzip -o GDRE_tools-v2.4.0-linux.zip -d gdre_tools

./gdre_tools/gdre_tools.x86_64 --headless --bytecode=4.5.0-stable \
  --decompile=extracted/assets/scripts/*.gdc --output=decompiled_src
```

### Step 3: Analyze the Decompiled Scripts

**GameState.gd:**
```gdscript
var wards: PackedInt32Array = PackedInt32Array([0, 0, 0])  # Three wards, 0-24 each
var hallmark: int = 0  # Auto-synced via reseal()
var struck: bool = false

func _ready():
    _resync_hallmark()

func file_ward(index: int, delta: int):
    wards[index] = clampi(wards[index] + delta, 0, 24)
    _resync_hallmark()

func _resync_hallmark():
    var bite = wards[0] + 2 * wards[1] + 3 * wards[2]
    hallmark = ForgeClient.reseal(PackedByteArray([
        wards[0], wards[1], wards[2], bite
    ]))
```

**ForgeClient.gd:**
```gdscript
func reseal(state: PackedByteArray) -> int:
    if _native == null:
        return 0
    return _native.reseal(state.decode_s32(0), state.decode_s32(4), 
        state.decode_s32(8), state.decode_s32(12)) & 0xffffffff

func strike(state: PackedByteArray, hallmark: int) -> Array:
    var v = _native.submit(state.decode_s32(0), state.decode_s32(4), 
        state.decode_s32(8), state.decode_s32(12), hallmark)
    var cert = _native.certificate() if v == ACCEPTED else ""
    return [v, cert]
```

**HUD.gd (strike interaction):**
```gdscript
func _strike():
    var result = ForgeClient.strike(GameState.snapshot(), GameState.hallmark)
    if result[0] == ForgeClient.Verdict.ACCEPTED:
        print("FLAG: " + result[1])  # Certificate = flag!
```

**Key Insight:** The game tries to protect by auto-syncing hallmark with state, but we can forge both independently by calling the native library directly.

---

## Reverse Engineering the APK

### Step 4: Extract and Parse the Native Library

```bash
cd extracted/lib/arm64-v8a
readelf -S libproofmark.arm64.so
```

**Section Layout:**
- `.text`: 0x1a94, size 0x11c8 (executable code)
- `.rodata`: 0x500, size 0x210 (read-only data, includes ciphertext)
- `.dynsym`, `.dynstr`: symbol tables

**Key constants in `.rodata`:**
```
2a53db7ba35d34f55f59745e0043881ca1136fb7f8d73f79c1b0af1a
↑ This is the 28-byte ciphertext we need to decrypt
```

### Step 5: Disassemble with Capstone

```python
import capstone
data = open('libproofmark.arm64.so','rb').read()

# .text section
text_offset = 0x00000a94
text_vaddr = 0x1a94
text_size = 0x11c8

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
code = data[text_offset:text_offset+text_size]

for instr in md.disasm(code, text_vaddr):
    print(f"{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
```

---

## Disassembling the Native Library

### Step 6: Identify Key Functions

Disassembling reveals three critical functions:

**Function 1: `0x1af4` — reseal() core**
- Takes: buffer pointer, length
- Returns: 32-bit hallmark hash

**Function 2: `0x1ff4` — submit() validator & decryptor**
- Takes: buffer pointer, length, hallmark, self_ptr, constant
- Performs state validation, PRNG stretch, cipher decryption
- Returns: verdict (0=REJECT_STATE, 1=REJECT_TOKEN, 2=ACCEPTED)

**Function 3: `0x28ec`, `0x29ac`, `0x2b10` — Wrapper glue**
- Marshal GDScript ints into 16-byte buffers
- Call the above two functions

### Step 7: Analyze submit() in Detail

Disassembly of `0x1ff4` reveals the attack surface:

```asm
1ff4:  cmp w1, #0x10          ; Check length == 16
1ff8:  b.ne #0x201c          ; If not, return REJECT_STATE (0)

1ffc:  ldp x8, x9, [x0]       ; Load first 8 bytes: wards[0] & wards[1]
2000:  mov x10, #0x53         
2004:  movk x10, #0x43, lsl #32  ; x10 = 0x0000004300000053 (67 << 32 | 83)
2008:  cmp x8, x10            ; Compare (83, 67) pair

200c:  mov x8, #0x37
2010:  movk x8, #0x1ce, lsl #32  ; x8 = 0x00000001ce00000037 (462 << 32 | 55)
2014:  ccmp x9, x8, #0, eq    ; Compare (55, 462) pair

2018:  b.eq #0x2024           ; If all match, proceed to crypto
201c:  mov w0, wzr            ; Else return 0
2020:  ret
```

**Critical discovery:** The code requires exact values:
- `wards[0] = 83`
- `wards[1] = 67`
- `wards[2] = 55`
- `wards[3] = 462` (the fourth parameter)

**These are impossible to reach via gameplay** (wards are clamped 0-24). This is intentional: you must forge directly.

### Step 8: Analyze the Crypto Logic

After state validation passes:

```asm
2024:  mov w8, #0xae35
2028:  mov w9, #0xca6b
202c:  mov w10, #0x4f80
2030:  movk w8, #0xc2b2, lsl #16     ; C1 = 0xc2b2ae35
2034:  movk w9, #0x85eb, lsl #16     ; C2 = 0x85ebca6b
2038:  movk w10, #0x12, lsl #16      ; Loop count high bits

2040:  add w11, w2, w8                ; Start PRNG with hallmark + C1
203c:  subs w10, w10, #1              ; Decrement loop counter
2044-2058: XOR-shift, multiply cycles (Murmur3-style avalanche)
2058:  b.ne #0x203c                   ; Loop until done
```

Loop counter = `0x124f80` = **1,200,000 iterations**!

---

## Cryptographic Analysis

### Step 9: Reverse the PRNG Algorithm

The embedded constants are from Murmur3:
```python
C1 = 0xc2b2ae35
C2 = 0x85ebca6b
```

**Single PRNG round:**
```python
def ROUND(x):
    MASK = 0xffffffff
    t = (x + C1) & MASK
    t ^= (t >> 16)           # XOR-shift
    t = (t * C2) & MASK
    t ^= (t >> 13)           # XOR-shift
    e = (t * C1) & MASK
    out = e ^ (e >> 16)      # Final XOR-shift
    return out & MASK
```

After 1,200,000 rounds, one final `fmix32`:
```python
def fmix32(h):
    h ^= (h >> 16)
    h = (h * C2) & 0xffffffff
    h ^= (h >> 13)
    h = (h * C1) & 0xffffffff
    h ^= (h >> 16)
    return h & 0xffffffff
```

**Keystream generation:**
```python
def keystream(w13_0, length=28):
    state = w13_0
    for i in range(length):
        nxt, e = round_step(state)
        ks_byte = (e >> 24) & 0xff  # Extract top byte
        yield ks_byte
        state = nxt
```

### Step 10: Extract Embedded Ciphertext

```python
cipher_hex = "2a53db7ba35d34f55f59745e0043881ca1136fb7f8d73f79c1b0af1a"
cipher = bytes.fromhex(cipher_hex)  # 28 bytes
```

**Known plaintext attack:** We know first 4 bytes are `"HTB{"`:
```python
PLAIN_PREFIX = b"HTB{"
req_keystream = [cipher[i] ^ PLAIN_PREFIX[i] for i in range(4)]
# = [0x62, 0x07, 0x99, 0x00]
```

---

## The Attack

### Step 11: Why Forward Brute-Force Fails

**Direct brute-force is infeasible:**
- `hallmark` is 32-bit (~4.3 billion candidates)
- Each candidate requires 1.2M PRNG rounds
- Total: 4.3B × 1.2M = **~5 × 10^15 operations** (impossible in reasonable time)

### Step 12: Breakthrough Insight

Instead of brute-forcing the initial hallmark, brute-force the **intermediate state** `w13_0` *after* the 1.2M-round stretch but *before* the final `fmix32`.

**Why this works:**
1. `w13_0` only needs to produce correct keystream for 4 bytes (HTB{)
2. Strong filtering: ~256K → ~234 → 0 → 0 (at byte 3, only ~1-2 survive)
3. Full 32-bit space searchable in **~75 seconds** with vectorized NumPy

---

## Exploitation

### Step 13: Vectorized Brute-Force

```python
import numpy as np
import time

C1 = np.uint32(0xc2b2ae35)
C2 = np.uint32(0x85ebca6b)

def round_step(x):
    t = x + C1
    t = t ^ (t >> np.uint32(16))
    t = t * C2
    t = t ^ (t >> np.uint32(13))
    e = t * C1
    out = e ^ (e >> np.uint32(16))
    return out, e

cipher = bytes.fromhex("2a53db7ba35d34f55f59745e0043881ca1136fb7f8d73f79c1b0af1a")
req_bytes = np.array([cipher[i] ^ b"HTB{"[i] for i in range(4)], dtype=np.uint8)

print("[*] Searching for w13_0 producing keystream: HTB{")
print(f"[*] Required keystream bytes: {[hex(int(x)) for x in req_bytes]}")

CHUNK = 1 << 24  # Process ~16.7M per chunk
total = 1 << 32
found_candidates = []

t0 = time.time()
for base in range(0, total, CHUNK):
    # Generate candidates
    state = (base + np.arange(CHUNK, dtype=np.int64)).astype(np.uint32)
    ids = state.copy()
    
    # Filter by first 4 keystream bytes
    for i in range(4):
        out, e = round_step(state)
        byte_i = ((e >> np.uint32(24)) & np.uint32(0xff)).astype(np.uint8)
        mask = (byte_i == req_bytes[i])
        
        if not mask.any():
            ids = ids[mask]
            break
        
        ids = ids[mask]
        state = out[mask]
    
    if ids.size > 0:
        found_candidates.extend(ids.tolist())
    
    if (base // CHUNK) % 16 == 0:
        elapsed = time.time() - t0
        pct = (base + CHUNK) / total * 100
        print(f"[+] {pct:5.1f}% | {elapsed:6.1f}s | Candidates: {len(found_candidates)}")

print(f"\n[✓] Found {len(found_candidates)} candidate(s) in {time.time()-t0:.1f}s")
for cand in found_candidates:
    print(f"    {cand} (0x{cand:08x})")
```

**Output:**
```
[*] Searching for w13_0 producing keystream: HTB{
[*] Required keystream bytes: ['0x62', '0x7', '0x99', '0x0']
[+]   0.0% |    0.0s | Candidates: 0
[+]  12.5% |    1.9s | Candidates: 0
[+]  25.0% |    7.8s | Candidates: 0
[+]  37.5% |   12.6s | Candidates: 1
[+]  50.0% |   17.4s | Candidates: 1
...continuing...
[✓] Found 2 candidate(s) in 75.3s
    477923728 (0x1c94e7d0)
    735249060 (0x2bc006e4)
```

### Step 14: Decode Each Candidate

```python
def round_step_scalar(x):
    MASK = 0xffffffff
    t = (x + 0xc2b2ae35) & MASK
    t ^= (t >> 16)
    t = (t * 0x85ebca6b) & MASK
    t ^= (t >> 13)
    e = (t * 0xc2b2ae35) & MASK
    out = e ^ (e >> 16)
    return out & MASK, e & MASK

def decode(w13_0):
    state = w13_0
    plaintext = bytearray()
    for i in range(28):
        nxt, e = round_step_scalar(state)
        ks_byte = (e >> 24) & 0xff
        plaintext.append(cipher[i] ^ ks_byte)
        state = nxt
    return bytes(plaintext)

for w13_0 in found_candidates:
    plaintext = decode(w13_0)
    print(f"w13_0 = {w13_0}: {plaintext}")
```

**Output:**
```
w13_0 = 477923728: b'HTB{p3rf3ct_f4c3_tru3_sp1n3}'  ✓ VALID!
w13_0 = 735249060: b'HTB{\x03c\xf8\x99y\xdcZw\xe6\x8a\xa4\xd3\x96\xe79\xd0c...'  ✗ Garbage
```

---

## Complete Solver Code

### All-in-One Solver (solve.py)

```python
#!/usr/bin/env python3
"""
Proofmark CTF Solver — Complete End-to-End Exploitation
Time: ~75 seconds | Flag: HTB{p3rf3ct_f4c3_tru3_sp1n3}
"""

import numpy as np
import time

# ============================================================================
# Constants
# ============================================================================

C1 = np.uint32(0xc2b2ae35)
C2 = np.uint32(0x85ebca6b)
CIPHER = bytes.fromhex("2a53db7ba35d34f55f59745e0043881ca1136fb7f8d73f79c1b0af1a")
PLAIN_PREFIX = b"HTB{"

# ============================================================================
# PRNG Functions
# ============================================================================

def round_step(x):
    """Single PRNG round (vectorized)"""
    t = x + C1
    t = t ^ (t >> np.uint32(16))
    t = t * C2
    t = t ^ (t >> np.uint32(13))
    e = t * C1
    out = e ^ (e >> np.uint32(16))
    return out, e

def round_step_scalar(x):
    """Single PRNG round (scalar)"""
    MASK = 0xffffffff
    t = (x + 0xc2b2ae35) & MASK
    t ^= (t >> 16)
    t = (t * 0x85ebca6b) & MASK
    t ^= (t >> 13)
    e = (t * 0xc2b2ae35) & MASK
    out = e ^ (e >> 16)
    return out & MASK, e & MASK

# ============================================================================
# Brute-Force
# ============================================================================

def brute_force():
    """Find w13_0 that produces required keystream"""
    print("[*] Brute-forcing intermediate keystream state...")
    
    req_bytes = np.array([CIPHER[i] ^ PLAIN_PREFIX[i] for i in range(4)], dtype=np.uint8)
    print(f"[*] Required keystream bytes: {[hex(int(x)) for x in req_bytes]}")
    
    CHUNK = 1 << 24
    total = 1 << 32
    candidates = []
    
    t0 = time.time()
    for base in range(0, total, CHUNK):
        state = (base + np.arange(CHUNK, dtype=np.int64)).astype(np.uint32)
        ids = state.copy()
        
        for i in range(4):
            out, e = round_step(state)
            byte_i = ((e >> np.uint32(24)) & np.uint32(0xff)).astype(np.uint8)
            mask = (byte_i == req_bytes[i])
            
            if not mask.any():
                ids = ids[mask]
                break
            
            ids = ids[mask]
            state = out[mask]
        
        if ids.size > 0:
            candidates.extend(ids.tolist())
        
        if (base // CHUNK) % 16 == 0:
            elapsed = time.time() - t0
            pct = (base + CHUNK) / total * 100
            print(f"[+] {pct:5.1f}% | {elapsed:6.1f}s | Candidates: {len(candidates)}")
    
    elapsed = time.time() - t0
    print(f"\n[✓] Found {len(candidates)} candidate(s) in {elapsed:.1f}s\n")
    return candidates

# ============================================================================
# Decryption
# ============================================================================

def decode(w13_0):
    """Decrypt ciphertext"""
    state = w13_0
    plaintext = bytearray()
    for i in range(28):
        nxt, e = round_step_scalar(state)
        ks_byte = (e >> 24) & 0xff
        plaintext.append(CIPHER[i] ^ ks_byte)
        state = nxt
    return bytes(plaintext)

# ============================================================================
# Main
# ============================================================================

def main():
    print("=" * 70)
    print(" Proofmark CTF Solver — Find the Flag")
    print("=" * 70)
    print()
    
    # Brute-force
    candidates = brute_force()
    
    # Validate
    print("[*] Validating candidates...")
    for w13_0 in candidates:
        plaintext = decode(w13_0)
        print(f"[?] w13_0 = {w13_0} (0x{w13_0:08x})")
        
        if plaintext.startswith(b"HTB{"):
            print(f"    [✓] ✓✓✓ FLAG FOUND ✓✓✓")
            print(f"    {plaintext.decode()}")
            print()
            print("=" * 70)
            return 0
        else:
            print(f"    [✗] Invalid")
    
    print("\n[✗] No valid candidate found")
    return 1

if __name__ == "__main__":
    exit(main())
```

---

## Flag Extraction

### Verification

Running the solver produces:

```
======================================================================
 Proofmark CTF Solver — Find the Flag
======================================================================

[*] Brute-forcing intermediate keystream state...
[*] Required keystream bytes: ['0x62', '0x7', '0x99', '0x0']
[+]   0.0% |    0.0s | Candidates: 0
[+]  12.5% |    1.9s | Candidates: 0
[+]  25.0% |    7.8s | Candidates: 0
[+]  37.5% |   12.6s | Candidates: 1
[+]  50.0% |   17.4s | Candidates: 1
...
[✓] Found 2 candidate(s) in 75.3s

[*] Validating candidates...
[?] w13_0 = 477923728 (0x1c94e7d0)
    [✓] ✓✓✓ FLAG FOUND ✓✓✓
    HTB{p3rf3ct_f4c3_tru3_sp1n3}

======================================================================
```

### The Flag

```
HTB{p3rf3ct_f4c3_tru3_sp1n3}
```

---

## Summary

### Attack Breakdown

| Phase | Technique | Time |
|-------|-----------|------|
| Reconnaissance | APK extraction, GDScript decompilation | <5s |
| Reverse Engineering | ARM64 disassembly, function identification | <1s |
| Cryptanalysis | PRNG reverse-engineering, constants extraction | Manual |
| **Attack** | **Intermediate state brute-force** | **~75s** |
| Flag Extraction | Ciphertext decryption | <1ms |

### Key Insights

1. **State validation is intentionally impossible** via gameplay (wards clamped 0-24 vs. required 83, 67, 55, 462) → designer wants you to forge directly

2. **Forward brute-force fails** due to 1.2M-round PRNG avalanche (infeasible: 4.3B × 1.2M operations)

3. **Intermediate state attack succeeds** by searching the post-stretch state (w13_0) with known-plaintext (HTB{) filtering → only 2 survivors in 32-bit space

4. **Vectorization is critical** — NumPy processes 16.7M candidates per chunk in ~2 seconds

5. **Narrative alignment** — Elric forges a ring; we forge cryptographic state. One strike, no second.

---

## Tools & Techniques

| Tool | Purpose |
|------|---------|
| `unzip` | Extract APK |
| GDRE Tools | Decompile GDScript bytecode |
| Capstone | Disassemble ARM64 code |
| pyelftools | Parse ELF headers |
| **NumPy** | **Vectorized brute-force** |
| Python | Implementation |

---

## References

- [Godot Engine Documentation](https://docs.godotengine.org/)
- [ARM64 ISA Reference](https://developer.arm.com/documentation/ddi0487/latest/)
- [Murmur3 Hash Algorithm](https://github.com/aappleby/smhasher)
- [Unicorn Emulator](https://www.unicorn-engine.org/)
- [GDRE Tools GitHub](https://github.com/GDRETools/gdsdecomp)

---

**Solved by:** CTF Player  
**Date:** 2025  
**Platform:** HackTheBox

---

**Flag:** `HTB{p3rf3ct_f4c3_tru3_sp1n3}`

### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon

