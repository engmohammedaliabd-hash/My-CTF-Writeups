# Overstrike
**Author:** Mohammed Ali  

**Category:** Mobile

## Artifact analysis

The supplied `Overstrike.apk` is a Godot .NET Android application. The source files are stripped, but the managed assembly remains at `assets/.godot/mono/publish/x86_64/Overstrike.dll`. Decompiling it reveals the logic in `GameState`, `MarkPickup`, `BridgeBuilder`, and `Archive`.

## Game logic

The world seal is calculated every frame from the carried mark:

```csharp
WorldSeal = Mix(CarriedMark);
```

The bridge opens only when `WorldSeal == 15682021040575554950UL`. `Mix` is an invertible 64-bit SplitMix-style finalizer: it subtracts `7046029254386353131`, applies two odd modular multiplications interleaved with right xorshifts, and applies a final right xorshift.

The five visible pickups are worth only `1, 2, 3, 5, 7`, so collecting them cannot produce the true mark. The intended solution is to invert `Mix` and forge the carried mark.

## Inverting the seal

Odd multipliers have modular inverses modulo `2^64`. A right-xorshift is reversed with progressively doubled shifts, for example `y ^= y >> 31; y ^= y >> 62`. Reversing the operations in the opposite order gives:

```text
forged mark = 15549431037298259574
forged mark = 0xd7caad24dd98b676
```

Verification: `Mix(0xd7caad24dd98b676) = 15682021040575554950`.

## Registry decryption

`GameState.UnsealRegistry()` derives a SHA-256 keystream from the little-endian forged mark and XORs it with the embedded `SealedRecord`:

```python
key = sha256(struct.pack('<Q', mark)).digest()
stream = sha256(key + struct.pack('<i', counter)).digest()
```

Decrypting the 56 bytes gives the registry record and flag.

## Flag

`HTB{0v3rstr1k3_r3cut_th3_w0rld_s34l_by_f0rg1ng_th3_mark}`

### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon
