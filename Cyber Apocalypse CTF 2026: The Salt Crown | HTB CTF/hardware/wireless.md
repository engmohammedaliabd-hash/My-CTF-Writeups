[writeup_wireless_connections.md](https://github.com/user-attachments/files/30521988/writeup_wireless_connections.md)
# Wireless Connections — Write-up
**Author:** Mohammed Ali  

## Scenario

The challenge provides an 8 MiB ESP32-S3 firmware dump in `firmware.bin`. The flag is encrypted in the application image and decrypted at runtime using a seed derived from the device's Wi-Fi MAC address.

## 1. Locate the application image

The ESP32 partition table is located at `0x8000`, and the application begins at `0x10000`. Parsing the ESP image header gives these relevant segments:

| Segment | Load address | File offset | Length |
|---|---:|---:|---:|
| DROM | `0x3c0a0020` | `0x10020` | `0x22d40` |
| DRAM | `0x3fc96c00` | `0x32d68` | `0x05248` |
| IROM | `0x42000020` | `0x40020` | `0x9a404` |

The visible strings include `blink_task`, `SpyHouse`, and `bugged26`, but no plaintext flag. The 32-byte data near the beginning of DROM is the ESP application SHA-256 descriptor, not the flag.

## 2. Identify the decryption routine

Disassembling the Xtensa IROM code shows a routine at approximately `0x42002ca0`. It implements a Numerical Recipes linear congruential generator:

```c
void decrypt(const unsigned char *src, unsigned char *dst,
             int len, uint32_t state) {
    for (int i = 0; i < len; i++) {
        state = state * 1664525u + 1013904223u;
        dst[i] = src[i] ^ ((state >> 16) & 0xff);
    }
}
```

The routine generates one keystream byte per ciphertext byte by taking bits 16–23 of the updated state.

## 3. Derive the seed

The caller obtains the Wi-Fi MAC address and uses only its first three bytes, the OUI:

```c
uint32_t oui = ((mac[0] << 16) | (mac[1] << 8) | mac[2]);
uint32_t seed = oui * 0x01000193u;
```

The OUI is unknown, giving a 24-bit search space.

## 4. Extract the ciphertext

The encrypted 32-byte flag is stored at virtual address `0x3c0b103b`.

The DROM mapping is:

```text
file offset = DROM file offset + (virtual address - DROM load address)
            = 0x10020 + (0x3c0b103b - 0x3c0a0020)
            = 0x2103b
```

The extracted ciphertext is:

```text
10a068e75de6e70f12bbb2f3cab4d202cbded8200de568924200be14f07bba01
```

## 5. Brute-force the OUI

The known flag prefix `HTB{` makes testing each candidate efficient. Only four LCG rounds are needed to reject almost every candidate.

```python
d = open("firmware.bin", "rb").read()
ct = d[0x2103b:0x2103b + 32]

A = 1664525
C = 1013904223

for oui in range(1 << 24):
    seed = (oui * 0x01000193) & 0xffffffff
    state = seed

    valid = True
    for i, expected in enumerate(b"HTB{"):
        state = (state * A + C) & 0xffffffff
        plain = ct[i] ^ ((state >> 16) & 0xff)
        if plain != expected:
            valid = False
            break

    if not valid:
        continue

    state = seed
    plaintext = bytearray()
    for value in ct:
        state = (state * A + C) & 0xffffffff
        plaintext.append(value ^ ((state >> 16) & 0xff))

    print(f"OUI={oui:06X}: {plaintext}")
```

The unique match is:

```text
OUI 7C:DF:A1
seed 0x65940A73
plaintext HTB{solv3d_w1th_xt3ns4_dec00mp}
```

## Flag

```text
HTB{solv3d_w1th_xt3ns4_dec00mp}
```
### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon
