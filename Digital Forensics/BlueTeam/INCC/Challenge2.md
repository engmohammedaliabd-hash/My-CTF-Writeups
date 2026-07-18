# INCC-CTF - Write-up
**Author:** Mohammed Ali  
**Team:** CyberScope    
**Category:** Stegnography
**Difficulty:** Medium
## Teacher's Secret

## Attached files:
image.png  memory.bin  secret.enc
## analyze picthure 
<img width="800" height="600" alt="image" src="https://github.com/user-attachments/assets/069e6fca-c7c1-4ecb-860d-18345184c504" />

```
SCHOOL IT SYSTEM

  I'm OSINT master

  I love Google

  Internet Explorer will always be the best

  - Teacher 
  ```
after analyze the picthure no suspicious result 
## analyze memmory.bin 

```
file memory.bin
memory.bin: OpenPGP Public Key
```
its Not meemory when its  OpenPGP Public Key so lets check the important strings 

<img width="1046" height="470" alt="image" src="https://github.com/user-attachments/assets/029e7e4d-08e0-4e74-865f-c5cb42de19e7" />

## The result 
```
Teacher's secret: check the image comments:
Password clue: I'm OSINT master-
Hint 1: Look at image text carefully
Hint 2: Google is important
Hint 3: Internet Explorer was mentioned
Key components: OSINT, Google, IE
Combine all image messages for decryption key
```
## secret.enc
ecret.enc: only 32 bytes — a size that exactly matches two blocks of AES encryption (16 bytes per block), which is likely AES-128/256 without extra padding.

this comment its very important 
```
Key components: OSINT, Google, IE
```
By combining these words without spaces, in the order they appear in the image:
```
OSINTGoogleInternetExplorer
```
### Since secret.enc is 32 bytes (AES blocks), and the expected key is plain text and not hex, the natural step is to hash the text to get a fixed-size (32 bytes) AES-256 key:
The AES-256 key from this text (SHA256)
```python
KEY=$(echo -n "OSINTGoogleInternetExplorer" | openssl dgst -sha256 -binary | xxd -p -c 64)
echo $KEY
66b1f760f4269a0047d0b27b8be47a6fbba7d49da61379e3702a8dfceedb9440
```
Decrypting secret.enc with AES-256-CBC with zero IV

```python
 openssl enc -d -aes-256-cbc \
  -in secret.enc \
  -K "$KEY" \
  -iv 00000000000000000000000000000000 \
  -nopad
INCC{m3m0ry_h1nt_0s1nt_m4st3r}
```
or 

```python
 openssl enc -d -aes-256-cbc \
  -in secret.enc \
  -K "66b1f760f4269a0047d0b27b8be47a6fbba7d49da61379e3702a8dfceedb9440" \
  -iv 00000000000000000000000000000000 \
  -nopad
INCC{m3m0ry_h1nt_0s1nt_m4st3r}
```

### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon

