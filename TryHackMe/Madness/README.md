# Write-up: Madness-Full Pwn-Try Hack Me By Mohammed-Ali 🚩

**Category:** Digital Forensics & Full-Pwn
**Level:** Easy/Medium
---
In this walkthrough, I explore the exploitation lifecycle of a target machine, progressing from initial discovery to full **Root compromise**. The journey involves a multi-staged attack vector: **repairing corrupted image headers** to reveal hidden data, bypass-driven parameter fuzzing, and decoding layered steganography. 

The final escalation leverages an outdated SUID binary to shatter system restrictions. This lab serves as a prime case study on how misconfigured directories and legacy binary permissions can lead to a total system takeover.
### 🔍 1. Initial Reconnaissance

i used nmap to identify open ports and services:

<img width="1014" height="368" alt="Screenshot_2026-05-13_18_29_09" src="https://github.com/user-attachments/assets/11232c2b-4ce6-4b64-b4b4-b8a38393273a" />
Result:

Port 22 → SSH  (OpenSSH 7.2p2 Ubuntu)
Port 80 → HTTP (Apache 2.4.18)

With only two ports open the entire attack surface lives on the web server — enumerate everything carefully.

### 2. Source Code Analysis — Hidden Directory

Web enumeration returned nothing useful so I inspected the page source directly. I found a reference to an embedded image and a suspicious comment:

<img width="1308" height="956" alt="Screenshot_2026-05-13_18_33_45" src="https://github.com/user-attachments/assets/54a13436-2ccb-473b-ab59-6073a78ca5a6" />

```html
<div class="page_header floating_element">
    <img src="thm.jpg" class="floating_element"/>
    <!-- They will never find me -->
</div>
```
so i download the picture but is broken you should edit the hex signthure to jpg so to edit the signthure i used tool name Hexedit 
<img width="733" height="207" alt="h" src="https://github.com/user-attachments/assets/a08b2a23-580f-46fd-b8fc-91ead9df00e9" />

so i download the picture but is broken you should edit the hex signthure to jpg so to edit the signthure i used tool name Hexedit 

<img width="1900" height="1035" alt="b" src="https://github.com/user-attachments/assets/2a25025b-5574-4bea-8da0-5ce77f5c14c5" />

Correct JPG header bytes applied:

FF D8 FF E0 00 10 4A 46 49 46

✅ Result: Image repaired — opening it revealed a hidden directory:

/th1s_1s_h1dd3n

<img width="400" height="400" alt="1_eK67L6P-APtgAy8II-I_Zw" src="https://github.com/user-attachments/assets/a368baab-1b8e-4723-898e-7011c15c3267" />

Always check image headers when a file looks broken — a wrong magic byte is a common CTF trick to hide data in plain sight.
## 🧪 3. Parameter Fuzzing — Secret Discovery

After discovering the hidden directory, another hint was waiting in the source code:
`<!-- It's between 0-99 but I don't think anyone will look here-->`

The page required a `secret` parameter to reveal more information. Instead of guessing manually, I wrote a **Python automation script** to brute-force the value:

### 🐍 The Exploitation Script:
```python
import requests

url = "http://[TARGET_IP]/th1s_1s_h1dd3n/" 

for i in range(100):
    params = {'secret': i}
    response = requests.get(url, params=params)
    
    # Checking if the failure message is gone
    if "That is wrong!" not in response.text:
        print(f"[+] Found it! The secret is: {i}")
        print(f"[-] Response Content: {response.text}")
        break
    else:
        print(f"[*] Trying: {i}", end="\r")
```
🚩 The Result:

After running the script, I successfully found the secret:

```python3 exploit.py
[+] Found it! The secret is: 73
[-] Response Content: ... Urgh, you got it right! But I won't tell you who I am! y2RPJ4QaPF!B
```
4. Steganography — Username Extraction

I used the discovered passphrase to extract hidden data from thm.jpg:

```steghide extract -sf thm.jpg

Passphrase: y2RPJ4QaPF!B

📊 Result: hidden.txt extracted containing:

Here's a username : wbxre

💭 wbxre looked encoded — I recognized it as ROT13 and decoded it:

wbxre → joker
```
### 5. Password Discovery — Second Image

I investigated the main CTF room image and found it also contained hidden data:

<img width="1920" height="1080" alt="5iW7kC8" src="https://github.com/user-attachments/assets/1fd07741-1cf5-431b-a315-72c43a43aa0a" />

```steghide info 5iW7kC8.jpg (there is no passphrase just press enter)
steghide extract -sf 5iW7kC8.jpg

Result: password.txt extracted containing:

*axA&GF8dP

➡Combined with the ROT13 decoded username with CyberChef:

Username : joker
Password : *axA&GF8dP
```
### 6. SSH Access

I logged in using the discovered credentials:

<img width="1034" height="620" alt="Screenshot_2026-05-13_18_49_00" src="https://github.com/user-attachments/assets/39779a8c-4765-4fc4-a524-a28bb073dde9" />

Result: Shell obtained as joker.

### 7. User Flag

/home/joker/user.txt

### 8. Privilege Escalation — Screen 4.5.0 SUID Exploit

``` sudo -l and /etc/crontab returned nothing useful. I searched for SUID binaries:

find / -type f -perm -04000 -ls 2>/dev/null

```

<img width="1193" height="528" alt="Screenshot_2026-05-13_18_49_17" src="https://github.com/user-attachments/assets/657bfd52-2c99-436e-985e-4858442b170b" />

### Finding:

```
 /bin/screen-4.5.0

```

I researched this binary and found a known local privilege escalation exploit on

https://github.com/YasserREED/screen-v4.5.0-priv-escalate/blob/main/README.md

I ran the exploit script against the vulnerable screen binary.

and i get root on this machine

<img width="1607" height="565" alt="Screenshot_2026-05-13_18_54_31" src="https://github.com/user-attachments/assets/6875f3c2-c494-4e5c-b554-1e81c16f50b1" />

### Conclusion

This challenge serves as a stark reminder of how layered security can crumble when steganography, encoding manipulation, and legacy SUID binaries are chained together. The critical takeaway is the ‘Adversarial Mindset’: attackers thrive in the spaces you overlook — within the comments of source code, the headers of corrupted images, and the seemingly empty directories. True security isn’t just about patching known bugs; it’s about eliminating the Breadcrumbs that lead to a total system compromise

### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon
