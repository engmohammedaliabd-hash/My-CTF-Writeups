# Digital Forensics Investigation Report: Practical Challenge
## 📝 Case Overview
* **Platform:** [Blue Team Labs Online](https://blueteamlabs.online/)
* **Category:** Digital Forensics & Artifact Analysis
* **Objective:** Investigate a compromised user device, locate hidden archives, bypass anti-forensics techniques, and recover exfiltrated corporate data.
* **Investigated By:** Mohammed Ali Abdul Mohsen 
* **Team:** Cyber Scope
# 1. Executive Summary

# This report documents the digital forensics analysis performed on a target system's disk drive. The investigation aimed to uncover hidden artifacts, unauthorized data, and potential compromise indicators. Through systematic directory traversal, steganography analysis, and file signature verification, four distinct pieces of evidence were successfully identified, analyzed, and documented.

## 2. Investigation Findings & Evidence Log
### 🔹 Evidence 1/4: Hidden Directory & Encrypted Archives
  <img width="811" height="981" alt="Screenshot 2026-06-06 192419" src="https://github.com/user-attachments/assets/23381dc0-1be4-4aa5-96c4-1320d897a6ac" />
  
* **Target Directory:** `to-do`

* **the file its need to password to unzip it so now i used ** `John`
<img width="1269" height="218" alt="Screenshot 2026-06-06 193024" src="https://github.com/user-attachments/assets/50221503-1949-4a77-8ece-5b77628ab18c" />

* **Discovered File:** `employee dump`

<img width="571" height="213" alt="Screenshot 2026-06-06 193201" src="https://github.com/user-attachments/assets/8d90f13d-6d72-4495-b687-bcbb355d53b6" />

### 🔹 Evidence 2/4: Steganography & Credential Extraction
* **Target Directory:** `Images`
* **Discovered File:** `laptop.jpg`
<img width="924" height="283" alt="Screenshot 2026-06-06 193349" src="https://github.com/user-attachments/assets/15de5aed-2717-48a8-a7ab-3c3e512b4c80" />

* **:** `When I search in folders i got files contain comment`

<img width="696" height="368" alt="Screenshot 2026-06-06 193947" src="https://github.com/user-attachments/assets/df2a7895-1367-4b07-8458-843ccf2c046c" />
<img width="1861" height="536" alt="Screenshot 2026-06-06 194520" src="https://github.com/user-attachments/assets/70881a86-53d4-4820-9a44-2e85da03b6a7" />

* **:** `So i used steghide maybe its the true passphrese`
* **Extracted payload:** `passwords`

### 🔹 Evidence 3/4: File Masquerading & Reconnaissance Data
* **The tarhet directory is :** `Weekly Meeting Notes`
* **Analysis Methodology:**
```bash
 cd ..                                                                                                                                                    Sat 06 Jun 2026 07:00:58 PM +03
 /m/c/U/m/D/d/J Harrison Disk Image 10.09.2019  ls                                                                                                                               Sat 06 Jun 2026 07:01:04 PM +03
 Images/   Payslips/  'Saved Emails'/  'WebDev work'/  'Weekly Meeting Notes'/
 /m/c/U/m/D/d/J Harrison Disk Image 10.09.2019  cd Payslips/                                                                                                                     Sat 06 Jun 2026 07:01:05 PM +03
 /m/c/U/m/D/d/J/Payslips  ls                                                                                                                                                     Sat 06 Jun 2026 07:01:16 PM +03
readme*
 /m/c/U/m/D/d/J/Payslips  cd ../WebDev\ work/                                                                                                                                    Sat 06 Jun 2026 07:01:16 PM +03
 /m/c/U/m/D/d/J/WebDev work  ls                                                                                                                                                  Sat 06 Jun 2026 07:01:23 PM +03
'finished webpages'/   Links.txt*   scan.xml*  'to do list'*  'unfinished webpages'/   VERSION*  'WAF on OS Detection Nmap Scan.txt'*
 /m/c/U/m/D/d/J/WebDev work  cd ../Weekly\ Meeting\ Notes/                                                                                                                       Sat 06 Jun 2026 07:01:24 PM +03
 /m/c/U/m/D/d/J/Weekly Meeting Notes  ;s                                                                                                                                         Sat 06 Jun 2026 07:01:39 PM +03
s: command not found
fish:
;s
 ^
 !  /m/c/U/m/D/d/J/Weekly Meeting Notes  ls                                                                                                                                     Sat 06 Jun 2026 07:01:40 PM +03
'Week 10'/  'Week 9'/
 /m/c/U/m/D/d/J/Weekly Meeting Notes  cd Week\ 9/                                                                                                                                Sat 06 Jun 2026 07:01:41 PM +03
 /m/c/U/m/D/d/J/W/Week 9  ls                                                                                                                                                     Sat 06 Jun 2026 07:01:46 PM +03
Friday*
 /m/c/U/m/D/d/J/W/Week 9  ls -la                                                                                                                                                 Sat 06 Jun 2026 07:01:47 PM +03
total 0
drwxrwxrwx 1 rootforce rootforce 4096 Jun  6 18:30 ./
drwxrwxrwx 1 rootforce rootforce 4096 Jun  6 18:30 ../
-rwxrwxrwx 1 rootforce rootforce  130 Oct 14  2019 Friday*
 /m/c/U/m/D/d/J/W/Week 9  file Friday                                                                                                                                            Sat 06 Jun 2026 07:01:49 PM +03
Friday: ASCII text
 /m/c/U/m/D/d/J/W/Week 9  strings Friday                                                                                                                                         Sat 06 Jun 2026 07:01:54 PM +03
Week 9, Friday:
- Decreased budget. Again. Can't believe this shit.
- New webpage needed for business partners.
- Blah blah blah
 /m/c/U/m/D/d/J/W/Week 9  cd ../Week\ 10/                                                                                                                                        Sat 06 Jun 2026 07:02:01 PM +03
 /m/c/U/m/D/d/J/W/Week 10  ls                                                                                                                                                    Sat 06 Jun 2026 07:02:21 PM +03
posidon.xml*  tue*
 /m/c/U/m/D/d/J/W/Week 10  file *                                                                                                                                                Sat 06 Jun 2026 07:02:22 PM +03
posidon.xml: PNG image data, 162 x 147, 8-bit/color RGB, non-interlaced
tue:         ASCII text
 /m/c/U/m/D/d/J/W/Week 10  cp posidon.xml posidon.png                                                                                                                            Sat 06 Jun 2026 07:02:26 PM +03
 /m/c/U/m/D/d/J/W/Week 10  file posidon.png                                                                                                                                      Sat 06 Jun 2026 07:02:41 PM +03
posidon.png: PNG image data, 162 x 147, 8-bit/color RGB, non-interlaced
```
<img width="1918" height="837" alt="Screenshot 2026-06-06 195343" src="https://github.com/user-attachments/assets/3c310794-cdfb-4de4-b002-d28b891b6c2b" />

1. Located a file named `posidon.xml` inside the `week 10` directory.
  2. Ran `cat` to inspect the raw file header (Magic Bytes), which confirmed that the file was actually a **PNG image** disguised with an `.xml` extension.
  3. Corrected the file extension to `.png`, allowing the image to render and exposing a confidential layout of office locations.

<img width="162" height="147" alt="posidon" src="https://github.com/user-attachments/assets/3d8bc61e-ab36-40f9-bab3-b0d424288558" />

### 🔹 Evidence 4/4: Data Obfuscation in Web Directories
* **Target Directory:** `css`
* **Discovered File:** `bootstrap.min.abc`
* **Artifact Recovered:** Target Profile (Colin's Personal Information).
* **Analysis Methodology:** 

<img width="1374" height="859" alt="Screenshot 2026-06-06 195813" src="https://github.com/user-attachments/assets/c014f927-59d2-4b1d-98e8-a36b7aad0738" />

---

## 👤 Connect with Me / About Me

I am a **Cyber Security Engineering student** and an active member of the **Cyber Scope** team. My core expertise and passion lie at the intersection of offensive and defensive security, specifically focusing on **Penetration Testing** and **Digital Forensics (DF)**. 

By understanding both adversary attack methodologies and rigorous forensic investigation techniques, I aim to bridge the gap between exploitation and artifact analysis. I constantly challenge myself through hands-on labs, CTFs, and real-world scenarios.

* **Instagram:** [@bingoh0wfun](https://www.instagram.com/bingoh0wfun)
* **Team:** Cyber Scope 🛡️

Feel free to reach out for collaborations, CTF team-ups, or discussions regarding cybersecurity, pentesting, and forensics!







  
