# CyberDefenders - Brave Lab Investigation & Write-up

**Author:** Mohammed Ali  
**Team:** CyberScope  
**Platform:** CyberDefenders  
**Category:** Endpoint Forensics / Memory Forensics  
**Difficulty:** Medium 

<img width="1459" height="857" alt="Screenshot 2026-06-15 195819" src="https://github.com/user-attachments/assets/52f1dfd7-e863-4b4b-941c-6d9136e0199b" />


## 📝 Lab Scenario
A memory image was acquired from a suspected compromised Windows workstation. The user was flagged for unauthorized access and suspicious browsing patterns. My task was to investigate the memory dump to identify malicious processes, network connections, and trace user activity to uncover the root cause of the compromise.

## 🔍 Investigation Methodology
1 - What time was the RAM image acquired according to the suspect system?
first step use plugin ``` windows.info > its show the os name and date ...``` so to find the 
time was the RAM image acquired the use this plugin 

<img width="1920" height="597" alt="Screenshot 2026-06-15 200702" src="https://github.com/user-attachments/assets/f7b0d23b-4538-4216-9957-9837a048e5d9" />

2 - What is the SHA256 hash value of the RAM image? 
its Easy to find it just use the cli on linux or Windows im used the cli for linux 
Command >> 
```python
sha256sum 20210430-Win10Home-20H2-64bit-memdump.mem
```
<img width="1112" height="90" alt="Screenshot 2026-06-15 201415" src="https://github.com/user-attachments/assets/b1b65168-6cf7-4fb9-88ba-3fc63204ebda" />

3 - What is the process ID of brave.exe?
Brave its program so when is open its process so to find the process run use this plugin 
``` windows.pslist ```

<img width="1888" height="956" alt="Screenshot 2026-06-15 201801" src="https://github.com/user-attachments/assets/64d69b25-97ee-484f-9700-0e73f48911ab" />

<img width="1778" height="953" alt="Screenshot 2026-06-15 201827" src="https://github.com/user-attachments/assets/e7f524e1-b329-4608-bf12-c81143129b26" />

The Process ID (PID) for brave.exe was identified as 4856 using the windows.pslist plugin. This confirms the browser was active at the time of the memory dump.

4 - How many established network connections were there at the time of acquisition?
this is network its have tow plugin to find the connections on system 
plugns >> ``` windows.netstat and windows.netscan ``` and i used the grep to show the result just the established connections 

<img width="1905" height="307" alt="Screenshot 2026-06-15 202455" src="https://github.com/user-attachments/assets/39c4d9f3-0051-48e2-b605-cabf791f74d6" />

``` Its 10 connections ```
5 - Which domain name does Chrome have an established network connection with?
to find the domains use tool like ``` nslookup ```

<img width="1077" height="91" alt="Screenshot 2026-06-15 202844" src="https://github.com/user-attachments/assets/efe97616-9939-4fdc-b218-deb123a0991e" />

6 - What is the MD5 hash value of the process executable for PID 6988?
to find this you should dump the file to extract the md5 hash so its many plugin i used the 
```python
windows.pslist --pid 6988 --dump
```
<img width="1890" height="176" alt="Screenshot 2026-06-15 204019" src="https://github.com/user-attachments/assets/75855ab0-56d0-4aab-9928-99bf8a96756e" />

<img width="624" height="77" alt="Screenshot 2026-06-15 204032" src="https://github.com/user-attachments/assets/c3543487-9f66-41a7-8601-500c964b3cfd" />

7 - Can you identify the word that begins at offset 0x45BE876 and is 6 bytes long?
i used the HXD ond windows to find the value 45BE876 
HxD — on Windows:
Open the memdump.mem capture file into HxD.
From the top menu, select “Search” > “Go to” and type the provided starting offset — you will need to omit the 0x prepended to the offset.

<img width="905" height="534" alt="Screenshot 2026-06-15 205845" src="https://github.com/user-attachments/assets/c534891a-c3a4-4edf-af2c-e0f17284d866" />

8 - What is the creation date and time of the parent process of powershell.exe? 
i used the plugin >>  ``` windows.pslist ```

<img width="1499" height="957" alt="Screenshot 2026-06-15 210406" src="https://github.com/user-attachments/assets/cba2a2a2-924e-4235-a6fe-33f4452d4930" />
so the parent pid is 4352 so lets find the the process the pid is 4352 thats is the creations time 

<img width="1906" height="990" alt="Screenshot 2026-06-15 210644" src="https://github.com/user-attachments/assets/c01fe1e6-277c-4db1-ad27-f11f57702da3" />

9 - What is the full path and name of the last file opened in notepad?
to find it i used the cmd line to show the write on notepad 
i used the plugin >>  ``` windows.cmdline ```

<img width="1898" height="86" alt="Screenshot 2026-06-15 211143" src="https://github.com/user-attachments/assets/a9e14663-f5bf-4cd5-931d-5fd523fd7825" />

10 - How long did the suspect use Brave browser? (In Hours)
this informations svae on registery so lets find it 
<img width="1885" height="263" alt="Screenshot 2026-06-15 211710" src="https://github.com/user-attachments/assets/a15c78ab-0c3d-4ad6-bd0d-ad49e0a46269" />
its 4 hours 


## Conclusion

The forensic investigation of the memory image provided a clear insight into the system's compromise. By utilizing Volatility 3 and manual artifact analysis, the CyberScope team successfully reconstructed the timeline of the incident. We identified that the adversary utilized brave.exe as an initial vector and attempted to maintain persistence through encoded powershell.exe commands.
The findings highlight the importance of memory forensics in detecting stealthy, fileless-like activities that traditional antivirus solutions might miss. Moving forward, it is 
recommended to implement enhanced EDR monitoring for PowerShell execution policies and to restrict outbound connections to encrypted services for non-essential processes.

### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon


