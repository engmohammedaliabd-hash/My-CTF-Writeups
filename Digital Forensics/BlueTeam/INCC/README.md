# INCC-CTF - Write-up
**Author:** Mohammed Ali  
**Team:** CyberScope    
**Category:** Network Forensics 
**Difficulty:** Hard
## 📝 Lab Scenario
One of our workstations was flagged by the SOC for "weird" outbound traffic, but nothing showed up in the proxy logs and no large file transfers were seen. We pulled a packet capture off the wire before isolating the host. The analyst is convinced something was smuggled out of the network - quietly. Figure out what was stolen.  hint: The secret left in the queries, not the payloads. What decodes cleanly is bait; the prize needs the key that pings home.  flag format: INCC{...} 
## 🔍 Investigation Methodology
use wireshark to anlyzee the trafic i looked for packets ICMP 

<img width="1917" height="1020" alt="Screenshot 2026-07-18 074730" src="https://github.com/user-attachments/assets/9a573bb9-5590-4431-96a0-c0e893f0add5" />

```python
BEACON|host=WIN-DESK07|sid=4471|XK=n3tw0rk|enc=xor-b32|v2
```
Its xor the value of xor key is n3tw0rk and the decode say b32 its base32 
Now lets check the DNS packets and analyze it 
<img width="1912" height="932" alt="image" src="https://github.com/user-attachments/assets/68084146-277f-4f54-906e-d12eb6c95e03" />

many dns packets so lets use tshark to get the get the dns

<img width="1315" height="932" alt="image" src="https://github.com/user-attachments/assets/164780ae-b7e8-4ab5-a38b-680519682ca1" />

its have suspicious dns like 
```python
.up.metrics-collector.net
.sync.cdn-telemetry.net
```
<img width="1342" height="238" alt="Screenshot 2026-07-18 075315" src="https://github.com/user-attachments/assets/3f084550-9641-4800-aaca-2d5cb57a577c" />

After arranging them
You Know the base32 is Upper case so lets use 

```
echo "k5je6tshl5iecvcil5fukrkql5ge6t2ljfheox2bkrpviscfl5hviscfkjpuit2nifeu4" | tr 'a-z' 'A-Z'
K5JE6TSHL5IECVCIL5FUKRKQL5GE6T2LJFHEOX2BKRPVISCFL5HVISCFKJPUIT2NIFEU4
```
<img width="1342" height="113" alt="image" src="https://github.com/user-attachments/assets/df2bde7a-ae98-4841-acdb-01b0a5e8fbf5" />

Its say Looking other Domain so lets check another suspicious domain 
<img width="1842" height="319" alt="image" src="https://github.com/user-attachments/assets/82e04f72-cba0-48b6-8a6b-f65b4b8752a6" />

So lets decode them 
<img width="1473" height="210" alt="image" src="https://github.com/user-attachments/assets/e493ab56-0533-4fd1-8da1-bc751b0642c8" />

Now mayber its the xor key use with this lets check it 
I use the Cybershef 
<img width="1918" height="892" alt="image" src="https://github.com/user-attachments/assets/95a6f37a-5e06-4a77-83c6-f67d37b9131f" />

Final flag : INCC{dns_tunn3l1ng_3xf1ltr4t10n_unc0v3r3d}

### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon
