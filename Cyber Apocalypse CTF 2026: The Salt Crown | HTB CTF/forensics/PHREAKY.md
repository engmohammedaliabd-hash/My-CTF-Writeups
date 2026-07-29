# Phreaky Challenge Writeup
**Difficulty:** Medium 
**Author:** Mohammed Ali  
**Challenge:** Phreaky  
**Type:** Forensics / Network Analysis  
**Flag:** `HTB{Th3Phr3aksReadyT0Att4ck}`

### Premise

In the shadowed realm where the Phreaks hold sway, a mole lurks within, leading them astray. A network packet capture reveals the trick—a traitor sending keys to The Talents through encrypted messages hidden in plain sight across the network.

### Objective

Analyze a PCAP file to:
1. Identify the mole and their communications
2. Extract fragmented data sent via SMTP
3. Decrypt/decode and reassemble the hidden information
4. Reveal the traitor's secret communication key

---

## Solution Approach

### Step 1: Analyze the PCAP File

The challenge provided a pcap file. First, I identified what tools were available in the environment.

```bash
capinfos phreaky.pcap
# Output: pcap capture file, microsecond ts (little-endian) - version 2.4
# Ethernet, capture length 262144
# 3915 packets total
```

Since advanced tools like `tshark` and `scapy` weren't available (and no internet for pip install), I built a minimal pcap parser from scratch.

### Step 2: Build a Custom PCAP Parser

**pcap_parse.py** — Low-level pcap file format parser:

```python
import struct, sys

def parse_pcap(path):
    with open(path, 'rb') as f:
        data = f.read()
    magic = data[0:4]
    # Detect endianness
    if magic == b'\xd4\xc3\xb2\xa1':
        endian = '<'
    elif magic == b'\xa1\xb2\xc3\xd4':
        endian = '>'
    else:
        raise ValueError("unknown magic")

    global_header = struct.unpack(endian+'IHHiIII', data[0:24])
    linktype = global_header[6]
    offset = 24
    packets = []
    idx = 0
    while offset < len(data):
        if offset+16 > len(data):
            break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian+'IIII', data[offset:offset+16])
        offset += 16
        pkt_data = data[offset:offset+incl_len]
        offset += incl_len
        packets.append((idx, ts_sec, ts_usec, pkt_data))
        idx += 1
    return linktype, packets
```

### Step 3: Dissect Traffic Flows

**dissect.py** — Parse Ethernet → IP → TCP/UDP headers:

```python
def parse_eth(pkt):
    dst = pkt[0:6]
    src = pkt[6:12]
    ethertype = struct.unpack('>H', pkt[12:14])[0]
    return ethertype, pkt[14:]

def parse_ip(payload):
    ver_ihl = payload[0]
    ihl = (ver_ihl & 0x0f) * 4
    total_len = struct.unpack('>H', payload[2:4])[0]
    proto = payload[9]
    src = payload[12:16]
    dst = payload[16:20]
    return {
        'ihl': ihl,
        'proto': proto,
        'src': ip_str(src),
        'dst': ip_str(dst),
        'payload': payload[ihl:total_len]
    }

def parse_tcp(payload):
    sport, dport, seq, ack, offset_flags = struct.unpack('>HHIIH', payload[0:14])
    data_offset = (offset_flags >> 12) * 4
    return {'sport': sport, 'dport': dport, 'seq': seq, 'ack': ack, 'data': payload[data_offset:]}
```

**Key Finding:**
```
('185.125.190.39', 80, '192.168.68.111', 34418, 'TCP') - HTTP (1720 packets)
('204.141.43.44', 25, '192.168.68.111', 33968+, 'TCP') - SMTP outbound (many streams)
('192.168.68.108', 58826+, '192.168.68.111', 25, 'TCP') - SMTP local (many streams)
```

**Focus:** 30 SMTP streams on port 25 between local host `192.168.68.108` and the mail relay.

### Step 4: Reconstruct TCP Streams

**streams.py** — Extract individual TCP stream data:

```python
def reassemble(pkts, from_endpoint):
    items = []
    for ts_sec, ts_usec, a, b, seq, data in pkts:
        if a == from_endpoint and data:
            items.append((seq, data))
    items.sort(key=lambda x: x[0])
    seen = set()
    out = b''
    for seq, data in items:
        if seq in seen:
            continue
        seen.add(seq)
        out += data
    return out
```

### Step 5: Extract SMTP Email Data

Reassembled the first SMTP stream to inspect:

```
HELO phreak-ubuntu01
MAIL FROM:<caleb@thephreaks.com>
RCPT TO:<resources@thetalents.com>
DATA
Date: Wed, 06 Mar 2024 14:59:12 +0000
From: caleb@thephreaks.com (Caleb)
To: resources@thetalents.com
Subject: Secure File Transfer
...
Attached is a part of the file. Password: S3W8yzixNoL8

Content-Type: application/zip
Content-Transfer-Encoding: base64
Content-Disposition: attachment; 
 filename*0="caf33472c6e0b2de339c1de893f78e67088cd6b1586a581c6f8e87b5596";
 filename*1="efcfd.zip"

[base64-encoded ZIP data]
```

**The Mole:** `caleb@thephreaks.com` (username: **Caleb**)  
**Target:** `resources@thetalents.com`

### Step 6: Extract and Decrypt All ZIP Parts

All 15 emails followed the same pattern:
- Same subject: "Secure File Transfer"
- Each password in plaintext in the email body
- Each containing a ZIP with one file: `phreaks_plan.pdf.partN`

**Mapping of emails to parts:**

| Email# | Source Port | Password        | File                  |
|--------|-------------|-----------------|----------------------|
| 0      | 40462       | S3W8yzixNoL8    | phreaks_plan.pdf.part1 |
| 1      | 42430       | (forwarded, no attach) | - |
| 2      | 45656       | r5Q6YQEcGWEF    | phreaks_plan.pdf.part2 |
| 3      | 57062       | (forwarded)     | - |
| 4      | 35464       | TVm9aC1UycxF    | phreaks_plan.pdf.part3 |
| ...    | ...         | ...             | ... |
| 28     | 52444       | gdOvbPtB0xCK    | phreaks_plan.pdf.part15 |

**Extraction script:**

```python
import re, base64

streams = get_streams('phreaky.pcap', 25)
results = []
for idx, key in enumerate(streams.keys()):
    pkts = streams[key]
    a, b = key
    for ep in (a,b):
        if ep[0] == '192.168.68.108':
            data = reassemble(pkts, ep)
            if b'Password:' in data:
                m = re.search(rb'Password: (\S+)', data)
                pwd = m.group(1).decode()
                m2 = re.search(rb'Content-Type: application/zip.*?\r\n\r\n(.*?)\r\n--', data, re.S)
                b64 = m2.group(1).replace(b'\r\n', b'')
                zipbytes = base64.b64decode(b64)
                fname = f'parts/part_{idx}.zip'
                with open(fname,'wb') as f:
                    f.write(zipbytes)
                print(idx, pwd, fname, len(zipbytes))
```

**Unzip each part with its password:**

```bash
unzip -P S3W8yzixNoL8 parts/part_0.zip -d extracted
unzip -P r5Q6YQEcGWEF parts/part_2.zip -d extracted
unzip -P TVm9aC1UycxF parts/part_4.zip -d extracted
# ... (repeat for all 15)
```

### Step 7: Reassemble the PDF

```bash
cat extracted/phreaks_plan.pdf.part1 \
    extracted/phreaks_plan.pdf.part2 \
    ... \
    extracted/phreaks_plan.pdf.part15 \
    > phreaks_plan.pdf

file phreaks_plan.pdf
# PDF document, version 1.3, 2 page(s)
```

### Step 8: Extract PDF Content

```bash
pdftotext phreaks_plan.pdf phreaks_plan.txt
cat phreaks_plan.txt
```

**PDF Content Summary:**

**Title:** "Operation Spotlight: The Phreaks' Grand Scheme Against The Talents"

**Key Sections:**
- **Background:** The Phreaks vs. The Talents (KORP universe factions)
- **Objective:** Infiltrate and disrupt The Talents' media operations
- **Strategy:** Multi-phase cyber infiltration, malware/DDoS, information warfare
- **Phases:**
  - Phase 1: Intercept & manipulate communications
  - Phase 2: Deploy malware, launch DDoS, plant false info
  - Phase 3: Cover tracks and exit

**CRITICAL — Appendix: Communication Protocols:**

```
For secure communication, all operatives are required to use encrypted channels only.
Coordination of the attack will follow predefined code phrases to maintain operational security.

Key for secure communication: HTB{Th3Phr3aksReadyT0Att4ck}
```

---

## Summary

| Finding | Details |
|---------|---------|
| **Mole** | Caleb (caleb@thephreaks.com, source host 192.168.68.108) |
| **Target** | The Talents (resources@thetalents.com) |
| **Method** | 15 SMTP emails with password-protected ZIP attachments |
| **Payload** | Fragmented PDF (phreaks_plan.pdf, 15 parts) |
| **Flag Location** | PDF Appendix: Communication Protocols section |
| **Flag** | `HTB{Th3Phr3aksReadyT0Att4ck}` |

---

## Tools & Techniques

- **Custom PCAP parsing** (struct, no external libs)
- **TCP stream reassembly** (sequence number ordering)
- **SMTP traffic analysis**
- **Base64 decoding**
- **ZIP extraction with passwords**
- **PDF reconstruction**
- **PDF text extraction**

---

## Key Learnings

1. **PCAP can be parsed from scratch** — Standard format with well-defined headers
2. **SMTP in plaintext** — All emails, passwords, and metadata visible (hence why TLS/encryption matters)
3. **Steganography via fragmentation** — Splitting a document across multiple encrypted attachments makes detection harder, but reassembly is straightforward once identified
4. **Email metadata + content correlation** — Matching passwords to ZIP files within email bodies links the full chain
5. **Endpoint identification** — Source IP + port patterns reveal the sender's identity (192.168.68.108 = phreak-ubuntu01)

---

## Flag

```
HTB{Th3Phr3aksReadyT0Att4ck}
```

### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon

