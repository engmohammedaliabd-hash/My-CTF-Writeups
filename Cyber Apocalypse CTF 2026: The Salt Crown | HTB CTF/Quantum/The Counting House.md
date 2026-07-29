# The Counting House — HTB Quantum Writeup

**Category:** Quantum
**Author:** Mohammed Ali



---

## Recon

The "Eastreach Counting House" (gunicorn/Flask) chains **three** quantum weaknesses.
`/api/market`:

```
/api/new         -> {token}
/api/enter       {token, circuit}          lock a note of value entry_value=4919 to take a seat
/api/book        {token, bidder,position,basis,shots}  measure a rival's bid work-tape qubit
/api/seal/commit {token, slots}            8 two-qubit strands -> challenge basis
/api/seal/peek   {token, basis}            measure your kept a-qubits -> a_outcomes
/api/seal/open   {token, values}           house measures each b in the challenge basis
/api/settle      {token, circuit, value}   pay the clearing price with a forged note -> deed
rivals=6, bid bits=16, seal_rounds=24, seal_strands=8
```

Note scheme: value `v` -> subspace state `|A_v>`, `A_v = ker(H_v)`; `H_v` has 4 rows over
8 bits, row `i` = `sha256("eastreach-note-v{v}-{i}")` **truncated to 8 bits** (skipping
rows that don't raise rank). Verify: house prepares your circuit and checks every
Z-reading lies in `A_v` and every X-reading in `A_v^perp`.

## Stage 1 — forge a note (CSS code state)

`|A_v>` is the uniform superposition over the linear code `C = ker(H_v)` (a `[8,4]`
code). This is exactly a CSS stabiliser state: Z-stabilisers are the rows of `H_v`
(so Z-readings satisfy `H_v x = 0` ⇒ `x ∈ A_v`), and after `H^⊗8` the state is the
uniform superposition over `A_v^perp = rowspace(H_v)` (X-readings in `A_v^perp`).

Prepare `Σ_{c∈C}|c>` with a standard code-superposition circuit:

1. Build `H_v`; the truncation is the **low byte** (`sha256(...)[31]`), bit `k` = qubit
   `k` (LSB-first). *(Determined by trying the 4 byte/bit conventions — only this one
   seats.)*
2. Basis of `ker(H_v)` in RREF (4 vectors, distinct pivot columns).
3. `H` on each pivot qubit, then `CX(pivot, j)` for every set non-pivot bit `j`.

```python
note_circuit(4919) = [['H',0],['H',1],['H',2],['H',5],
                      ['CX',0,4],['CX',0,7],['CX',1,6],['CX',2,6],['CX',5,7]]
POST /api/enter -> {"seated": true}
```

## Stage 2 — read the sealed book (BB84 basis trick)

Each rival's 16-bit bid is stored "qubit by qubit", but each qubit is prepared in a
**random basis** (some `|0>/|1>`, some `|+>/|->`). A naive Z read gives noise, but we
may measure *any* work-tape qubit — so measure each qubit in **both** Z and X and take
whichever basis is deterministic across shots:

```python
z = measure(bidder,pos,"Z"); x = measure(bidder,pos,"X")
bit = z[0] if all_equal(z) else x[0]      # X: |+>=0, |->=1
```

Reconstruct all six 16-bit bids; the clearing price is the max. Reading bit `p` as the
`2^(15-p)` place (MSB-first) gives the winner **bidder 3 = 63543** (the LSB-first
reading, 60447, is rejected — settle confirms the endianness).

## Stage 3 — pass the seal-check (EPR commitment cheat)

`seal/commit + peek + open` is the same non-binding bit-commitment game as *The Coin
That Won't Land*: you commit 8 two-qubit strands (you keep `a`, the house seals `b`),
the house names a random basis `c`, and your opened bits must equal its reading of each
`b`. Commit each strand as a **Bell pair** `Φ⁺` (`H a; CX a→b`) — correlated in both Z
and X — then `peek` your `a`-qubits in basis `c` and `open` those `a_outcomes`. Holds
all 24 rounds.

## Stage 4 — settle

Pay the clearing price with a forged note of that exact value:

```python
POST /api/settle {token, circuit: note_circuit(63543), value: 63543}
-> {"settled": true, "deed": "HTB{...}"}
```

```

```

### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon


- A note = uniform superposition over a classical linear code `ker(H)` — a textbook
  CSS state; prepare it with `H` on the free qubits + `CX` down the RREF generator rows.
- "Sealed" BB84-style qubits are readable if you can choose the measurement basis:
  measure Z and X, keep the deterministic one.
- Quantum bit commitment isn't binding — the `Φ⁺` EPR pair answers any Z/X challenge,
  so the 24-round seal-check is free. *Forged, read, and settled to the silver.*
