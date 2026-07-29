# The Coin That Won't Land — HTB Quantum Writeup

**Category:** Quantum
**Author:** Mohammed Ali  


---

## Recon

The "Oathbinding Court" service (gunicorn/Flask) is a **quantum bit-commitment /
coin-flip** game. Per `/api/oath`:

```
POST /api/new    -> { token, strands: 8, rounds: 32 }
POST /api/commit {token, slots:[<strand> x8]} -> {challenge: c, round}
     each strand is a 2-qubit circuit over a,b applied to |00>; you keep a, Warden seals b
POST /api/peek   {token, basis}  -> measure your kept a-qubits in Z or X -> {a_outcomes:[...]}
POST /api/open   {token, values} -> Warden measures each b in basis c
     (c=0 -> Z, c=1 -> X); the oath holds only if every value matches
rounds: 32, strands: 8 — every round must hold ("2^-32 by luck alone")
```

Each round: you commit 8 two-qubit circuits, the court reveals a random challenge
basis `c`, and you must open 8 bits that equal the Warden's measurement of each `b`
in basis `c`. Guessing gives `1/2` per round → `2^-32` overall.

## The weakness — an EPR pair opens both ways

You control the committed circuit *and* you keep qubit `a`. Commit each strand as a
**Bell / EPR pair** `Φ⁺ = (|00> + |11>)/√2`:

```
strand = [ ["H","a"], ["CX","a","b"] ]     # H on a, then CX a->b
```

`Φ⁺` is correlated in **both** measurement bases:

- Z basis: `(|00> + |11>)/√2`  → `a == b`.
- X basis: `Φ⁺ = (|++> + |-->)/√2` → `a == b` as well.

So whatever basis `c` the court chooses, measuring your kept `a` in that same basis
yields exactly what the Warden will read from `b`. This is the standard reason
quantum bit commitment is impossible: the committer can defer/steer the value via
entanglement (the coin never lands).

## Solve

For each of the 32 rounds: commit 8 EPR pairs, read the challenge `c`, `peek` your
`a`-qubits in basis `c`, and `open` with those outcomes.

```python
bell = [["H","a"], ["CX","a","b"]]
tok  = POST("/api/new")["token"]
for _ in range(32):
    c    = POST("/api/commit", {"token": tok, "slots": [bell]*8})["challenge"]
    outs = POST("/api/peek",   {"token": tok, "basis": "Z" if c==0 else "X"})["a_outcomes"]
    POST("/api/open", {"token": tok, "values": outs})
# -> {"flag": "...", "passes": 32, "round_held": true, "rounds_done": 32}

### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon
