# The Far Orchard — Complete Solution
**Author:** Mohammed Ali  

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [The Vulnerability](#the-vulnerability)
3. [Technical Deep Dive](#technical-deep-dive)
4. [Why It Works](#why-it-works)
5. [Installation & Setup](#installation--setup)
6. [Usage](#usage)
7. [Files Overview](#files-overview)
8. [Step-by-Step Walkthrough](#step-by-step-walkthrough)
9. [Expected Output](#expected-output)
10. [Troubleshooting](#troubleshooting)

---

## Executive Summary

**The Far Orchard** is a ZK circuit challenge masquerading as a blockchain-based vow registry. Eight "Goldleaf Far-Seals" are locked behind what appears to be a zero-knowledge proof of discrete-log knowledge — but the circuit has a classic ZK design flaw: **the base point used in the scalar multiplication is a free witness, never anchored to any fixed generator**.

This means that for any of the 8 registered public keys (all published via the API), an attacker can forge a valid proof in seconds without knowing the actual private key. The proof passes local verification, the validator issues a signature, and the attacker's `honorSeal()` call goes through on-chain. Repeat 8 times and all seals fall.

**What you get:**
- A Rust exploit binary that forges all 8 proofs in one run (~10–30 seconds after params setup)
- A Python driver script that orchestrates the full flow (API → forge → verify → on-chain)
- A complete write-up of why the circuit is broken

**What you need:**
- Rust toolchain (`rustup`)
- Foundry (`cast` command)
- Python 3 + `requests` library
- Network access to the challenge server

---

## The Vulnerability

### What's Actually Being Checked

When you call `FarOrchard.honorSeal(sealId, nullifier, signature)`, the contract only verifies the **validator's signature**. There's no ZK verification on-chain — the entire security model is: *"I'll sign this honor receipt only if the HTTP `/api/verify` endpoint accepted a ZK proof claiming you know the secret key of one of the 8 registered public keys."*

So the entire challenge reduces to one question: **Can you make `/api/verify` accept a proof you shouldn't be able to create?**

### The Circuit's Intended Design (Orchard-Inspired)

Looking at `src/circuit.rs`, the circuit is loosely based on Zcash Orchard spend proofs. It:

1. Takes a secret scalar `sk` and a curve point `g_d` as private inputs
2. Computes `pk := [sk] · g_d` (scalar multiplication)
3. Derives `nullifier := [sk] · G` where `G` is a fixed generator
4. Checks that `pk`'s x-coordinate is a Merkle leaf under the published root
5. Exposes `(merkle_root, nullifier_x, pk_x)` as public inputs

In a real design (Orchard), `g_d` would be the protocol's fixed generator `G`, and proving `pk = [sk] · G` would indeed prove you know the discrete log of `pk`. But here, `g_d` is **arbitrary**.

### The Bug: An Unanchored Witness

```rust
// From src/circuit.rs, FarOrchardConfig::synthesize
let g_d = NonIdentityPoint::new(ecc_chip.clone(), .., self.g_d)?;   // <-- FREE WITNESS
let (pk, _) = g_d.mul(.., sk_scalar)?;                              // pk := [sk] · g_d
let nullifier = nullifier_base.mul(.., sk_cell.clone())?;           // nf := [sk] · G  (fixed)
```

`g_d` is witnessed using `NonIdentityPoint::new`, which (see `chip/witness_point.rs`, lines 1–150) only enforces two constraints:

1. The point is on the curve: `y² = x³ + b`
2. The point is not the identity: `(x, y) ≠ (0, 0)`

That's it. `g_d` is **never exposed as a public input**, never checked against the fixed generator `G`, and never constrained to any specific value. It's a completely free witness — the prover can set it to anything on the Pallas curve.

### Exploit: Forging Any Proof

Given:
- A target registered public key's x-coordinate: `pk_x_i` (all 8 are public)
- Any nonzero scalar you choose: `sk`

You can trivially satisfy `pk == [sk] · g_d` by setting:

```
g_d := sk⁻¹ · pk_point_i
```

where `pk_point_i` is some point with x-coordinate `pk_x_i` (recoverable via `sqrt`).

Then:
```
[sk] · g_d = [sk] · (sk⁻¹ · pk_point_i) = pk_point_i  ✓
```

The forged `pk`'s x-coordinate equals a registered Merkle leaf, so the (otherwise honest) Merkle-path check passes. The nullifier `[sk] · G` uses *your* chosen `sk`, so picking a distinct `sk` per seal avoids nullifier collisions. The proof verifies completely legitimately, the validator signs, and you own a seal you never actually proved knowledge of.

---

## Technical Deep Dive

### The ECC Chip's Witness Gate

From `crates/halo2_gadgets/src/ecc/chip/witness_point.rs` (lines 54–92):

```rust
meta.create_gate("witness non-identity point", |meta| {
    let q_point_non_id = meta.query_selector(self.q_point_non_id);
    Constraints::with_selector(q_point_non_id, Some((
        "on_curve",
        // y² - (x³ + b)
        y.square() - (x.clone().square() * x) - Expression::Constant(b)
    )))
});
```

This is a **single polynomial constraint**: `q_point_non_id · (y² - x³ - b) = 0`, enforcing the curve equation. No additional constraints bind the point to anything else. The "non-identity" check is a runtime panic in Rust (line 205: `value.error_if_known_and(...)`), not a circuit constraint.

### Scalar Field Arithmetic

Pallas/Vesta are "pasta curves" (`pasta_curves` crate, pinned to v0.5.1 in `Cargo.lock`), with field arithmetic from `ff` v0.13.1. Both support:

- `.sqrt()` → `CtOption<Self>`, finds a square root if it exists
- `.invert()` → `CtOption<Self>`, computes multiplicative inverse
- `Field::random(rng)` for random sampling

All three are used in the exploit and confirmed to exist in the vendored source.

### Merkle Tree & Proof Wire Format

`merkle.rs` implements Sinsemilla hashing (the Zcash construction) and Merkle paths. The `MerkleTree::path(i)` method returns a `Vec<Base>` of sibling hashes at each level (depth 3 for 8 leaves). The proof wire format (`serialize_proof`) embeds the proof bytes along with public inputs, so the Python driver can extract the nullifier (bytes 32–64 of the hex string) without trusting the JSON response.

---

## Why It Works

### 1. No Discrete Log Knowledge Required

Without an anchor tying `g_d` to a fixed base, the relation `pk = [sk] · g_d` is **satisfiable by construction** for *any* target `pk` and *any* nonzero `sk`. There's no hidden discrete log; you're choosing both `g_d` and `sk` to make the math work.

### 2. Merkle Tree Still Works

The Merkle path check is honest — it verifies that your forged `pk_x` really is a registered leaf. But that's intentional: all 8 leaf values are public in `/api/info`, so there's nothing secret about *which* leaf you claim to know the discrete log of. The bug is that you're *not* proving knowledge of *any* discrete log — you're just proving membership in the set, which you already knew from the public data.

### 3. Nullifier Uniqueness Avoids Collisions

Each seal gets its own `nullifier = [sk_i] · G` with a distinct `sk_i` (e.g., `sk_i = 0xC0FFEE + i`). Since `G` is fixed and all `sk_i` are distinct, all nullifiers are distinct, so the on-chain `honoredBitmap` doesn't reject any of them.

### 4. Validator Signs Without Checking

`/api/verify` only cares that the ZK proof verifies. It doesn't verify the discrete log itself (that's the proof's job) or cross-check against a real private key. Once the proof passes, it signs immediately.

---

## Installation & Setup

### Prerequisites

You need:
- **Rust toolchain** (Cargo + rustc)
- **Foundry** (`cast` command for on-chain calls)
- **Python 3** with `pip`
- **Network access** (for crates.io and the challenge server)

### Step 1: Install Rust (if not already installed)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
cargo --version  # should print "cargo 1.x.x"
rustc --version  # should print "rustc 1.x.x"
```

### Step 2: Install Foundry

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
cast --version  # should print "cast 0.x.x"
```

### Step 3: Install Python Dependencies

```bash
pip install requests
```

### Step 4: Obtain the Challenge Release

Download `release.zip` from the challenge server and extract it. You should have a folder structure like:

```
release/
├── Cargo.toml
├── Cargo.lock
├── crates/
│   ├── halo2_gadgets/
│   ├── halo2_poseidon/
│   └── halo2_proofs/
├── setup/
│   └── src/
│       ├── FarOrchard.sol
│       └── Setup.sol
└── src/
    ├── circuit.rs
    ├── merkle.rs
    ├── verifier.rs
    ├── main.rs
    └── lib.rs
```

### Step 5: Copy the Exploit Binary

Create the `src/bin/` folder and copy `exploit.rs`:

```bash
mkdir -p release/src/bin
cp exploit.rs release/src/bin/exploit.rs
```

### Step 6: Build the Exploit

```bash
cd release
cargo build --release --bin exploit
```

**First build:** This will compile the entire vendored `halo2_proofs`/`halo2_gadgets` stack (several gigabytes of intermediate objects). Expect 5–15 minutes depending on your CPU.

**Subsequent builds:** Should be nearly instant if only `exploit.rs` changes.

### Step 7: Verify the Build Succeeded

```bash
ls -lh target/release/exploit
```

Should show an executable of ~10–20 MB.

---

## Usage

### Option A: Full Automated Run (Python Driver)

```bash
python3 solve.py \
  --host http://154.57.164.67:31154 \
  --exploit-bin ./release/target/release/exploit
```

**What it does:**
1. Calls `POST /api/launch` to start a fresh instance
2. Calls `GET /api/info` to get the 8 registered public keys and Merkle root
3. Runs the compiled Rust exploit binary with those values
4. For each seal ID (0–7):
   - Calls `POST /api/verify` with the forged proof
   - Extracts the nullifier from the proof wire format
   - Calls `cast send honorSeal(...)` on-chain
5. Calls `cast call isSolved()` to verify all 8 seals are honored
6. Calls `GET /api/flag` and prints the flag

### Option B: Manual Step-by-Step

If you want to drive each step yourself:

**1. Launch the instance:**
```bash
curl -s -X POST http://154.57.164.67:31154/api/launch | jq .
```

Save the `RPC_URL`, `PRIVKEY`, `SETUP_CONTRACT_ADDR`, and `WALLET_ADDR`.

**2. Get the merkle info:**
```bash
curl -s http://154.57.164.67:31154/api/info | jq .
```

Extract `merkle_root`, the 8 `pk_x` values (indexed by `seal_id`), and `orchard_address`.

**3. Run the exploit binary:**
```bash
./release/target/release/exploit \
  <merkle_root_hex> \
  <pk_x_seal_0> <pk_x_seal_1> ... <pk_x_seal_7>
```

This outputs 8 lines like:
```
SEAL=0 PROOF=<long hex string>
SEAL=1 PROOF=<long hex string>
...
```

**4. Verify each proof and honor the seal:**

For each line, extract the proof hex and submit:

```bash
# Verify the proof (example for seal 0)
PROOF="<hex from SEAL=0 line>"
RESPONSE=$(curl -s -X POST http://154.57.164.67:31154/api/verify \
  -H "Content-Type: application/json" \
  -d "{\"proof\": \"$PROOF\", \"seal_id\": 0}")
SIG=$(echo "$RESPONSE" | jq -r .signature)

# Extract nullifier (bytes 32–64 of hex = chars 64–128)
NULLIFIER="0x${PROOF:64:64}"

# Honor on-chain
cast send <ORCHARD_ADDR> "honorSeal(uint256,bytes32,bytes)" 0 "$NULLIFIER" "$SIG" \
  --rpc-url <RPC_URL> --private-key <PRIVKEY>
```

Repeat for seal IDs 1–7.

**5. Check and claim:**
```bash
cast call <SETUP_ADDR> "isSolved()(bool)" --rpc-url <RPC_URL>
curl -s http://154.57.164.67:31154/api/flag
```

---

## Files Overview

### `exploit.rs`

The core Rust exploit binary. Lives at `release/src/bin/exploit.rs` after you copy it.

**Key functions:**
- `normalize_hex(s)` — Strips `0x` prefix, left-pads to 64 chars (32 bytes)
- `parse_field_hex(s)` — Parses hex string to `pallas::Base` field element
- `parse_field_hex_reversed(s)` — Same, but with reversed byte order (fallback for big-endian)
- `point_from_x(x)` — Recovers a curve point from its x-coordinate via `sqrt`
- `main()` — Drives the full exploit:
  1. Parses command-line args (root + 8 leaf x-coords)
  2. Auto-detects hex byte order by rebuilding the Merkle tree locally
  3. Generates halo2 params (once) + proving/verifying keys
  4. For each seal ID:
     - Chooses a throwaway `sk`
     - Computes `g_d := sk⁻¹ · pk_target`
     - Creates and proves the circuit
     - **Self-verifies the proof locally** (catches bugs early)
     - Outputs `SEAL=<id> PROOF=<hex>`

**Important:** The binary self-verifies each proof before printing it. If it panics, there's a bug in the proof generation or the math is wrong — you'll see the panic message immediately rather than a confusing rejection from the server.

### `solve.py`

Python driver script that orchestrates the full API + on-chain flow.

**Key functions:**
- `cast(*args)` — Wrapper around the `cast` command-line tool
- `find_key(d, *names)` — Defensive JSON field lookup (tries multiple possible key names)
- `main()` — Orchestrates:
  1. `POST /api/launch`
  2. `GET /api/info`
  3. Shells out to the exploit binary
  4. For each seal: `POST /api/verify`, extract nullifier, `cast send honorSeal(...)`
  5. `cast call isSolved()`, `GET /api/flag`

**Caveats:**
- The exact JSON field names from `/api/launch` and `/api/verify` are not documented in the released code (only the Solidity/Rust side is). The `find_key()` function tries several likely names; if it fails, it will print the raw JSON so you can see the actual keys.
- The nullifier is extracted from the proof wire format (bytes 32–64), not from the JSON response, so you're not trusting the server for that critical value.

### `SOLUTION.md`

A shorter summary of the vulnerability and the approach. Suitable for quick reference.

---

## Step-by-Step Walkthrough

### Full Walkthrough Using the Automated Driver

Assume you have `release/` extracted and `exploit.rs` placed at `release/src/bin/exploit.rs`.

```bash
# Build
cd release
cargo build --release --bin exploit
cd ..

# Run the solver
python3 solve.py \
  --host http://154.57.164.67:31154 \
  --exploit-bin ./release/target/release/exploit
```

**Expected output:**

```
[*] /api/launch -> {"RPC_URL": "...", "PRIVKEY": "...", ...}
[*] /api/info -> {"merkle_root": "0x...", "merkle_leaves": [...], "orchard_address": "0x...", ...}
[*] Forging proofs locally (this runs the Rust exploit binary)...
[*] Hex looks little-endian - locally rebuilt root matches. Good.
[*] Setting up halo2 params (k=13)... this can take a little while.
[*] Keys ready. Forging proofs for all 8 seals...
[*] Seal 0: generating proof...
[+] Seal 0: proof self-verifies OK (pk_x=0x...).
...
[*] Seal 0: /api/verify seal 0 -> {...}
[*] Honoring seal 0 on-chain...
[+] Seal 0 honored.
...
[*] isSolved() -> true
[*] /api/flag -> FLAG{...}
```

### Manual Walkthrough (Step-by-Step)

If you prefer to drive each step by hand:

**Step 1: Launch**
```bash
curl -s -X POST http://154.57.164.67:31154/api/launch | jq .
```

Save the response values.

**Step 2: Info**
```bash
curl -s http://154.57.164.67:31154/api/info | jq .
```

Extract `merkle_root` and all 8 `pk_x` values (in seal_id order).

**Step 3: Forge**
```bash
./release/target/release/exploit \
  0x<merkle_root_without_prefix> \
  0x<pk_x_0> 0x<pk_x_1> ... 0x<pk_x_7>
```

The output will be 8 lines. Save them all.

**Step 4: Verify and Honor (example for seal 0)**
```bash
PROOF="<hex from SEAL=0>"
RESPONSE=$(curl -s -X POST http://154.57.164.67:31154/api/verify \
  -H "Content-Type: application/json" \
  -d "{\"proof\": \"$PROOF\", \"seal_id\": 0}")
echo "$RESPONSE" | jq .
SIG=$(echo "$RESPONSE" | jq -r .signature)
NULLIFIER="0x${PROOF:64:64}"

cast send 0x<ORCHARD_ADDR> "honorSeal(uint256,bytes32,bytes)" 0 "$NULLIFIER" "$SIG" \
  --rpc-url "http://<RPC_URL>" --private-key "0x<PRIVKEY>"
```

Repeat for seals 1–7.

**Step 5: Check**
```bash
cast call 0x<SETUP_ADDR> "isSolved()(bool)" --rpc-url "http://<RPC_URL>"
curl -s http://154.57.164.67:31154/api/flag
```

---

## Expected Output

### From the Rust Exploit Binary

```
[*] Hex looks little-endian - locally rebuilt root matches. Good.
[*] Setting up halo2 params (k=13)... this can take a little while.
[*] Keys ready. Forging proofs for all 8 seals...
[*] Seal 0: generating proof...
[+] Seal 0: proof self-verifies OK (pk_x=0x1234567890abcdef...).
SEAL=0 PROOF=abcd1234...
[*] Seal 1: generating proof...
[+] Seal 1: proof self-verifies OK (pk_x=0x...).
SEAL=1 PROOF=...
...
[*] Done. Feed each SEAL=<id> PROOF=<hex> line to POST /api/verify.
```

Each proof hex is ~2000 characters (the Halo2 IPA proof for PLONK at k=13).

### From the Python Driver

```
[*] /api/launch -> {
  "RPC_URL": "http://...:31154/rpc/...",
  "PRIVKEY": "0x...",
  "SETUP_CONTRACT_ADDR": "0x...",
  "WALLET_ADDR": "0x..."
}
[*] /api/info -> {
  "merkle_root": "0x...",
  "merkle_leaves": [...],
  "total_seals": 8,
  "setup_address": "0x...",
  "orchard_address": "0x...",
  "validator_signer": "0x..."
}
[*] Forging proofs locally (this runs the Rust exploit binary)...
[...output from exploit binary...]
[*] /api/verify seal 0 -> {
  "signature": "0x...",
  "nullifier": "0x...",
  "seal_id": 0
}
[*] Honoring seal 0 on-chain...
[+] Seal 0 honored.
...
[*] isSolved() -> true
[*] /api/flag -> FLAG{the_far_orchard_falls_to_an_unanchored_witness}
```

---

## Troubleshooting

### `cargo build` fails with a type error

**Most likely causes:**

1. **`CtOption` vs `Option` confusion** — `pasta_curves` uses `CtOption` from the `subtle` crate for constant-time operations. If you see an error like `expected CtOption, found Option`, check the import:

   ```rust
   use subtle::CtOption;
   ```

   The exploit uses `.sqrt()` which returns `CtOption`, and `.invert()` which also returns `CtOption`. Both are `.unwrap()`'d directly in the code.

2. **Field/Scalar mismatch** — `pallas::Base` is the field, `pallas::Scalar` is the scalar. If you see a type error around line 144–145, ensure:

   ```rust
   let sk_scalar = pallas::Scalar::from_repr(sk.to_repr()).unwrap();
   ```

   This converts from the field representation to the scalar field.

3. **Value::known vs Value::unknown** — The circuit takes `Value<T>` for private inputs. `Value::known(x)` is what we use; never `Value::unknown()`.

**Solution:** Paste the exact error message in an issue, and I'll fix it immediately.

### `exploit` binary panics with "self-verification of freshly generated proof FAILED"

This means the proof you just generated doesn't verify under the same verifying key. Likely causes:

1. **The Merkle root doesn't match locally** — The exploit tries both little-endian and big-endian parsing. If it prints a `[!] WARNING:`, the root didn't match either way. Double-check:
   - You're passing the 8 `pk_x` values in seal_id order (0, 1, 2, ... 7)
   - The `merkle_root` hex is correct (copy from `/api/info`)

2. **A public-input mismatch** — The proof commits to `(merkle_root, nullifier_x, pk_x)` as public inputs. If any of these don't match what the verifying key expects, the proof fails self-verification. This would be a bug in the code — file an issue with the full panic output.

### `solve.py` fails with "KeyError: none of ['RPC_URL', ...] found in response"

The `/api/launch` or `/api/verify` responses use different JSON field names than expected. The script will print the raw response — look at the actual keys and add them to the `find_key()` call in `solve.py`.

For example, if `/api/launch` returns:
```json
{"rpc": "http://...", "private_key": "0x...", ...}
```

Change line in `solve.py`:
```python
rpc_url = find_key(launch_data, "RPC_URL", "rpc_url", "rpc")
```

### `cast send` fails with "insufficient funds" or "invalid signature"

1. **Insufficient funds:** The prover wallet doesn't have enough gas. Check the `WALLET_ADDR` has ETH:
   ```bash
   cast balance <WALLET_ADDR> --rpc-url <RPC_URL>
   ```

2. **Invalid signature:** The `SIG` from `/api/verify` is malformed, or the nullifier extraction went wrong. Print both:
   ```bash
   PROOF="..."
   NULLIFIER="0x${PROOF:64:64}"
   echo "Nullifier: $NULLIFIER"
   RESPONSE=$(curl -s -X POST ... )
   echo "Response: $RESPONSE"
   ```

### `cast call isSolved()` returns false after honoring all 8 seals

This means not all 8 seals made it on-chain. Likely causes:

1. **One of the `cast send honorSeal` calls silently failed** — `cast` doesn't error on transaction revert; it just shows the transaction hash. Check each transaction on the block explorer (if accessible) or re-run `solve.py` with more verbose output.

2. **The validator signer isn't the right address** — `/api/verify` returns a signature from `validator_signer`. The on-chain contract checks `ecrecover(...)` against that address. If the signature is wrong, `honorSeal` will revert silently.

3. **Seal was already honored** — If you run the solver twice on the same instance, the second run's transactions will revert (you can't honor the same seal twice). Kill the instance and launch a fresh one.

---

## Why This Works: The Math

### Problem Setup

- **Given:** A registered public key's x-coordinate `pk_x_i` (public knowledge)
- **Goal:** Prove knowledge of the discrete log without actually knowing it
- **Circuit constraint:** `pk == [sk] · g_d` for some witness `g_d`

### Solution

1. **Choose** an arbitrary nonzero scalar `sk_i` (e.g., `0xC0FFEE + i`)
2. **Recover** a curve point with x-coordinate `pk_x_i`:
   ```
   y² = pk_x_i³ + b
   y = sqrt(y²)  [either of 2 roots; doesn't matter which]
   pk_point_i = (pk_x_i, y)
   ```
3. **Compute** the "base point":
   ```
   g_d := sk_i⁻¹ · pk_point_i
   ```
4. **Verify:**
   ```
   [sk_i] · g_d = [sk_i] · (sk_i⁻¹ · pk_point_i) = pk_point_i
   ```
   The x-coordinate still equals `pk_x_i`, which is a Merkle leaf. ✓

5. **Nullifier** is `[sk_i] · G` using your own `sk_i`, so all 8 nullifiers are distinct (different `sk_i` values).

No discrete log knowledge required anywhere — `g_d` was constructed to make the math work.

---

## Formal Analysis

### What the Circuit Enforces

Looking at `src/circuit.rs`:

| Constraint | Enforced | Bind-to-Fix | 
|---|---|---|
| `pk = [sk] · g_d` | ✓ Yes (scalar mult gate) | Not yet applied — `g_d` is free |
| `nf = [sk] · G` | ✓ Yes (fixed base scalar mult) | Yes — `G` is fixed |
| `pk_x is in Merkle tree` | ✓ Yes (Sinsemilla path check) | Not needed — `pk_x` is public |
| `g_d is on curve` | ✓ Yes (NonIdentityPoint gate) | No — this is insufficient |
| `g_d = G` or `g_d is some fixed value` | ✗ **No** | **This is the missing constraint** |

### Why the Fix Would Be Simple

To patch the circuit, you'd add one line in `synthesize`:

```rust
let g_d_fixed = <protocol's fixed point>;  // e.g., precomputed G
g_d.constrain_equal(layouter, &g_d_fixed)?;  // force equality
```

This would expose `g_d` to a constraint that ties it to a known value, making the forged relation impossible.

---

## References

- **Halo2:** https://github.com/zcash/halo2
- **Zcash Orchard:** https://zips.z.cash/protocol/nu5.pdf
- **ECC chip (where the bug surfaces):** `crates/halo2_gadgets/src/ecc/chip/witness_point.rs`
- **Circuit (where g_d is used):** `src/circuit.rs`

---

## License & Attribution

This solution is provided for educational purposes. The vulnerability is a real ZK circuit design flaw. The exploit demonstrates why anchoring witness inputs is critical in zero-knowledge proof systems.

---

## Questions?

If you hit any issues:
1. Check the **Troubleshooting** section above
2. Verify all inputs (Merkle root, pk_x values) are correct
3. Run with verbose output: `python3 solve.py ... 2>&1 | head -50`
4. Paste the exact error message

Good luck! 🍂


### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon


