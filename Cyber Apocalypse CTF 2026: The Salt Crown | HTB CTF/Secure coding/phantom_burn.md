# Phantom Burn — HTB Apocalypse  Challenge Writeup
**Author:** Mohammed Ali  

> **Category:** Secure Coding / Smart Contracts  
> **Difficulty:** Hard  
> **Status:** ✅ Solved (PR #32 accepted — Hard Score Testing Passed)
---

## Challenge Overview

**Phantom Burn** is a secure-coding challenge built around an archival service backed by an Ethereum smart contract registry. Players are given a `developer` branch and must patch a series of vulnerabilities in a cross-component stack: a Solidity registry contract, a Node.js operator console (`app`), and a separate Node.js archive gate service (`archive-service`).

The objective is to **eliminate every trust path that relies on client-supplied or public-ledger metadata** for authorization decisions, replacing them with cryptographic binding to verified on-chain events.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  External Clients / Operators                           │
└───────────────────┬─────────────────────┬───────────────┘
                    │ /app/*               │ /archive/*
                    ▼                      ▼
         ┌──────────────────┐    ┌─────────────────────┐
         │  app (port 5000) │    │ archive-service     │
         │  - Operator UI   │    │ (port 5001)         │
         │  - Session auth  │    │ - /archive/open     │
         │  - /api/source/  │    │ - verifyReceipt()   │
         │    unlock        │    │ - markConsumed()    │
         │    bundle        │    └──────────┬──────────┘
         └──────────┬───────┘               │
                    │                        │
                    ▼                        ▼
         ┌──────────────────────────────────────────────┐
         │  Ethereum Node (Anvil / Foundry)              │
         │  ShardRegistry.sol — 0x...registryAddress    │
         └──────────────────────────────────────────────┘
```

### Key Files

| File | Purpose |
|------|---------|
| `contracts/src/ShardRegistry.sol` | On-chain registry; stores filing shards |
| `contracts/src/interfaces/IShardRegistry.sol` | Solidity ABI interface |
| `app/src/sourceVault.ts` | Off-chain filing resolver & token issuer |
| `app/src/routes.ts` | Express routes for `/api/source/unlock` and `/api/source/bundle` |
| `app/src/config.ts` | App configuration (RPC, registry address, confirmations) |
| `archive-service/src/chainReceipt.ts` | Receipt verifier — the security core |
| `archive-service/src/receiptStore.ts` | One-time consumption store |
| `archive-service/src/routes.ts` | Archive gate API (`/archive/open`) |

---

## Vulnerabilities Identified

### 1. 🔴 `unlockSeal` Published to Public Ledger (Contract)

**File:** `contracts/src/ShardRegistry.sol`

**Vulnerable code (original):**
```solidity
// Seal that downstream archive services use to reference this filing.
bytes32 unlockSeal = keccak256(abi.encodePacked("PHANTOM_BURN_ARCHIVE:", archiveKey));

shards[shardId] = Shard({
    owner: msg.sender,
    uri: uri,
    commitment: commitment,
    unlockSeal: unlockSeal,   // ← published on-chain!
    nonce: nonce
});

emit ShardFiled(msg.sender, shardId, uri, unlockSeal, nonce); // ← emitted in event!
```

**Impact:** Any observer of the blockchain can derive the `archiveKey` from the emitted `unlockSeal`. This means the archive gate's bearer capability is publicly disclosed on the ledger the moment a shard is filed.

---

### 2. 🔴 Client-Supplied `unlockSeal` Accepted for Authorization (App)

**File:** `app/src/sourceVault.ts`

**Vulnerable code (original):**
```typescript
if (receipt.unlockSeal) {
  const expectedCommitment = keccak256(
    encodePacked(["string", "bytes32"], ["PHANTOM_BURN_ARCHIVE:", receipt.unlockSeal as `0x${string}`])
  );
  if (args.unlockSeal !== expectedCommitment) {
    return null;
  }
} else {
  // Must provide the unlock seal to prove ownership of the filing
  return null;
}
```

**Impact:** The app trusts `receipt.unlockSeal` supplied by the caller to gate access. Since this seal is already published on-chain (Bug #1), any unauthorized party can read it from the blockchain and replay it to unlock the archive.

---

### 3. 🔴 `filingId` Derived from Client-Supplied Metadata (App)

**File:** `app/src/routes.ts`

**Vulnerable code (original):**
```typescript
// Filing ID was derived from request body, not chain truth
const filingId = `${receipt.owner}:${receipt.shardId}:${receipt.nonce}`;
issuedTokens.add(filingId);
```

**Impact:** An attacker can manipulate `owner`, `shardId`, or `nonce` in the request body to generate novel `filingId` values and bypass the one-time consumption check.

---

### 4. 🔴 Receipt ID Uses Client-Provided Fields (Archive Service)

**File:** `archive-service/src/chainReceipt.ts`

**Vulnerable code (original):**
```typescript
export function receiptId(receipt: ChainReceipt): string {
  return crypto.createHash("sha256")
    .update([receipt.registry, receipt.owner, receipt.shardId, receipt.txHash, receipt.logIndex].join(":"))
    .digest("hex");
}
```

**Impact:** Including `owner` and `shardId` in the receipt ID (values controlled by the caller) means the replay barrier can be trivially bypassed by altering these fields in the request.

---

### 5. 🔴 In-Memory Consumption Store (Both Services)

**Files:** `app/src/routes.ts`, `archive-service/src/receiptStore.ts`

**Vulnerable code (original):**
```typescript
const issuedTokens = new Set<string>();
// ...
const consumed = new Set<string>();
```

**Impact:** Restarting either service resets the consumed-token store, allowing replay attacks across restarts.

---

### 6. 🔴 `shardId` Returned from Request Context (Archive Service)

**File:** `archive-service/src/routes.ts`

**Vulnerable code (original):**
```typescript
res.json({
  opened: true,
  shardId: receipt.shardId,   // ← from request body, not chain!
  grants: ["source:read", "decree:audit"]
});
```

**Impact:** Grant response includes caller-controlled `shardId`, not the chain-verified value.

---

### 7. 🔴 Bundle Download Does Not Re-verify Chain (App)

**Original behavior:** The `/api/source/bundle` endpoint verified only the HMAC token signature but did not re-resolve the filing from the chain. It also used an in-memory allowlist that was not durable.

---

## The Fix — Complete Patch

### Vulnerability 1 Fix: Zero Out `unlockSeal` On-Chain

**`contracts/src/ShardRegistry.sol`:**
```solidity
// archiveKey accepted for interface compatibility but seal is ALWAYS zeroed
// to prevent entitlement material from leaking into the public ledger.
bytes32 unlockSeal = bytes32(0);

shards[shardId] = Shard({
    owner: msg.sender,
    uri: uri,
    commitment: commitment,
    unlockSeal: unlockSeal,   // always bytes32(0)
    nonce: nonce
});

emit ShardFiled(msg.sender, shardId, uri, unlockSeal, nonce);
```

The public ABI (`IShardRegistry`) is preserved for backward compatibility — `archiveKey` is still accepted but silently discarded. The `unlockSeal` field exists in the struct/event but carries no meaningful value.

---

### Vulnerability 2 Fix: Remove `unlockSeal` Validation — Anchor to Chain Events

**`app/src/sourceVault.ts` — `resolveFiling()`:**
```typescript
export async function resolveFiling(config: AppConfig, receipt: UnlockReceipt): Promise<FiledShard | null> {
  const client = createPublicClient({ chain: foundry, transport: http(config.rpcUrl) });
  try {
    const txReceipt = await client.getTransactionReceipt({ hash: receipt.txHash as `0x${string}` });
    
    // Enforce configurable confirmation depth
    const currentBlock = await client.getBlockNumber();
    if (currentBlock - txReceipt.blockNumber < BigInt(config.confirmations)) {
      return null;
    }
    
    // Pin log to configured registry address
    const log = txReceipt.logs.find((entry) => Number(entry.logIndex) === receipt.logIndex);
    if (!log || log.address.toLowerCase() !== config.registryAddress.toLowerCase()) {
      return null;
    }

    // Decode event — ALL values come from chain, not request body
    const decoded = decodeEventLog({ abi: [shardFiledEvent], data: log.data, topics: log.topics });
    const args = decoded.args as { owner: string; shardId: string; uri: string; unlockSeal: string; nonce: bigint };

    return {
      txHash: txReceipt.transactionHash,  // canonical hash from chain
      logIndex: log.logIndex,             // canonical index from chain
      owner: args.owner,                  // chain-decoded
      shardId: args.shardId,             // chain-decoded
      uri: args.uri,
      nonce: args.nonce.toString()
    };
  } catch {
    return null;
  }
}
```

---

### Vulnerability 3 Fix: Canonical `filingId` from Chain Coordinates

**`app/src/routes.ts`:**
```typescript
// Derived from verified chain log coordinates — not caller-supplied metadata
const filingId = `${config.registryAddress}:${filing.txHash}:${filing.logIndex}`;
```

---

### Vulnerability 4 Fix: Receipt ID Uses Only Verified Chain Fields

**`archive-service/src/chainReceipt.ts`:**
```typescript
export function receiptId(registry: string, txHash: string, logIndex: number): string {
  return keccak256(
    encodePacked(
      ["address", "bytes32", "uint256"],
      [
        registry as `0x${string}`,
        txHash as `0x${string}`,
        BigInt(logIndex)
      ]
    )
  );
}
```

The receipt ID is now a `keccak256` of `(registryAddress, txHash, logIndex)` — all values come from the verified on-chain event, not from the caller.

---

### Vulnerability 5 Fix: Durable Atomic Store with Temp+Rename

**`archive-service/src/receiptStore.ts`:**
```typescript
const STORE_PATH = path.resolve(process.cwd(), ".consumed-receipts.json");
const consumed = new Set<string>();

// Hydrate from disk on startup
if (fs.existsSync(STORE_PATH)) {
  const data = JSON.parse(fs.readFileSync(STORE_PATH, "utf8"));
  if (Array.isArray(data)) data.forEach((id) => consumed.add(id));
}

export function markConsumed(receiptId: string): boolean {
  if (consumed.has(receiptId)) return false;
  consumed.add(receiptId);
  
  // Atomic write: temp file → rename, so no partial reads
  const tmp = STORE_PATH + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(Array.from(consumed)));
  fs.renameSync(tmp, STORE_PATH);
  return true;
}
```

Same pattern applied to `app/src/routes.ts` for `consumedFilings`.

---

### Vulnerability 6 + 7 Fix: Full Verifier-Driven Grant Flow

**`archive-service/src/chainReceipt.ts` — `verifyReceipt()`:**

The function signature was changed to remove the `Principal` parameter entirely. All authoritative values are **returned from chain decoding**:

```typescript
export async function verifyReceipt(
  config: ArchiveConfig,
  receipt: ChainReceipt
): Promise<
  { ok: true; receiptId: string; owner: string; shardId: string } |
  { ok: false; reason: string }
> {
  // ... confirmation depth check ...
  // ... log.address pinned to config.registryAddress ...
  // ... event decoded via ABI ...
  
  return {
    ok: true,
    receiptId: receiptId(log.address, txReceipt.transactionHash, log.logIndex),
    owner: args.owner,    // ← from chain
    shardId: args.shardId // ← from chain
  };
}
```

**`archive-service/src/routes.ts` — `/archive/open`:**
```typescript
const verdict = await verifyReceipt(config, receipt);
if (!verdict.ok) { res.status(403).json({ error: verdict.reason }); return; }

// Cross-check caller identity against chain-decoded owner
const claimedPrincipal = String(req.header("x-archive-principal") ?? "");
if (!claimedPrincipal || claimedPrincipal.toLowerCase() !== verdict.owner.toLowerCase()) {
  res.status(403).json({ error: "principal does not match filing owner" });
  return;
}

// One-time consumption via verifier-derived id
if (!markConsumed(verdict.receiptId)) {
  res.status(409).json({ error: "receipt already consumed" });
  return;
}

res.json({
  opened: true,
  owner: verdict.owner,    // ← from chain, not request
  shardId: verdict.shardId, // ← from chain, not request
  grants: ["source:read", "decree:audit"]
});
```

**`app/src/routes.ts` — `/api/source/unlock` (operator session required):**
```typescript
router.post("/api/source/unlock", requireOperator, express.json(), async (req, res, next) => {
  const receipt = req.body as UnlockReceipt;
  const filing = await resolveFiling(config, receipt);
  if (!filing) { res.status(400).json({ error: "invalid receipt" }); return; }

  const filingId = `${config.registryAddress}:${filing.txHash}:${filing.logIndex}`;
  if (consumedFilings.has(filingId)) {
    res.status(403).json({ error: "source already unlocked" });
    return;
  }

  // Token embeds chain-decoded owner — no caller-supplied identity
  const token = deriveArchiveToken(config, filing, filing.owner);
  res.json({ archive: config.archiveBundle, download: "/api/source/bundle", token });
});
```

**`app/src/routes.ts` — `/api/source/bundle` (operator session required):**
```typescript
router.get("/api/source/bundle", requireOperator, async (req, res) => {
  // 1. Verify HMAC signature + expiry
  // 2. Parse token payload (contains txHash, logIndex, owner — all chain-derived)
  // 3. Re-resolve filing from chain
  const filing = await resolveFiling(config, { txHash: body.txHash, logIndex: body.logIndex });
  
  // 4. Cross-check chain-decoded owner with token-embedded owner
  if (!filing || filing.owner.toLowerCase() !== String(body.owner ?? "").toLowerCase()) {
    res.status(403).json({ error: "invalid source token binding" });
    return;
  }

  // 5. One-time consumption
  const filingId = `${config.registryAddress}:${filing.txHash}:${filing.logIndex}`;
  if (consumedFilings.has(filingId)) { res.status(403).json({ error: "source token already consumed" }); return; }
  consumedFilings.add(filingId);
  saveConsumed();

  res.download(bundle, "archive-service.locked.tar.gz");
});
```

---

### Bonus Fix: `config.confirmations` Instead of Magic `12n`

**`app/src/config.ts`:**
```typescript
export type AppConfig = {
  // ...
  confirmations: number;   // ← added
};

export function loadConfig(): AppConfig {
  return {
    // ...
    confirmations: Number(process.env.PHANTOM_BURN_CONFIRMATIONS ?? "12"),
  };
}
```

---

## Trust Model — Before vs After

### Before (Vulnerable)

```
Caller → submits { txHash, logIndex, owner, shardId, unlockSeal, nonce }
           ↓
App trusts: receipt.unlockSeal (client-supplied, also on public ledger)
App derives: filingId = owner:shardId:nonce  (all client-supplied)
Archive returns: shardId = receipt.shardId  (client-supplied)
Store: in-memory Set, lost on restart
```

### After (Hardened)

```
Caller → submits { txHash, logIndex } only
           ↓
App resolves: ALL values from on-chain event
  - Pins log.address → config.registryAddress
  - Enforces config.confirmations depth
  - Decodes ShardFiled event via ABI
  - Returns chain-decoded: owner, shardId, txHash, logIndex
App derives: filingId = registryAddress:txHash:logIndex (chain-canonical)
App issues: signed HMAC token embedding chain-decoded owner
Bundle download: re-resolves from chain, cross-checks owner
Archive: verifyReceipt returns chain-decoded owner+shardId
  - Cross-checks x-archive-principal header against verdict.owner
  - markConsumed uses keccak256(registry||txHash||logIndex)
Store: durable JSON file with atomic temp+rename writes
```

---

## Summary of Files Changed

| File | What Changed |
|------|--------------|
| `contracts/src/ShardRegistry.sol` | `unlockSeal` always `bytes32(0)` — no entitlement on ledger |
| `contracts/test/ShardRegistry.t.sol` | Test verifies seal is zeroed |
| `app/src/config.ts` | Added `confirmations` field |
| `app/src/sourceVault.ts` | `resolveFiling` anchors to chain; `deriveArchiveToken` embeds chain owner |
| `app/src/routes.ts` | Session auth on unlock+bundle; durable atomic consumed store; chain re-resolution on download |
| `app/test/sourceVault.test.mjs` | Updated tests |
| `archive-service/src/chainReceipt.ts` | `verifyReceipt` takes no principal; returns chain owner+shardId; keccak256 receiptId |
| `archive-service/src/receiptStore.ts` | Durable atomic file store |
| `archive-service/src/routes.ts` | Verifier-driven grant; principal cross-checked against chain owner |
| `archive-service/test/chainReceipt.test.mjs` | Updated tests |
| `tools/unlock-source.mjs` | Updated to call API instead of computing token locally |

---

## Key Lessons

1. **Never store bearer capabilities on a public ledger.** The `unlockSeal` was derived from the `archiveKey` and emitted in a blockchain event — publicly visible to anyone.

2. **Never trust client-supplied values for authorization.** All fields that influence access decisions (`owner`, `shardId`, `nonce`) must be derived exclusively from verified on-chain events.

3. **Canonical identifiers must be immutable and unique.** Using `txHash:logIndex` (chain-native) as the filing/receipt ID is collision-resistant and replay-safe, unlike client-supplied fields.

4. **One-time consumption must be durable.** An in-memory `Set` is wiped on restart — use file or database persistence with atomic writes.

5. **Every grant path in every service must apply the same provenance checks.** A vulnerability in one service (archive-service) can undermine security enforced by another (app).

6. **Public ABIs should be preserved.** Changing the `ShardFiled` event signature would break existing integrations. Keep the ABI stable and zero out sensitive fields instead.

### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon


