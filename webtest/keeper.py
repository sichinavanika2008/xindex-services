#!/usr/bin/env python3
"""Web-testbed attestation keeper — the off-chain signer-network SIMULATION.

Watches the deployed `IntentQueue` on local anvil and plays the role the
3-of-5 signer fleet + THORChain cross-chain leg play in production, but
fully simulated (no real BTC/ETH/...):

  * MintIntentCreated   -> collect a 3-of-5 MINT attestation from the live
                           daemons (via the panic-free `attest_mint`
                           example) and post `oracle.attest` for each async
                           slot.
  * RedemptionIntentCreated -> SIMULATE THORChain delivering the native ->
                           USDT leg by minting USDT to the IndexToken
                           (MockERC20.mint is permissionless), then collect a
                           3-of-5 REDEMPTION-DELIVERY attestation (via
                           `attest_redeem`) and post `oracle.attestRedemption`
                           for each leg.

finalizeMint / finalizeBurn are NOT done here — the dApp calls them (it holds
the basket config, so it builds the finalizeBurn hints trivially). This keeper
only does the work the off-chain network does.

Stdlib only (urllib + subprocess + json). Signatures are collected by POSTing
each daemon's typed sign endpoint directly — the daemon recomputes the EIP-712
digest on its OWN pinned domain (oracle address + chain id from ITS config) and
signs, so a plain POST is equivalent to the production `RemoteHsmBackend` client.
DEV/ANVIL ONLY.

Config via env (written by up.sh):
  WEBTEST_RPC, WEBTEST_KEEPER_KEY,
  WEBTEST_ORACLE, WEBTEST_QUEUE, WEBTEST_USDT,
  WEBTEST_D0_URL/ADDR, WEBTEST_D1_URL/ADDR, WEBTEST_D2_URL/ADDR,
  WEBTEST_START_BLOCK (default 0), WEBTEST_POLL_SECS (default 2).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request

RPC = os.environ["WEBTEST_RPC"]
KEY = os.environ["WEBTEST_KEEPER_KEY"]
ORACLE = os.environ["WEBTEST_ORACLE"]
QUEUE = os.environ["WEBTEST_QUEUE"]
USDT = os.environ["WEBTEST_USDT"]
REGISTRY = os.environ.get("WEBTEST_REGISTRY", "")  # ThorchainVaultRegistry (keeper owns it)
# Fork mode: USDT is REAL Tether (no permissionless mint), so the simulated
# native->USDT delivery transfers from an impersonated whale instead. Unset on
# Sepolia (mock USDT) -> falls back to MockERC20.mint.
WHALE = os.environ.get("WEBTEST_USDT_WHALE", "")
POLL_SECS = float(os.environ.get("WEBTEST_POLL_SECS", "2"))
# publicnode's free tier rejects eth_getLogs older than ~128 blocks ("archive
# requests require a personal token"). Cap how far back we ever query so a keeper
# that fell behind (e.g. the host slept) skips forward instead of wedging on a
# permanent 403 against an ever-widening archive range.
LOG_WINDOW = int(os.environ.get("WEBTEST_LOG_WINDOW", "90"))

DAEMONS = [
    (os.environ["WEBTEST_D0_URL"], os.environ["WEBTEST_D0_ADDR"]),
    (os.environ["WEBTEST_D1_URL"], os.environ["WEBTEST_D1_ADDR"]),
    (os.environ["WEBTEST_D2_URL"], os.environ["WEBTEST_D2_ADDR"]),
]

# Event topic0 hashes (full signature incl. indexed params, array types
# spelled bytes32[] / uint256[]).
MINT_SIG = "MintIntentCreated(bytes32,address,address,address,uint256,uint64,bytes32[],uint256[])"
REDEEM_SIG = "RedemptionIntentCreated(bytes32,address,address,uint256,uint64,bytes32[],uint256[])"


def log(msg: str) -> None:
    print(f"[keeper] {msg}", flush=True)


def run(cmd: list[str]) -> str:
    """Run a command, return stdout; raise with captured output on failure."""
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"cmd failed ({res.returncode}): {' '.join(cmd)}\n{res.stderr}{res.stdout}")
    return res.stdout.strip()


def cast(*args: str) -> str:
    return run(["cast", *args, "--rpc-url", RPC])


def cast_send(to: str, sig: str, *params: str) -> None:
    run(["cast", "send", to, sig, *params, "--rpc-url", RPC, "--private-key", KEY])


def deliver_usdt(to: str, amount: str) -> None:
    """SIMULATE THORChain delivering the native->USDT leg. On a mainnet fork
    USDT is real Tether (no mint), so transfer from an impersonated whale
    (anvil --auto-impersonate); on Sepolia (WHALE unset) mint mock USDT."""
    if WHALE:
        run(["cast", "send", USDT, "transfer(address,uint256)", to, amount, "--rpc-url", RPC, "--from", WHALE, "--unlocked"])
    else:
        cast_send(USDT, "mint(address,uint256)", to, amount)


def keccak(text: str) -> str:
    return run(["cast", "keccak", text])


def to_hex_block(n: int) -> str:
    return hex(n)


def get_logs(topic0: str, from_block: int, to_block: int) -> list[dict]:
    flt = json.dumps(
        {
            "fromBlock": to_hex_block(from_block),
            "toBlock": to_hex_block(to_block),
            "address": QUEUE,
            "topics": [topic0],
        }
    )
    out = run(["cast", "rpc", "eth_getLogs", flt, "--rpc-url", RPC])
    return json.loads(out)


def abi_decode(types: str, data: str) -> list[str]:
    """Decode ABI-encoded `data` as a tuple of `types`. Returns one string
    per top-level field; array fields come back as a single bracketed string."""
    out = run(["cast", "abi-decode", f"x()({types})", data])
    return [line.strip() for line in out.splitlines() if line.strip()]


def parse_array(field: str) -> list[str]:
    """Parse cast's `[a, b, c]` array rendering into a list of trimmed items."""
    field = field.strip()
    if field.startswith("[") and field.endswith("]"):
        field = field[1:-1]
    if not field.strip():
        return []
    return [x.strip() for x in field.split(",") if x.strip()]


def strip_annot(v: str) -> str:
    """cast sometimes annotates numbers like `1000000 [1e6]` — keep the head."""
    return v.split()[0] if v else v


def attest_amount(expected: str, fallback: int) -> str:
    """Native amount the keeper attests for a mint slot. Async legs report a
    zero pre-trade estimate BY DESIGN (the delivered amount is only known
    off-chain), so fall back to an equal split of the funding — large enough
    that a later burn's per-leg pro-rata dispatch never rounds to zero."""
    n = int(strip_annot(expected))
    return str(n if n > 0 else max(fallback, 1))


def daemon_sign(path: str, body: dict) -> list[str]:
    """POST a typed sign request to the first 3 daemons; return their 3 sigs.
    The daemon recomputes the digest on its own pinned domain and signs."""
    sigs: list[str] = []
    payload = json.dumps(body).encode()
    for url, _addr in DAEMONS:
        req = urllib.request.Request(
            url + path, data=payload, headers={"content-type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            sigs.append(json.loads(resp.read())["signature"])
    if len(sigs) < 3:
        raise RuntimeError(f"got {len(sigs)} sigs, need 3")
    return sigs[:3]


def settlement_context(lg: dict) -> tuple[dict, str]:
    """Build one deterministic, signed source context for an observed log."""
    source_chain_id = int(strip_annot(cast("chain-id")))
    source_block_number = int(lg["blockNumber"], 16)
    source_block_hash = lg["blockHash"]
    observed_at = int(
        strip_annot(cast("block", str(source_block_number), "--field", "timestamp"))
    )
    valid_until = observed_at + 300
    observation_epoch = int(
        strip_annot(
            cast(
                "call",
                ORACLE,
                "observationEpoch(uint256)(uint64)",
                str(source_chain_id),
            )
        )
    )
    evidence_hash = keccak(
        f'{source_block_hash}:{lg["transactionHash"]}:{lg["logIndex"]}'
    )
    body = {
        "evidence_hash": evidence_hash,
        "observed_at": observed_at,
        "valid_until": valid_until,
        "source_chain_id": source_chain_id,
        "source_block_number": source_block_number,
        "source_block_hash": source_block_hash,
        "observation_epoch": observation_epoch,
    }
    encoded = (
        f"({evidence_hash},{observed_at},{valid_until},{source_chain_id},"
        f"{source_block_number},{source_block_hash},{observation_epoch})"
    )
    return body, encoded


def handle_mint(lg: dict) -> None:
    intent_id = lg["topics"][1]
    fields = abi_decode("address,uint256,uint64,bytes32[],uint256[]", lg["data"])
    # fields: [fundingToken, amountIn, deadline, slotAssetIds[], slotExpectedAmounts[]]
    amount_in = int(strip_annot(fields[1]))
    expected = parse_array(fields[4])
    n = len(expected)
    per_slot = amount_in // n if n else 0
    context_body, context_tuple = settlement_context(lg)
    log(f"MintIntentCreated {intent_id} — {n} async slot(s), amountIn={amount_in}")
    for slot in range(n):
        amount = attest_amount(expected[slot], per_slot)
        try:
            sigs = daemon_sign(
                "/api/v1/sign/eip712-attestation",
                {
                    "intent_id": intent_id,
                    "slot_index": str(slot),
                    "attested_amount": amount,
                    **context_body,
                },
            )
            cast_send(
                ORACLE,
                "attest(bytes32,uint256,uint256,(bytes32,uint64,uint64,uint256,uint64,bytes32,uint64),bytes[])",
                intent_id,
                str(slot),
                amount,
                context_tuple,
                "[" + ",".join(sigs) + "]",
            )
            log(f"  attested slot {slot} amount={amount}")
        except RuntimeError as exc:
            # Already-attested (restart re-scan) or transient — skip this slot.
            log(f"  slot {slot} skipped: {str(exc).splitlines()[-1][:120]}")


def handle_redeem(lg: dict) -> None:
    redemption_id = lg["topics"][1]
    index_token = "0x" + lg["topics"][2][-40:]
    fields = abi_decode("uint256,uint64,bytes32[],uint256[]", lg["data"])
    # fields: [shares, deadline, legAssetIds[], legExpectedExits[]]
    shares = int(strip_annot(fields[0]))
    asset_ids = parse_array(fields[2])
    n = len(asset_ids)
    # Leg i's dispatched native == slotBalance * shares / supply, evaluated at
    # the PRE-burn state. burn() shrinks both the slot balances and the supply
    # pro-rata in the same tx, so reading them AFTER the burn is numerically
    # unstable for a near-full cash-out: post-burn supply collapses to the
    # locked MIN_LIQUIDITY floor and the truncated post-burn slot balance is
    # then amplified by shares/MIN_LIQUIDITY (a full burn delivers sqrt-scaled
    # nonsense). Read at burn_block-1 — the exact pre-burn values the protocol
    # itself used to size the dispatch — and deliver the native 1:1 as USDT so
    # burning fraction f returns ~f * the original deposit.
    at = ("--block", str(int(lg["blockNumber"], 16) - 1))
    supply = int(strip_annot(cast("call", index_token, "totalSupply()(uint256)", *at)))
    context_body, context_tuple = settlement_context(lg)
    log(f"RedemptionIntentCreated {redemption_id} — {n} leg(s) for {index_token}")
    for leg in range(n):
        bal = int(strip_annot(cast("call", index_token, "asyncSlotBalance(uint256)(uint256)", str(leg), *at)))
        amount = str(max(bal * shares // supply, 1)) if supply else "1"
        asset_id = asset_ids[leg]
        try:
            # 1. SIMULATE THORChain delivering native -> USDT to the IndexToken.
            deliver_usdt(index_token, amount)
            # 2. collect + post the per-leg delivery attestation.
            sigs = daemon_sign(
                "/api/v1/sign/eip712-redemption-delivery",
                {
                    "redemption_id": redemption_id,
                    "leg_index": str(leg),
                    "asset_id": asset_id,
                    "delivered_amount": amount,
                    **context_body,
                },
            )
            cast_send(
                ORACLE,
                "attestRedemption(bytes32,uint256,bytes32,uint256,(bytes32,uint64,uint64,uint256,uint64,bytes32,uint64),bytes[])",
                redemption_id,
                str(leg),
                asset_id,
                amount,
                context_tuple,
                "[" + ",".join(sigs) + "]",
            )
            log(f"  delivered+attested leg {leg} asset={asset_id} usdt={amount}")
        except RuntimeError as exc:
            log(f"  leg {leg} skipped: {str(exc).splitlines()[-1][:120]}")


def refresh_vault() -> None:
    """Keep the THORChain vault registry fresh — the off-chain bot's documented
    job. The adapter rejects a vault older than MAX_VAULT_AGE (4h), which would
    otherwise block mintAsync; the keeper owns the registry and re-writes it."""
    if not REGISTRY:
        return
    try:
        last = int(strip_annot(cast("call", REGISTRY, "lastUpdated()(uint64)")))
        if int(time.time()) - last > 3000:  # well under the 4h window
            vault = cast("call", REGISTRY, "currentVault()(address)").split()[0]
            cast_send(REGISTRY, "setVault(address)", vault)
            log("refreshed THORChain vault")
    except Exception as exc:  # noqa: BLE001 — never let a refresh hiccup kill the keeper
        log(f"vault refresh skipped: {exc}")


def main() -> None:
    mint_topic = keccak(MINT_SIG)
    redeem_topic = keccak(REDEEM_SIG)
    last_block = int(os.environ.get("WEBTEST_START_BLOCK", "0"))
    seen_mint: set[str] = set()
    seen_redeem: set[str] = set()
    log(f"watching queue={QUEUE} oracle={ORACLE} from block {last_block}; poll {POLL_SECS}s")
    refresh_vault()

    while True:
        try:
            refresh_vault()
            latest = int(strip_annot(cast("block-number")))
            if latest >= last_block:
                from_block = max(last_block, latest - LOG_WINDOW)
                if from_block > last_block:
                    log(f"skipped {from_block - last_block} stale block(s) to stay within the RPC log window")
                for lg in get_logs(mint_topic, from_block, latest):
                    iid = lg["topics"][1]
                    if iid not in seen_mint:
                        seen_mint.add(iid)
                        handle_mint(lg)
                for lg in get_logs(redeem_topic, from_block, latest):
                    rid = lg["topics"][1]
                    if rid not in seen_redeem:
                        seen_redeem.add(rid)
                        handle_redeem(lg)
                last_block = latest + 1
        except Exception as exc:  # noqa: BLE001 — keeper must survive transient RPC/daemon errors
            log(f"error (continuing): {exc}")
        time.sleep(POLL_SECS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
