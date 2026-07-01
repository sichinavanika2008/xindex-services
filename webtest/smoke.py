#!/usr/bin/env python3
"""Headless end-to-end smoke test for the web testbed — drives the SAME
contract-call sequence the dApp does (create multi-chain basket → mint →
finalize → burn → finalize) via cast, as the account-0 user, and asserts
shares were minted and USDT came back. Proves the keeper + on-chain stack
work without needing a browser.

Run after webtest/up.sh:  python3 webtest/smoke.py
Reads webtest/addresses.js for the deployed addresses. DEV/ANVIL ONLY.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
# Anvil defaults; override via env for the live Sepolia testbed (WEBTEST_RPC +
# WEBTEST_ME + WEBTEST_ME_KEY = the funded dApp wallet from addresses.js).
RPC = os.environ.get("WEBTEST_RPC", "http://127.0.0.1:8545")
# anvil account 0 = the dApp's default test wallet (distinct from the
# keeper's account 9, so no nonce races).
ME = os.environ.get("WEBTEST_ME", "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
KEY = os.environ.get("WEBTEST_ME_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
PICK = ["BTC.BTC", "ETH.ETH", "GAIA.ATOM"]  # the multi-chain basket to test


def run(cmd: list[str]) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"cmd failed: {' '.join(cmd)}\n{r.stderr}{r.stdout}")
    return r.stdout.strip()


def call(to: str, sig: str, *args: str) -> str:
    return run(["cast", "call", to, sig, *args, "--rpc-url", RPC]).split()[0]


def send(to: str, sig: str, *args: str) -> dict:
    out = run(["cast", "send", to, sig, *args, "--rpc-url", RPC, "--private-key", KEY, "--json"])
    return json.loads(out)


def keccak(s: str) -> str:
    return run(["cast", "keccak", s])


def id_from(receipt: dict, topic0: str) -> str:
    for lg in receipt.get("logs", []):
        if lg["topics"] and lg["topics"][0].lower() == topic0.lower():
            return lg["topics"][1]
    raise RuntimeError(f"event {topic0} not in receipt")


def load_addresses() -> dict:
    js = open(os.path.join(HERE, "addresses.js")).read()
    g = lambda k: re.search(rf'{k}:\s*"(0x[0-9a-fA-F]{{40}})"', js).group(1)
    chains = {
        a: {"adapter": ad, "sentinel": se}
        for a, ad, se in re.findall(r'asset:\s*"([^"]+)",\s*adapter:\s*"(0x[0-9a-fA-F]{40})",\s*sentinel:\s*"(0x[0-9a-fA-F]{40})"', js)
    }
    return {"factory": g("factory"), "usdt": g("usdt"), "oracle": g("oracle"), "queue": g("queue"), "chains": chains}


def main() -> int:
    A = load_addresses()
    factory, usdt, queue = A["factory"], A["usdt"], A["queue"]
    sel = [A["chains"][a] for a in PICK]
    tokens = [c["sentinel"] for c in sel]
    adapters = [c["adapter"] for c in sel]
    weights = [3334, 3333, 3333]
    print(f"basket: {', '.join(PICK)}  weights {weights}")

    mint_topic = keccak("MintIntentCreated(bytes32,address,address,address,uint256,uint64,bytes32[],uint256[])")
    redeem_topic = keccak("RedemptionIntentCreated(bytes32,address,address,uint256,uint64,bytes32[],uint256[])")
    created_topic = keccak("IndexCreated(address,address,address[],uint16[],address[],string,string,address)")

    # 1. fund: mint 10,000 test USDT to the user.
    send(usdt, "mint(address,uint256)", ME, "10000000000")
    print(f"funded: USDT balance {int(call(usdt, 'balanceOf(address)(uint256)', ME).split()[0])}")

    # 2. create the multi-chain basket (oracle=0 min-ratio, empty assetIds/decimals).
    cfg = (
        f"([{','.join(tokens)}],[{','.join(map(str, weights))}],[{','.join(adapters)}],"
        f'"Smoke Tri","STRI",0x0000000000000000000000000000000000000000,[],[])'
    )
    rc = send(factory, "createIndex((address[],uint16[],address[],string,string,address,bytes32[],uint8[]))", cfg)
    clone = "0x" + id_from(rc, created_topic)[-40:]
    print(f"basket created: {clone}")

    # 3. per-slot hints = abi.encode(minOutNative=1, custodyHash, interval=0, quantity=0).
    hints = []
    for ad in adapters:
        h = call(ad, "nativeCustodyHash()(bytes32)")
        hints.append(run(["cast", "abi-encode", "f(uint256,bytes32,uint256,uint256)", "1", h, "0", "0"]))
    hints_arg = "[" + ",".join(hints) + "]"
    deadline = str(int(time.time()) + 7200)

    # 4. mint: approve + mintAsync.
    send(usdt, "approve(address,uint256)", clone, "1000000000")  # 1000 USDT
    rc = send(clone, "mintAsync(address,uint256,uint64,bytes[])", usdt, "1000000000", deadline, hints_arg)
    intent = id_from(rc, mint_topic)
    print(f"mintAsync intent {intent[:14]}… — waiting for keeper attestation")

    # 5. wait for keeper to attest all slots, then finalizeMint.
    for _ in range(int(os.environ.get("WEBTEST_POLL_TRIES", "40"))):
        if call(queue, "isFullyAttested(bytes32)(bool)", intent) == "true":
            break
        time.sleep(2)
    else:
        print("FAIL: mint attestation timed out", file=sys.stderr); return 1
    send(clone, "finalizeMint(bytes32,uint256)", intent, "1")
    shares = int(call(clone, "balanceOf(address)(uint256)", ME).split()[0])
    print(f"finalizeMint done — user holds {shares} shares")
    if shares == 0:
        print("FAIL: zero shares minted", file=sys.stderr); return 1

    # 6. burn half → redemption.
    usdt_before = int(call(usdt, "balanceOf(address)(uint256)", ME).split()[0])
    # minUsdtOut = 10000 wei (0.01 USDT): a negligible floor that still keeps
    # each leg's per-weight LIM (minUsdtOut * weight / 10000) above zero.
    rc = send(clone, "burn(uint256,uint256,uint64)", str(shares // 2), "10000", deadline)
    rid = id_from(rc, redeem_topic)
    print(f"burn {shares // 2} shares — redemption {rid[:14]}… — waiting for keeper delivery+attest")

    # 7. wait until finalizeBurn no longer reverts (keeper delivered+attested all legs).
    for _ in range(int(os.environ.get("WEBTEST_POLL_TRIES", "40"))):
        try:
            run(["cast", "call", clone, "finalizeBurn(bytes32,bytes[])(uint256)", rid, hints_arg, "--from", ME, "--rpc-url", RPC])
            break
        except RuntimeError:
            time.sleep(2)
    else:
        print("FAIL: burn delivery timed out", file=sys.stderr); return 1
    send(clone, "finalizeBurn(bytes32,bytes[])", rid, hints_arg)
    got = int(call(usdt, "balanceOf(address)(uint256)", ME).split()[0]) - usdt_before
    print(f"finalizeBurn done — received {got} USDT ({got / 1e6:.6f})")
    if got == 0:
        print("FAIL: zero USDT returned on burn", file=sys.stderr); return 1

    print("\nPASS: multi-chain mint→shares→burn→USDT round trip works.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
