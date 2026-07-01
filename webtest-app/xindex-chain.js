// ── Xindex real-web3 bridge ─────────────────────────────────────────
// Swaps the app's simulated mint/burn for REAL Sepolia transactions against
// the verified contracts + the live 3-of-5 keeper. The app's portfolio numbers
// stay its own illustration; every ACTION here is a real on-chain tx (the
// activity log surfaces the tx hashes + clone address + Etherscan links).
// Reads window.XINDEX (addresses.js). Needs ethers v6 loaded first.
(function () {
  const X = window.XINDEX;
  const EXPLORER = "https://sepolia.etherscan.io";
  // app token id -> our THORChain asset string (addresses.js chains key)
  const ID2ASSET = {
    btc: "BTC.BTC", ltc: "LTC.LTC", bch: "BCH.BCH", doge: "DOGE.DOGE", zec: "ZEC.ZEC",
    eth: "ETH.ETH", bnb: "BSC.BNB", avax: "AVAX.AVAX", ethb: "BASE.ETH", pol: "POL.MATIC",
    atom: "GAIA.ATOM", usdc: "NOBLE.USDC", xrp: "XRP.XRP", sol: "SOL.SOL", trx: "TRON.TRX",
  };
  const chainFor = (id) => X.chains.find((c) => c.asset === ID2ASSET[id]);

  const FACTORY_ABI = [
    "function createIndex((address[],uint16[],address[],string,string,address,bytes32[],uint8[])) returns (address)",
    "event IndexCreated(address indexed index, address indexed creator, address[] tokens, uint16[] weightsBps, address[] adapters, string name, string symbol, address oracle)",
  ];
  const USDT_ABI = [
    "function balanceOf(address) view returns (uint256)",
    "function approve(address,uint256) returns (bool)",
    "function mint(address,uint256)",
  ];
  const CLONE_ABI = [
    "function mintAsync(address,uint256,uint64,bytes[]) returns (bytes32)",
    "function finalizeMint(bytes32,uint256)",
    "function burn(uint256,uint256,uint64)",
    "function finalizeBurn(bytes32,bytes[]) returns (uint256)",
    "function balanceOf(address) view returns (uint256)",
    "function totalSupply() view returns (uint256)",
    "function decimals() view returns (uint8)",
    "event MintIntentCreated(bytes32 indexed intentId, address indexed creator, address indexed token, address funding, uint256 amountIn, uint64 deadline, bytes32[] slotAssetIds, uint256[] slotExpectedAmounts)",
    "event RedemptionIntentCreated(bytes32 indexed redemptionId, address indexed token, address indexed burner, uint256 shares, uint64 deadline, bytes32[] legAssetIds, uint256[] legExpectedExits)",
  ];
  const QUEUE_ABI = ["function isFullyAttested(bytes32) view returns (bool)"];
  const ADAPTER_ABI = ["function nativeCustodyHash() view returns (bytes32)"];

  const provider = new ethers.JsonRpcProvider(X.rpc, X.chainId);
  const wallet = new ethers.Wallet(X.deployerKey, provider);
  const factory = new ethers.Contract(X.factory, FACTORY_ABI, wallet);
  const usdt = new ethers.Contract(X.usdt, USDT_ABI, wallet);
  const queue = new ethers.Contract(X.queue, QUEUE_ABI, provider);
  const coder = ethers.AbiCoder.defaultAbiCoder();
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const deadline = () => Math.floor(Date.now() / 1000) + 7200;
  const txLink = (h) => `${EXPLORER}/tx/${h}`;

  async function usdtBalance() {
    return Number(await usdt.balanceOf(wallet.address)) / 1e6;
  }
  async function ethBalance() {
    return Number(ethers.formatEther(await provider.getBalance(wallet.address)));
  }

  // Faucet: mint 10,000 mock USDT (permissionless MockERC20).
  async function faucet(log) {
    const tx = await usdt.mint(wallet.address, 10000n * 10n ** 6n);
    log(`Faucet tx ${tx.hash.slice(0, 10)}… — minting 10,000 USDT`, "faucet", txLink(tx.hash));
    await tx.wait();
    return { usdt: await usdtBalance(), eth: await ethBalance() };
  }

  // Create the on-chain basket clone. basket=[{id,weight(0-100)}].
  async function createIndex(basket, name, symbol, log) {
    basket = basket.filter((b) => b.weight > 0); // drop 0% legs — the factory rejects zero-weight constituents
    const tokens = [], weights = [], adapters = [];
    for (const b of basket) {
      const c = chainFor(b.id);
      if (!c) throw new Error(`no live adapter for ${b.id}`);
      tokens.push(c.sentinel); adapters.push(c.adapter); weights.push(b.weight * 100); // 0-100 -> bps
    }
    const cfg = [tokens, weights, adapters, name || "Xindex", symbol || "XIDX", ethers.ZeroAddress, [], []];
    const tx = await factory.createIndex(cfg);
    log(`Creating index on-chain — tx ${tx.hash.slice(0, 10)}…`, "mint", txLink(tx.hash));
    const rc = await tx.wait();
    for (const lg of rc.logs) {
      try {
        const p = factory.interface.parseLog(lg);
        if (p && p.name === "IndexCreated") return p.args.index;
      } catch (_) {}
    }
    throw new Error("IndexCreated not found");
  }

  // Real mint: approve + mintAsync + wait keeper attestation + finalizeMint.
  // onPhase(0..4) drives the app's deposit animation from real progress.
  async function mint(cloneAddr, basket, amountUSDT, onPhase, log) {
    basket = basket.filter((b) => b.weight > 0); // keep legs consistent with the clone (0% legs were dropped at create)
    const clone = new ethers.Contract(cloneAddr, CLONE_ABI, wallet);
    const amount = BigInt(Math.round(amountUSDT * 1e6));
    onPhase(0);
    const ap = await usdt.approve(cloneAddr, amount);
    await ap.wait();
    // per-leg hints: abi.encode(minOutNative=1, custodyHash, 0, 0)
    const hints = [];
    for (const b of basket) {
      const c = chainFor(b.id);
      const ad = new ethers.Contract(c.adapter, ADAPTER_ABI, provider);
      const h = await ad.nativeCustodyHash();
      hints.push(coder.encode(["uint256", "bytes32", "uint256", "uint256"], [1, h, 0, 0]));
    }
    onPhase(1);
    const mtx = await clone.mintAsync(X.usdt, amount, deadline(), hints);
    log(`Deposit ${amountUSDT} USDT — mintAsync ${mtx.hash.slice(0, 10)}…`, "mint", txLink(mtx.hash));
    const mrc = await mtx.wait();
    let intentId;
    for (const lg of mrc.logs) {
      try { const p = clone.interface.parseLog(lg); if (p && p.name === "MintIntentCreated") intentId = p.args.intentId; } catch (_) {}
    }
    if (!intentId) throw new Error("MintIntentCreated not found");
    onPhase(2);
    log(`Awaiting 3-of-5 signer attestation…`, "mint");
    for (let i = 0; i < 90; i++) {
      if (await queue.isFullyAttested(intentId)) break;
      await sleep(2500);
    }
    if (!(await queue.isFullyAttested(intentId))) throw new Error("attestation timed out");
    onPhase(3);
    const ftx = await clone.finalizeMint(intentId, 1);
    await ftx.wait();
    onPhase(4);
    const shares = await clone.balanceOf(wallet.address);
    const dec = Number(await clone.decimals());
    log(`Minted — finalize ${ftx.hash.slice(0, 10)}…; ${shares} raw shares`, "ok", txLink(ftx.hash));
    return { shares: Number(shares) / 10 ** dec, sharesRaw: shares, decimals: dec, intentId };
  }

  // Real cash-out: burn + wait keeper delivery + finalizeBurn -> USDT back.
  async function burn(cloneAddr, basket, fraction, onPhase, log) {
    basket = basket.filter((b) => b.weight > 0); // same non-zero legs as the clone
    const clone = new ethers.Contract(cloneAddr, CLONE_ABI, wallet);
    const total = await clone.balanceOf(wallet.address);
    const burnRaw = (total * BigInt(Math.round(fraction * 1e6))) / 1000000n;
    if (burnRaw <= 0n) throw new Error("nothing to burn");
    onPhase(0);
    const before = await usdt.balanceOf(wallet.address);
    const btx = await clone.burn(burnRaw, 10000, deadline());
    log(`Burn ${burnRaw} raw shares — tx ${btx.hash.slice(0, 10)}…`, "burn", txLink(btx.hash));
    const brc = await btx.wait();
    let rid;
    for (const lg of brc.logs) {
      try { const p = clone.interface.parseLog(lg); if (p && p.name === "RedemptionIntentCreated") rid = p.args.redemptionId; } catch (_) {}
    }
    if (!rid) throw new Error("RedemptionIntentCreated not found");
    onPhase(1);
    // per-leg hints (finalizeBurn) = same minOut/custody encoding
    const hints = [];
    for (const b of basket) {
      const c = chainFor(b.id);
      const ad = new ethers.Contract(c.adapter, ADAPTER_ABI, provider);
      const h = await ad.nativeCustodyHash();
      hints.push(coder.encode(["uint256", "bytes32", "uint256", "uint256"], [1, h, 0, 0]));
    }
    onPhase(2);
    log(`Awaiting keeper delivery + attestation across ${basket.length} legs…`, "burn");
    let ok = false;
    for (let i = 0; i < 120; i++) {
      try { await clone.finalizeBurn.staticCall(rid, hints); ok = true; break; } catch (_) { await sleep(2500); }
    }
    if (!ok) throw new Error("burn delivery timed out");
    onPhase(3);
    const ftx = await clone.finalizeBurn(rid, hints);
    await ftx.wait();
    onPhase(4);
    const after = await usdt.balanceOf(wallet.address);
    const usdtBack = Number(after - before) / 1e6;
    log(`Settled — finalize ${ftx.hash.slice(0, 10)}…; ${usdtBack.toFixed(6)} USDT returned`, "ok", txLink(ftx.hash));
    return { usdtBack, usdt: Number(after) / 1e6 };
  }

  // Read the wallet's live share balance in a clone (for refresh-safe restore).
  async function sharesOf(cloneAddr) {
    const clone = new ethers.Contract(cloneAddr, CLONE_ABI, provider);
    const bal = await clone.balanceOf(wallet.address);
    const dec = Number(await clone.decimals());
    return { shares: Number(bal) / 10 ** dec, raw: bal };
  }

  window.XindexChain = {
    address: wallet.address, explorer: EXPLORER,
    usdtBalance, ethBalance, faucet, createIndex, mint, burn, sharesOf, chainFor,
  };
  console.log("[xindex-chain] ready as", wallet.address, "on chain", X.chainId);
})();
