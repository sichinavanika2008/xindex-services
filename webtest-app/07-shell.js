// ── Xindex app shell: state, lifecycles, top bar, activity log ──────
const { Catalog, Basket, IndexPanel, Monogram, RedeemModal } = window;

// ── Account chip ────────────────────────────────────────────────────
function Bal({ label, value, color, flash }) {
  return (
    <div className="flex flex-col items-end leading-tight">
      <span className="text-[10px] text-faint uppercase tracking-[0.08em]">{label}</span>
      <span className="font-mono text-[13px] tabular-nums transition-transform" style={{ color: color || "var(--ink)", transform: flash ? "scale(1.12)" : "scale(1)" }}>{value}</span>
    </div>
  );
}

function TopBar({ address, eth, usdt, onFaucet, flash, busy }) {
  return (
    <header className="sticky top-0 z-30" style={{ background: "color-mix(in srgb, var(--base) 86%, transparent)", backdropFilter: "blur(14px)", borderBottom: "1px solid var(--line)" }}>
      <div className="max-w-[1320px] mx-auto px-4 sm:px-6 h-16 flex items-center justify-between gap-4">
        <div className="flex items-center gap-3 min-w-0">
          <div className="relative w-9 h-9 shrink-0 grid place-items-center">
            <div className="absolute inset-0 rounded-[10px]" style={{ background: "rgba(182,80,158,0.06)", border: "1px solid rgba(182,80,158,0.22)", boxShadow: "inset 0 0 14px rgba(182,80,158,0.10)" }} />
            <svg viewBox="0 0 32 32" className="relative w-6 h-6">
              <defs>
                <linearGradient id="xiNavGrad" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0" stopColor="#2EBAC6" />
                  <stop offset="0.5" stopColor="#B6509E" />
                  <stop offset="1" stopColor="#7C5CFF" />
                </linearGradient>
              </defs>
              <g stroke="url(#xiNavGrad)" strokeWidth="1.3" opacity="0.7">
                <line x1="16" y1="16" x2="16" y2="4.8" /><line x1="16" y1="16" x2="25.7" y2="10.4" /><line x1="16" y1="16" x2="25.7" y2="21.6" /><line x1="16" y1="16" x2="16" y2="27.2" /><line x1="16" y1="16" x2="6.3" y2="21.6" /><line x1="16" y1="16" x2="6.3" y2="10.4" />
              </g>
              <g fill="#B6509E">
                <circle cx="16" cy="4.8" r="2.1" /><circle cx="25.7" cy="10.4" r="2.1" /><circle cx="25.7" cy="21.6" r="2.1" /><circle cx="16" cy="27.2" r="2.1" /><circle cx="6.3" cy="21.6" r="2.1" /><circle cx="6.3" cy="10.4" r="2.1" />
              </g>
              <circle cx="16" cy="16" r="4.4" fill="url(#xiNavGrad)" />
            </svg>
          </div>
          <div className="min-w-0">
            <div className="text-[16px] font-semibold text-ink tracking-tight leading-none">Xindex</div>
            <div className="text-[11px] text-faint tracking-wide mt-0.5">omnichain index</div>
          </div>
        </div>

        <div className="flex items-center gap-2 sm:gap-3">
          <div className="hidden sm:flex items-center gap-4 px-3.5 py-2 rounded-xl" style={{ background: "rgba(255,255,255,0.025)", border: "1px solid var(--line)" }}>
            <div className="flex items-center gap-2">
              <span className="w-6 h-6 rounded-full grid place-items-center text-[10px]" style={{ background: "linear-gradient(135deg,var(--brand),var(--green))", color: "#0A0C11", fontWeight: 700 }}>◇</span>
              <span className="font-mono text-[12.5px] text-mute">{address}</span>
            </div>
            <span className="w-px h-6" style={{ background: "var(--line)" }} />
            <Bal label="ETH" value={window.fmtNum(eth, 2)} flash={flash} />
            <Bal label="USDT" value={window.fmtNum(usdt, 0)} flash={flash} />
          </div>
          <button onClick={onFaucet} disabled={busy} className="ghost-btn !px-3.5 flex items-center gap-1.5 disabled:opacity-50" title="+100 ETH, +10,000 USDT">
            <svg viewBox="0 0 16 16" className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M4 2 h8 l-1 4 a3 3 0 0 1 -6 0 z" /><path d="M8 9 v3 M6 14 h4" strokeLinecap="round"/></svg>
            <span className="hidden sm:inline">Faucet</span>
          </button>
        </div>
      </div>
    </header>
  );
}

// ── Activity log ────────────────────────────────────────────────────
const LOG_COLOR = { mint: "var(--brand)", burn: "var(--green)", ok: "var(--green)", faucet: "var(--amber)", info: "var(--faint)" };
function ActivityLog({ entries }) {
  const ref = useRef(null);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [entries]);
  return (
    <section className="panel">
      <div className="px-5 py-3 border-b flex items-center justify-between" style={{ borderColor: "var(--line)" }}>
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full" style={{ background: "var(--green)", boxShadow: "0 0 6px var(--green)" }} />
          <h3 className="text-[13px] font-semibold text-ink tracking-tight">Activity log</h3>
        </div>
        <span className="font-mono text-[11px] text-faint">{entries.length} events</span>
      </div>
      <div ref={ref} className="h-[180px] overflow-y-auto xi-scroll px-5 py-3 font-mono text-[12px] leading-relaxed">
        {entries.length === 0 ? (
          <div className="text-faint">Waiting for activity…</div>
        ) : (
          entries.map((e, i) => (
            <div key={i} className="flex items-start gap-2.5 py-0.5">
              <span className="text-faint shrink-0 tabular-nums">{e.t}</span>
              <span className="shrink-0 mt-1.5 w-1.5 h-1.5 rounded-full" style={{ background: LOG_COLOR[e.kind] || "var(--faint)" }} />
              <span style={{ color: e.kind === "info" ? "var(--mute)" : "var(--ink)" }}>{e.msg}</span>
            </div>
          ))
        )}
      </div>
    </section>
  );
}

// ── Main App ────────────────────────────────────────────────────────
function App() {
  const [eth, setEth] = useState(4.0);
  const [usdt, setUsdt] = useState(5000);
  const [flash, setFlash] = useState(false);

  const [basket, setBasket] = useState([]); // [{id, weight}]
  const [created, setCreated] = useState(null); // {name, symbol, familyCount}
  const [nameDraft, setNameDraft] = useState("");
  const [symbolDraft, setSymbolDraft] = useState("");

  const [holdings, setHoldings] = useState({}); // id -> native amount
  const [totalShares, setTotalShares] = useState(0);
  const [userShares, setUserShares] = useState(0);

  const [flow, setFlow] = useState({ kind: null, phase: -1 });
  const [rd, setRd] = useState({ open: false, step: "form", pct: 0, burnShares: 0, fraction: 0, legs: [], addresses: {}, progress: {} });
  const [log, setLog] = useState([]);

  const busyRef = useRef(false);
  const cloneRef = useRef(null);
  const holdingsRef = useRef(holdings);
  const totalSharesRef = useRef(totalShares);
  useEffect(() => { holdingsRef.current = holdings; }, [holdings]);
  useEffect(() => { totalSharesRef.current = totalShares; }, [totalShares]);
  // sync real wallet balances from Sepolia on mount
  useEffect(() => {
    let on = true;
    (async () => {
      try {
        if (!window.XindexChain) return;
        const u = await window.XindexChain.usdtBalance();
        const e = await window.XindexChain.ethBalance();
        if (on) { setUsdt(window.round2(u)); setEth(window.round2(e)); }
        pushLog(`Connected to Sepolia as ${window.XindexChain.address.slice(0, 8)}… — balances synced from chain.`, "ok");
        // refresh-safe: restore a live index from a prior session (reads real shares)
        const saved = JSON.parse(localStorage.getItem("xindex_session") || "null");
        if (saved && saved.clone) {
          const sh = await window.XindexChain.sharesOf(saved.clone);
          if (sh.shares > 0 && on) {
            cloneRef.current = saved.clone;
            setBasket(saved.basket || []);
            setCreated({
              name: saved.name || "Xindex", symbol: saved.symbol || "XIDX",
              familyCount: new Set((saved.basket || []).map((b) => window.TOKEN_BY_ID[b.id].family)).size,
            });
            setTotalShares(window.round2(sh.shares));
            setUserShares(window.round2(sh.shares));
            const legs = window.legsFor(saved.basket || [], saved.deposit || 0);
            setHoldings(Object.fromEntries(legs.map((l) => [l.id, l.amount])));
            pushLog(`Restored live index ${saved.clone.slice(0, 10)}… — ${window.fmtNum(sh.shares, 2)} shares on-chain. You can cash out.`, "ok");
          } else if (sh.shares <= 0) {
            localStorage.removeItem("xindex_session");
          }
        }
      } catch (err) {
        pushLog("Chain connect failed: " + (err.message || err), "burn");
      }
    })();
    return () => { on = false; };
  }, []);

  const basketIds = new Set(basket.map((b) => b.id));
  const minted = totalShares > 0;

  // derived NAV / values
  const navFrom = (h) => Object.entries(h).reduce((s, [id, amt]) => s + amt * window.TOKEN_BY_ID[id].price, 0);
  const nav = navFrom(holdings);
  const sharePrice = totalShares > 0 ? nav / totalShares : 1;
  const userValue = userShares * sharePrice;

  const pushLog = (msg, kind = "info") => {
    const d = new Date();
    const t = d.toLocaleTimeString("en-GB", { hour12: false });
    setLog((l) => [...l, { t, msg, kind }].slice(-60));
  };

  // ── basket ops ──
  const toggle = (id) => {
    if (minted) return;
    setBasket((b) => (b.some((x) => x.id === id) ? b.filter((x) => x.id !== id) : [...b, { id, weight: 0 }]));
  };
  const setWeight = (id, w) => setBasket((b) => b.map((x) => (x.id === id ? { ...x, weight: w } : x)));
  const remove = (id) => setBasket((b) => b.filter((x) => x.id !== id));
  const evenSplit = () => {
    const n = basket.length;
    if (!n) return;
    const base = Math.floor(100 / n);
    let rem = 100 - base * n;
    setBasket((b) => b.map((x, i) => ({ ...x, weight: base + (i < rem ? 1 : 0) })));
  };
  const normalize = () => {
    const total = basket.reduce((s, b) => s + b.weight, 0);
    if (total === 0) return evenSplit();
    let scaled = basket.map((x) => ({ ...x, raw: (x.weight / total) * 100 }));
    let floored = scaled.map((x) => ({ ...x, weight: Math.floor(x.raw) }));
    let rem = 100 - floored.reduce((s, x) => s + x.weight, 0);
    floored.sort((a, b) => (b.raw - Math.floor(b.raw)) - (a.raw - Math.floor(a.raw)));
    for (let i = 0; i < rem; i++) floored[i % floored.length].weight += 1;
    const map = Object.fromEntries(floored.map((x) => [x.id, x.weight]));
    setBasket((b) => b.map((x) => ({ ...x, weight: map[x.id] })));
  };

  const indexName = () => {
    const top = [...basket].sort((a, b) => b.weight - a.weight).slice(0, 3).map((b) => window.TOKEN_BY_ID[b.id].symbol);
    return top.join(" / ") + (basket.length > 3 ? ` +${basket.length - 3}` : "");
  };
  const familyCount = () => new Set(basket.map((b) => window.TOKEN_BY_ID[b.id].family)).size;

  const createIndex = () => {
    const total = basket.reduce((s, b) => s + b.weight, 0);
    if (total !== 100 || basket.length === 0) return;
    const name = nameDraft.trim() || indexName();
    const symbol = symbolDraft.trim() || "XIDX";
    setCreated({ name, symbol, familyCount: familyCount() });
    pushLog(`Index “${name}” (${symbol}) composed — ${basket.length} constituents across ${familyCount()} chain families.`, "ok");
  };

  const resetAll = () => {
    setBasket([]); setCreated(null); setHoldings({}); setTotalShares(0); setUserShares(0);
    setNameDraft(""); setSymbolDraft("");
    setFlow({ kind: null, phase: -1 }); busyRef.current = false;
    cloneRef.current = null;
    try { localStorage.removeItem("xindex_session"); } catch (_) {}
    pushLog("Cleared index. Build a new basket to start again.", "info");
  };

  const faucet = async () => {
    if (busyRef.current) return;
    setFlash(true);
    setTimeout(() => setFlash(false), 650);
    pushLog("Faucet: requesting 10,000 USDT on Sepolia…", "faucet");
    try {
      const bal = await window.XindexChain.faucet(pushLog);
      setUsdt(window.round2(bal.usdt));
      setEth(window.round2(bal.eth));
      pushLog("Faucet settled — wallet balances synced from chain.", "ok");
    } catch (e) {
      pushLog("Faucet failed: " + (e.message || e), "burn");
    }
  };

  // ── native redemption flow ──
  const openNativeRedeem = (pct) => {
    if (busyRef.current || userShares <= 0) return;
    const burnShares = window.round2((userShares * pct) / 100);
    const ts = totalSharesRef.current;
    const fraction = ts > 0 ? burnShares / ts : 0;
    const legs = basket.map((b) => {
      const t = window.TOKEN_BY_ID[b.id];
      const amt = (holdingsRef.current[b.id] || 0) * fraction;
      return { id: b.id, token: t, amount: amt, usd: amt * t.price };
    }).filter((l) => l.amount > 0);
    setRd({ open: true, step: "form", pct, burnShares, fraction, legs, addresses: {}, progress: {} });
  };
  const rdSetAddr = (chain, val) => setRd((r) => ({ ...r, addresses: { ...r.addresses, [chain]: val } }));
  const rdReview = () => setRd((r) => ({ ...r, step: "confirm" }));
  const rdBack = () => setRd((r) => ({ ...r, step: "form" }));
  const rdClose = () => { if (rd.step === "pending") return; setRd((r) => ({ ...r, open: false })); };

  const uniqueChains = (legs) => {
    const seen = []; legs.forEach((l) => { if (!seen.includes(l.token.chain)) seen.push(l.token.chain); }); return seen;
  };

  const rdSubmit = async () => {
    if (busyRef.current || !cloneRef.current) return;
    busyRef.current = true;
    const chains = uniqueChains(rd.legs);
    const symbol = created?.symbol || "XIDX";
    setRd((r) => ({ ...r, step: "pending", progress: Object.fromEntries(chains.map((c) => [c, "queued"])) }));
    pushLog(`Cashing out ${window.fmtNum(rd.burnShares, 2)} ${symbol} natively across ${chains.length} ${chains.length === 1 ? "chain" : "chains"}…`, "burn");
    // cosmetic per-chain progress while the real burn settles on-chain
    const stages = ["signing", "sent", "done"];
    chains.forEach((c, ci) => stages.forEach((st, si) =>
      setTimeout(() => setRd((r) => (r.open ? { ...r, progress: { ...r.progress, [c]: st } } : r)), 500 + ci * 400 + si * 600)));
    try {
      const res = await window.XindexChain.burn(cloneRef.current, basket, rd.fraction, () => {}, pushLog);
      setHoldings((h) => { const n = { ...h }; Object.keys(n).forEach((id) => { n[id] = n[id] * (1 - rd.fraction); }); return n; });
      setTotalShares((t) => window.round2(t - rd.burnShares));
      setUserShares((u) => window.round2(u - rd.burnShares));
      setUsdt(window.round2(res.usdt));
      setRd((r) => ({ ...r, step: "done", progress: Object.fromEntries(chains.map((c) => [c, "done"])) }));
      pushLog(`Native redemption settled — ${window.fmtNum(res.usdtBack, 2)} USDT-equiv delivered (cross-chain leg simulated).`, "ok");
    } catch (e) {
      pushLog("Redemption failed: " + (e.message || e), "burn");
      setRd((r) => ({ ...r, step: "form" }));
    }
    busyRef.current = false;
  };

  // ── mint lifecycle ──
  const doMint = async (amount) => {
    if (busyRef.current || amount <= 0 || amount > usdt) return;
    busyRef.current = true;
    const legs = window.legsFor(basket, amount);
    pushLog(`Depositing ${window.fmtNum(amount, 2)} USDT into the Xindex vault…`, "mint");
    const onPhase = (p) => setFlow({ kind: "mint", phase: p });
    onPhase(0);
    try {
      if (!cloneRef.current) {
        cloneRef.current = await window.XindexChain.createIndex(basket, created?.name, created?.symbol, pushLog);
        pushLog(`Index deployed at ${cloneRef.current.slice(0, 10)}… on Sepolia.`, "ok");
      }
      const res = await window.XindexChain.mint(cloneRef.current, basket, amount, onPhase, pushLog);
      // real on-chain shares; per-asset holdings shown as the illustrative
      // USD-split (testnet legs carry no native price).
      setHoldings((h) => {
        const n = { ...h };
        legs.forEach((l) => { n[l.id] = (n[l.id] || 0) + l.amount; });
        return n;
      });
      setTotalShares(window.round2(res.shares));
      setUserShares(window.round2(res.shares));
      setUsdt(window.round2(await window.XindexChain.usdtBalance()));
      pushLog(`Minted ${window.fmtNum(res.shares, 2)} ${created?.symbol || "XIDX"} shares — real on-chain.`, "ok");
      // refresh-safe: remember the live index so a reload can restore it from chain
      try {
        localStorage.setItem("xindex_session", JSON.stringify({
          clone: cloneRef.current, basket, name: created?.name, symbol: created?.symbol, deposit: amount,
        }));
      } catch (_) {}
    } catch (e) {
      pushLog("Mint failed: " + (e.message || e), "burn");
    }
    setTimeout(() => { setFlow({ kind: null, phase: -1 }); busyRef.current = false; }, 700);
  };

  // ── burn lifecycle ──
  const doBurn = async (pct) => {
    if (busyRef.current || userShares <= 0 || !cloneRef.current) return;
    busyRef.current = true;
    const fraction = pct / 100;
    pushLog(`Burning ${pct}% of holding (${window.fmtNum(userShares * fraction, 2)} shares)…`, "burn");
    const onPhase = (p) => setFlow({ kind: "burn", phase: p });
    onPhase(0);
    try {
      const res = await window.XindexChain.burn(cloneRef.current, basket, fraction, onPhase, pushLog);
      setHoldings((h) => {
        const n = { ...h };
        Object.keys(n).forEach((id) => { n[id] = n[id] * (1 - fraction); });
        return n;
      });
      setTotalShares((t) => window.round2(t * (1 - fraction)));
      setUserShares((u) => window.round2(u * (1 - fraction)));
      setUsdt(window.round2(res.usdt));
      pushLog(`USDT returned: ${window.fmtNum(res.usdtBack, 2)} — real on-chain.`, "ok");
    } catch (e) {
      pushLog("Cash-out failed: " + (e.message || e), "burn");
    }
    setTimeout(() => { setFlow({ kind: null, phase: -1 }); busyRef.current = false; }, 700);
  };

  return (
    <div className="min-h-screen pb-10">
      <TopBar address={window.XindexChain ? window.XindexChain.address.slice(0, 6) + "…" + window.XindexChain.address.slice(-4) : "0x…"} eth={eth} usdt={usdt} onFaucet={faucet} flash={flash} busy={false} />

      <main className="max-w-[1320px] mx-auto px-4 sm:px-6 mt-4 flex flex-col gap-4">
        <div className="grid lg:grid-cols-[1.5fr_1fr] gap-4 items-start" style={{ minHeight: "min(620px, 70vh)" }}>
          <div className="flex flex-col h-full" style={{ maxHeight: "calc(100vh - 180px)" }}>
            <Catalog basketIds={basketIds} onToggle={toggle} locked={minted} />
          </div>
          <div className="flex flex-col h-full" style={{ maxHeight: "calc(100vh - 180px)" }}>
            <Basket
              basket={basket}
              onWeight={setWeight}
              onRemove={remove}
              onEven={evenSplit}
              onNormalize={normalize}
              onCreate={createIndex}
              created={!!created}
              locked={minted}
              nameDraft={nameDraft}
              symbolDraft={symbolDraft}
              autoName={basket.length ? indexName() : "Name your index"}
              onName={setNameDraft}
              onSymbol={setSymbolDraft}
            />
          </div>
        </div>

        {minted && (
          <div className="flex items-center justify-between -mb-1">
            <span className="text-[11.5px] text-faint">Holdings are locked while the index is live.</span>
            <button onClick={resetAll} className="ghost-btn !py-1.5 !px-3 text-[12px]">Start a new index</button>
          </div>
        )}

        {created && (
          <IndexPanel
            index={{ name: created.name, symbol: created.symbol, familyCount: created.familyCount }}
            basket={basket}
            nav={nav}
            totalShares={totalShares}
            userShares={userShares}
            userValue={userValue}
            sharePrice={sharePrice}
            holdings={holdings}
            usdtBalance={usdt}
            flow={flow}
            onMint={doMint}
            onBurn={doBurn}
            onNativeRedeem={openNativeRedeem}
            nativeBusy={rd.open && rd.step === "pending"}
          />
        )}

        <ActivityLog entries={log} />
      </main>

      <RedeemModal
        rd={rd}
        symbol={created?.symbol || "XIDX"}
        onAddr={rdSetAddr}
        onReview={rdReview}
        onBack={rdBack}
        onSubmit={rdSubmit}
        onClose={rdClose}
      />
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
