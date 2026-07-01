// ── Index panel: stats, holdings, mint & burn async lifecycles ──────
const { Monogram, Lifecycle, AllocationBar } = window;

const MINT_STEPS = ["Deposit USDT", "THORChain swap", "3-of-5 attest", "Shares minted"];
const BURN_STEPS = ["Burn shares", "Redeem legs", "3-of-5 attest", "USDT paid"];

function Stat({ label, value, num, format, sub, accent }) {
  const Num = window.CountUp;
  return (
    <div className="flex-1 min-w-[120px] px-4 py-3.5 rounded-xl" style={{ background: "rgba(255,255,255,0.022)", border: "1px solid var(--line)" }}>
      <div className="text-[11.5px] text-mute uppercase tracking-[0.08em]">{label}</div>
      <div className="font-mono text-[22px] font-semibold tabular-nums mt-1 leading-none" style={{ color: accent || "var(--ink)" }}>
        {num != null && Num ? <Num value={num} format={format} duration={750} /> : value}
      </div>
      {sub && <div className="text-[11.5px] text-faint mt-1.5">{sub}</div>}
    </div>
  );
}

function HoldingsTable({ basket, holdings, totalShares }) {
  return (
    <div className="rounded-xl overflow-hidden" style={{ border: "1px solid var(--line)" }}>
      <div className="grid grid-cols-[1.6fr_0.7fr_1fr_1fr] gap-2 px-4 py-2.5 text-[11px] uppercase tracking-[0.08em] text-faint" style={{ background: "rgba(255,255,255,0.02)", borderBottom: "1px solid var(--line)" }}>
        <span>Asset</span>
        <span className="text-right">Target</span>
        <span className="text-right">Held</span>
        <span className="text-right">Value</span>
      </div>
      <div className="flex flex-col">
        {basket.map((b, i) => {
          const t = window.TOKEN_BY_ID[b.id];
          const held = holdings[b.id] || 0;
          const value = held * t.price;
          return (
            <div key={b.id} className="grid grid-cols-[1.6fr_0.7fr_1fr_1fr] gap-2 px-4 py-2.5 items-center" style={{ borderTop: i === 0 ? "none" : "1px solid rgba(255,255,255,0.04)" }}>
              <div className="flex items-center gap-2.5 min-w-0">
                <Monogram token={t} size={26} />
                <div className="min-w-0">
                  <div className="text-[13px] text-ink font-medium truncate leading-tight">{t.symbol}</div>
                  <div className="text-[11px] text-mute truncate">{t.chain}</div>
                </div>
              </div>
              <div className="text-right font-mono text-[13px] text-mute tabular-nums">{b.weight}%</div>
              <div className="text-right font-mono text-[13px] text-ink tabular-nums">
                {window.native(held, t.price)} <span className="text-faint text-[11px]">{t.symbol}</span>
              </div>
              <div className="text-right font-mono text-[13px] text-ink tabular-nums">{window.usd(value)}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function MintControl({ usdtBalance, busy, flow, onMint, sharePrice, symbol }) {
  const [amount, setAmount] = useState("1000");
  const num = Number(amount) || 0;
  const insufficient = num > usdtBalance;
  const invalid = num <= 0 || insufficient;
  const active = flow.kind === "mint" && flow.phase >= 0 && flow.phase < MINT_STEPS.length;
  const sharesOut = sharePrice > 0 ? num / sharePrice : 0;

  return (
    <div className="rounded-xl p-4" style={{ background: "rgba(255,255,255,0.022)", border: "1px solid var(--line)" }}>
      <div className="flex items-center justify-between mb-3">
        <div className="text-[13px] font-semibold text-ink">Mint shares</div>
        <div className="text-[11.5px] text-mute">Balance <span className="font-mono text-ink tabular-nums">{window.fmtNum(usdtBalance, 2)}</span> USDT</div>
      </div>
      <div className="flex items-stretch gap-2.5">
        <div className="relative flex-1">
          <input
            type="number" min="0" value={amount} disabled={busy}
            onChange={(e) => setAmount(e.target.value)}
            placeholder="0.00"
            aria-label="USDT amount to deposit"
            className="w-full rounded-xl bg-transparent pl-3.5 pr-16 py-2.5 text-[15px] font-mono tabular-nums text-ink outline-none xi-num disabled:opacity-60"
            style={{ border: `1px solid ${insufficient ? "color-mix(in srgb, var(--red) 50%, transparent)" : "var(--line)"}` }}
            onFocus={(e) => { if (!insufficient) e.target.style.borderColor = "color-mix(in srgb, var(--brand) 55%, transparent)"; }}
            onBlur={(e) => { if (!insufficient) e.target.style.borderColor = "var(--line)"; }}
          />
          <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1.5">
            <button onClick={() => setAmount(String(Math.floor(usdtBalance)))} disabled={busy} className="text-[10.5px] font-medium px-1.5 py-0.5 rounded-md text-faint hover:text-ink" style={{ border: "1px solid var(--line)" }}>MAX</button>
            <span className="text-[12px] text-faint font-mono">USDT</span>
          </div>
        </div>
        <button
          onClick={() => onMint(num)}
          disabled={busy || invalid}
          className="primary-btn px-5 shrink-0"
          style={{ opacity: busy || invalid ? 0.5 : 1, cursor: busy || invalid ? "not-allowed" : "pointer" }}
        >
          {busy && flow.kind === "mint" ? "Minting…" : "Mint"}
        </button>
      </div>
      {insufficient && <div className="text-[11.5px] mt-2" style={{ color: "var(--red)" }}>Insufficient USDT balance — use the faucet to top up.</div>}
      {!invalid && (
        <div className="flex items-center justify-between mt-3 px-3 py-2.5 rounded-lg" style={{ background: "rgba(255,255,255,0.018)", border: "1px solid var(--line)" }}>
          <span className="text-[11.5px] text-mute">You pay <span className="font-mono text-ink tabular-nums">{window.fmtNum(num, 2)}</span> USDT</span>
          <svg viewBox="0 0 16 16" className="w-3.5 h-3.5 text-faint" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M3 8 H12.5 M9 4.5 L12.5 8 L9 11.5" /></svg>
          <span className="text-[11.5px] text-mute">Receive ≈ <span className="font-mono tabular-nums" style={{ color: "var(--brand-200)" }}>{window.fmtNum(sharesOut, 2)}</span> {symbol || "XIDX"}</span>
        </div>
      )}
      {(active || flow.kind === "mint") && flow.phase >= 0 && (
        <div className="mt-3.5">
          <Lifecycle steps={MINT_STEPS} phase={flow.phase} />
        </div>
      )}
    </div>
  );
}

function BurnControl({ userShares, busy, flow, onBurn, onNativeRedeem }) {
  const [pct, setPct] = useState(50);
  const [mode, setMode] = useState("usdt"); // usdt | native
  const burnShares = (userShares * pct) / 100;
  const native = mode === "native";

  return (
    <div className="rounded-xl p-4" style={{ background: "rgba(255,255,255,0.022)", border: "1px solid var(--line)" }}>
      <div className="flex items-center justify-between mb-3">
        <div className="text-[13px] font-semibold text-ink">Burn &amp; redeem</div>
        <div className="text-[11.5px] text-mute">Your shares <span className="font-mono text-ink tabular-nums">{window.fmtNum(userShares, 2)}</span></div>
      </div>
      {/* redemption mode toggle */}
      <div className="flex gap-1 p-1 rounded-lg mb-3" style={{ background: "rgba(255,255,255,0.03)", border: "1px solid var(--line)" }}>
        {[["usdt", "To USDT"], ["native", "To native assets"]].map(([k, l]) => (
          <button key={k} onClick={() => setMode(k)} disabled={busy} className="flex-1 py-1.5 rounded-md text-[12px] font-medium transition-colors" style={{ background: mode === k ? "color-mix(in srgb, var(--green) 16%, transparent)" : "transparent", color: mode === k ? "var(--green)" : "var(--mute)", border: mode === k ? "1px solid color-mix(in srgb, var(--green) 32%, transparent)" : "1px solid transparent" }}>{l}</button>
        ))}
      </div>
      <div className="flex items-center gap-3 mb-1">
        <input
          type="range" min="1" max="100" step="1" value={pct} disabled={busy}
          onChange={(e) => setPct(Number(e.target.value))}
          className="xi-slider flex-1" style={{ "--pct": `${pct}%`, "--accent": "var(--green)" }}
          aria-label="Percent of shares to burn"
        />
        <div className="font-mono text-[16px] font-semibold tabular-nums w-[52px] text-right" style={{ color: "var(--green)" }}>{pct}%</div>
      </div>
      <div className="flex items-center gap-2 mb-3 mt-1">
        {[["Half", 50], ["Max", 100]].map(([l, v]) => (
          <button key={l} onClick={() => setPct(v)} disabled={busy} className="text-[10.5px] font-medium px-2 py-0.5 rounded-md text-faint hover:text-ink" style={{ border: "1px solid var(--line)" }}>{l}</button>
        ))}
        <span className="text-[11px] text-mute ml-auto">{native ? "Sends each leg to your own chains" : "Settles back to USDT"}</span>
      </div>
      <div className="flex items-center justify-between gap-2">
        <div className="text-[11.5px] text-mute">Burning <span className="font-mono text-ink tabular-nums">{window.fmtNum(burnShares, 2)}</span> shares</div>
        <button
          onClick={() => (native ? onNativeRedeem(pct) : onBurn(pct))}
          disabled={busy || userShares <= 0}
          className="success-btn px-5 shrink-0"
          style={{ opacity: busy || userShares <= 0 ? 0.5 : 1, cursor: busy || userShares <= 0 ? "not-allowed" : "pointer" }}
        >
          {busy && flow.kind === "burn" ? "Burning…" : native ? "Redeem natively" : "Burn"}
        </button>
      </div>
      {flow.kind === "burn" && flow.phase >= 0 && (
        <div className="mt-3.5">
          <Lifecycle steps={BURN_STEPS} phase={flow.phase} accent="var(--green)" />
        </div>
      )}
    </div>
  );
}

function IndexPanel({ index, basket, nav, totalShares, userShares, userValue, sharePrice, holdings, usdtBalance, flow, onMint, onBurn, onNativeRedeem, nativeBusy }) {
  const busy = flow.kind !== null || nativeBusy;
  const minted = totalShares > 0;

  return (
    <section className="panel">
      <div className="px-5 sm:px-6 pt-5 pb-4 border-b flex flex-wrap items-center justify-between gap-3" style={{ borderColor: "var(--line)" }}>
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex -space-x-2">
            {basket.slice(0, 5).map((b) => (
              <div key={b.id} className="ring-2 rounded-full" style={{ "--tw-ring-color": "var(--panel)" }}>
                <Monogram token={window.TOKEN_BY_ID[b.id]} size={30} />
              </div>
            ))}
            {basket.length > 5 && (
              <div className="grid place-items-center w-[30px] h-[30px] rounded-full text-[11px] font-mono text-mute ring-2" style={{ background: "var(--panel2)", "--tw-ring-color": "var(--panel)", border: "1px solid var(--line)" }}>+{basket.length - 5}</div>
            )}
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h2 className="text-[16px] font-semibold text-ink tracking-tight truncate">{index.name}</h2>
              <span className="font-mono text-[10px] px-1.5 py-0.5 rounded-md text-brand-200" style={{ background: "color-mix(in srgb, var(--brand) 14%, transparent)", border: "1px solid color-mix(in srgb, var(--brand) 32%, transparent)" }}>{index.symbol}</span>
            </div>
            <div className="text-[12px] text-mute">{basket.length} constituents · {index.familyCount} {index.familyCount === 1 ? "chain family" : "chain families"}</div>
          </div>
        </div>
      </div>

      <div className="p-5 sm:p-6 flex flex-col gap-5">
        {/* stats */}
        <div className="flex flex-wrap gap-2.5">
          <Stat label="Index NAV" num={nav} format={(v) => window.usd(v)} sub={`Share price ${window.usd(sharePrice, { minimumFractionDigits: 4, maximumFractionDigits: 4 })}`} />
          <Stat label="Your shares" num={userShares} format={(v) => window.fmtNum(v, 2)} sub={minted ? `${totalShares > 0 ? ((userShares / totalShares) * 100).toFixed(1) : 0}% of supply` : "Not minted yet"} />
          <Stat label="Your value" num={userValue} format={(v) => window.usd(v)} accent={userValue > 0 ? "var(--green)" : null} sub="Marked at mock prices" />
        </div>

        {/* holdings */}
        {minted ? (
          <HoldingsTable basket={basket} holdings={holdings} totalShares={totalShares} />
        ) : (
          <div className="rounded-xl px-4 py-5 text-center" style={{ border: "1px dashed var(--line)" }}>
            <div className="text-[13px] text-ink font-medium">No holdings yet</div>
            <div className="text-[12px] text-mute mt-1">Deposit USDT below to mint shares and acquire the native legs across chains.</div>
          </div>
        )}

        {/* allocation reminder */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-[12px] text-mute">Target allocation</span>
          </div>
          <AllocationBar basket={basket} />
        </div>

        {/* mint + burn */}
        <div className="grid md:grid-cols-2 gap-3.5">
          <MintControl usdtBalance={usdtBalance} busy={busy} flow={flow} onMint={onMint} sharePrice={sharePrice} symbol={index.symbol} />
          {userShares > 0 ? (
            <BurnControl userShares={userShares} busy={busy} flow={flow} onBurn={onBurn} onNativeRedeem={onNativeRedeem} />
          ) : (
            <div className="rounded-xl p-4 grid place-items-center text-center" style={{ background: "rgba(255,255,255,0.012)", border: "1px dashed var(--line)" }}>
              <div>
                <div className="text-[13px] text-faint font-medium">Burn &amp; redeem</div>
                <div className="text-[11.5px] text-faint mt-1 max-w-[220px]">Available once you hold shares. Redeems native legs back to USDT.</div>
              </div>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

Object.assign(window, { IndexPanel, MINT_STEPS, BURN_STEPS });
