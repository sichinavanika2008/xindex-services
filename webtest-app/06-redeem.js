// ── Native redemption flow: per-chain address collection + settle ───
const { useState: useStateRd } = React;

function groupLegs(legs) {
  const out = [], by = {};
  legs.forEach((l) => {
    const c = l.token.chain;
    if (!by[c]) { by[c] = { chain: c, token: l.token, amount: 0, usd: 0 }; out.push(by[c]); }
    by[c].amount += l.amount; by[c].usd += l.usd;
  });
  return out;
}

// demo address samples that pass validation (for the faucet-style helper)
function sampleAddr(token) {
  const b58 = "8xqp9KmWv2RtY7nQ3sZ1aBcD4eF6gH5jKpLmNrStUvW";
  switch (token.family) {
    case "EVM": return "0x" + "a3F19c2B".repeat(5).slice(0, 40);
    case "UTXO": return token.id === "doge" ? "DQA5h47oXh3w8x9P2mKvQ7rT1sLpZnYbCd" : token.id === "zec" ? "t1bChooseAddr9x2mKvQ7rT1sLpZnYbCdEf" : "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    case "Cosmos": return (token.id === "usdc" ? "noble1" : "cosmos1") + "x7y2z9q3m8k4p6r5s1t0v2w4n6b8d0f2h4j6l8";
    case "XRP": return "rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFy";
    case "Solana": return b58;
    case "TRON": return "TQ5NMqJzL8vK3pWxR7yB4nH6sD9cF2gA1bE";
    default: return "";
  }
}

function StatusIcon({ state }) {
  if (state === "done") return (<span className="grid place-items-center w-5 h-5 rounded-full shrink-0" style={{ background: "color-mix(in srgb, var(--green) 16%, transparent)", color: "var(--green)" }}><svg viewBox="0 0 14 14" className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round"><path d="M2.5 7.5 L6 11 L11.5 3.5" /></svg></span>);
  if (state === "queued") return (<span className="w-5 h-5 rounded-full shrink-0 grid place-items-center"><span className="w-1.5 h-1.5 rounded-full" style={{ background: "var(--faint)" }} /></span>);
  return (<span className="xi-spin-sm shrink-0" />);
}

function RedeemModal({ rd, symbol, onAddr, onReview, onBack, onSubmit, onClose }) {
  const [ack, setAck] = useStateRd(false);
  if (!rd.open) return null;
  const groups = groupLegs(rd.legs);
  const allValid = groups.every((g) => window.validateAddress(g.token, rd.addresses[g.chain]).valid);
  const totalUsd = groups.reduce((s, g) => s + g.usd, 0);
  const step = rd.step;
  const locked = step === "pending";

  const Mono = window.Monogram;

  return (
    <div className="fixed inset-0 z-50 grid place-items-center px-4 xi-modal-overlay" onMouseDown={(e) => { if (e.target === e.currentTarget && !locked) onClose(); }}>
      <div className="panel !rounded-2xl w-full max-w-[540px] xi-modal-card overflow-hidden flex flex-col" style={{ maxHeight: "90vh" }}>
        {/* header */}
        <div className="px-6 pt-5 pb-4 flex items-start justify-between gap-4 border-b shrink-0" style={{ borderColor: "var(--line)" }}>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-[17px] font-semibold text-ink tracking-tight">Cash out to native assets</h3>
            </div>
            <p className="text-[12.5px] text-mute mt-1">
              {step === "form" && `Burning ${window.fmtNum(rd.burnShares, 2)} ${symbol} → receive ${groups.length} assets on their own chains.`}
              {step === "confirm" && "Review destinations. This cannot be undone once submitted."}
              {step === "pending" && "Settling across chains — this resolves over a few minutes."}
              {step === "done" && "Your assets are on their way to your wallets."}
            </p>
          </div>
          {!locked && (
            <button onClick={onClose} className="grid place-items-center w-8 h-8 rounded-lg text-faint hover:text-ink shrink-0" style={{ border: "1px solid var(--line)" }} aria-label="Close">
              <svg viewBox="0 0 14 14" className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"><path d="M3.5 3.5 L10.5 10.5 M10.5 3.5 L3.5 10.5" /></svg>
            </button>
          )}
        </div>

        {/* step indicator */}
        <div className="px-6 py-3 flex items-center gap-2 border-b shrink-0" style={{ borderColor: "var(--line)" }}>
          {[["form", "Addresses"], ["confirm", "Confirm"], ["pending", "Settle"], ["done", "Done"]].map(([k, l], i) => {
            const order = ["form", "confirm", "pending", "done"];
            const cur = order.indexOf(step), me = order.indexOf(k);
            const on = me <= cur;
            return (
              <div key={k} className="flex items-center gap-2">
                <span className="grid place-items-center w-5 h-5 rounded-full font-mono text-[10px]" style={{ background: on ? "var(--brand)" : "rgba(255,255,255,0.05)", color: on ? "#0A0C11" : "var(--faint)", border: on ? "none" : "1px solid var(--line)" }}>{me < cur ? "✓" : i + 1}</span>
                <span className="text-[11.5px]" style={{ color: on ? "var(--ink)" : "var(--faint)" }}>{l}</span>
                {i < 3 && <span className="w-5 h-px" style={{ background: "var(--line)" }} />}
              </div>
            );
          })}
        </div>

        {/* body */}
        <div className="px-6 py-5 overflow-y-auto xi-scroll">
          {step === "form" && (
            <div className="flex flex-col gap-3">
              {groups.map((g) => {
                const val = rd.addresses[g.chain] || "";
                const res = window.validateAddress(g.token, val);
                const showErr = !res.empty && !res.valid;
                return (
                  <div key={g.chain} className="rounded-xl p-3.5" style={{ background: "rgba(255,255,255,0.018)", border: "1px solid var(--line)" }}>
                    <div className="flex items-center justify-between gap-3 mb-2.5">
                      <div className="flex items-center gap-2.5 min-w-0">
                        <Mono token={g.token} size={28} />
                        <div className="min-w-0">
                          <div className="text-[13px] text-ink font-medium leading-tight">{window.native(g.amount, g.token.price)} <span className="text-faint text-[11px]">{g.token.symbol}</span></div>
                          <div className="text-[11px] text-mute">{g.chain} · {window.usd(g.usd)}</div>
                        </div>
                      </div>
                      <button onClick={() => onAddr(g.chain, sampleAddr(g.token))} className="text-[10.5px] font-medium px-2 py-1 rounded-md text-faint hover:text-ink shrink-0" style={{ border: "1px solid var(--line)" }} title="Fill a demo address">Demo addr</button>
                    </div>
                    <div className="relative">
                      <input
                        value={val}
                        onChange={(e) => onAddr(g.chain, e.target.value)}
                        placeholder={window.addrPlaceholder(g.token)}
                        spellCheck={false}
                        className="w-full rounded-lg bg-transparent pl-3 pr-9 py-2.5 text-[12.5px] font-mono text-ink placeholder:text-faint outline-none"
                        style={{ border: `1px solid ${showErr ? "color-mix(in srgb, var(--red) 55%, transparent)" : res.valid ? "color-mix(in srgb, var(--green) 50%, transparent)" : "var(--line)"}` }}
                      />
                      {res.valid && <span className="absolute right-2.5 top-1/2 -translate-y-1/2" style={{ color: "var(--green)" }}><svg viewBox="0 0 14 14" className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M2.5 7.5 L6 11 L11.5 3.5" /></svg></span>}
                    </div>
                    {showErr && <div className="text-[11px] mt-1.5" style={{ color: "var(--red)" }}>Doesn't look like a valid {g.chain} address.</div>}
                  </div>
                );
              })}
              <div className="flex items-start gap-2 text-[11.5px] text-faint mt-0.5">
                <svg viewBox="0 0 16 16" className="w-4 h-4 mt-px shrink-0" fill="none" stroke="currentColor" strokeWidth="1.4"><circle cx="8" cy="8" r="6.5" /><path d="M8 5 v.01 M8 7.5 v3.5" strokeLinecap="round" /></svg>
                <span>Each leg settles to an address you control on its own chain. Double-check every one — transfers are irreversible.</span>
              </div>
            </div>
          )}

          {step === "confirm" && (
            <div className="flex flex-col gap-3">
              <div className="rounded-xl overflow-hidden" style={{ border: "1px solid var(--line)" }}>
                {groups.map((g, i) => (
                  <div key={g.chain} className="flex items-center gap-3 px-3.5 py-3" style={{ borderTop: i ? "1px solid rgba(255,255,255,0.04)" : "none" }}>
                    <Mono token={g.token} size={26} />
                    <div className="min-w-0 flex-1">
                      <div className="text-[12.5px] text-ink font-medium leading-tight">{window.native(g.amount, g.token.price)} {g.token.symbol} <span className="text-faint">· {g.chain}</span></div>
                      <div className="font-mono text-[11px] text-mute truncate mt-0.5">→ {rd.addresses[g.chain]}</div>
                    </div>
                    <span className="font-mono text-[12px] text-mute tabular-nums shrink-0">{window.usd(g.usd)}</span>
                  </div>
                ))}
              </div>
              <div className="flex items-center justify-between px-1">
                <span className="text-[12px] text-mute">Total redeem value</span>
                <span className="font-mono text-[14px] font-semibold text-ink tabular-nums">{window.usd(totalUsd)}</span>
              </div>
              <div className="rounded-xl p-3.5 flex items-start gap-2.5" style={{ background: "rgba(255,107,107,0.07)", border: "1px solid color-mix(in srgb, var(--red) 28%, transparent)" }}>
                <svg viewBox="0 0 16 16" className="w-4 h-4 mt-px shrink-0" fill="none" stroke="var(--red)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M8 2 L15 14 H1 Z" /><path d="M8 6.5 v3 M8 11.5 v.01" /></svg>
                <span className="text-[12px]" style={{ color: "color-mix(in srgb, var(--red) 85%, white)" }}>Funds are sent to these exact addresses across {groups.length} chains. A wrong address means permanent loss — Xindex cannot recover it.</span>
              </div>
              <label className="flex items-center gap-2.5 cursor-pointer select-none px-1">
                <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} className="xi-check" />
                <span className="text-[12.5px] text-mute">I've verified every destination address is correct and under my control.</span>
              </label>
            </div>
          )}

          {(step === "pending" || step === "done") && (
            <div className="flex flex-col gap-2.5">
              {step === "pending" && (
                <div className="text-[12.5px] text-mute mb-1">Selling and dispatching native legs across {groups.length} chains. You can leave this open — settlement continues in the background.</div>
              )}
              {groups.map((g) => {
                const st = rd.progress[g.chain] || "queued";
                const label = { queued: "Queued", signing: "Signing (3-of-5)…", sent: "Broadcast on-chain…", done: "Delivered" }[st];
                return (
                  <div key={g.chain} className="flex items-center gap-3 rounded-xl px-3.5 py-3" style={{ background: "rgba(255,255,255,0.018)", border: "1px solid var(--line)" }}>
                    <Mono token={g.token} size={26} />
                    <div className="min-w-0 flex-1">
                      <div className="text-[12.5px] text-ink font-medium leading-tight">{window.native(g.amount, g.token.price)} {g.token.symbol} <span className="text-faint">· {g.chain}</span></div>
                      <div className="font-mono text-[10.5px] text-mute truncate mt-0.5">→ {window.shortAddr(rd.addresses[g.chain])}</div>
                    </div>
                    <span className="text-[11px]" style={{ color: st === "done" ? "var(--green)" : "var(--mute)" }}>{label}</span>
                    <StatusIcon state={st} />
                  </div>
                );
              })}
              {step === "done" && (
                <div className="rounded-xl p-3.5 flex items-center gap-2.5 mt-1" style={{ background: "color-mix(in srgb, var(--green) 9%, transparent)", border: "1px solid color-mix(in srgb, var(--green) 28%, transparent)" }}>
                  <span className="grid place-items-center w-7 h-7 rounded-full shrink-0" style={{ background: "color-mix(in srgb, var(--green) 16%, transparent)", color: "var(--green)" }}><svg viewBox="0 0 16 16" className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M3 8.4 L6.4 12 L13 4.5" /></svg></span>
                  <span className="text-[12.5px]" style={{ color: "color-mix(in srgb, var(--green) 88%, white)" }}>Redeemed {window.fmtNum(rd.burnShares, 2)} {symbol} natively. {window.usd(totalUsd)} in assets delivered across {groups.length} chains.</span>
                </div>
              )}
            </div>
          )}
        </div>

        {/* footer actions */}
        <div className="px-6 py-4 border-t shrink-0 flex items-center justify-between gap-3" style={{ borderColor: "var(--line)" }}>
          {step === "form" && (
            <>
              <button onClick={onClose} className="ghost-btn !py-2.5">Cancel</button>
              <button onClick={onReview} disabled={!allValid} className="primary-btn !py-2.5 px-5" style={{ opacity: allValid ? 1 : 0.5, cursor: allValid ? "pointer" : "not-allowed" }}>Review redemption</button>
            </>
          )}
          {step === "confirm" && (
            <>
              <button onClick={onBack} className="ghost-btn !py-2.5">Back</button>
              <button onClick={onSubmit} disabled={!ack} className="success-btn !py-2.5 px-5" style={{ opacity: ack ? 1 : 0.5, cursor: ack ? "pointer" : "not-allowed" }}>Confirm &amp; redeem</button>
            </>
          )}
          {step === "pending" && (
            <div className="w-full flex items-center justify-center gap-2 text-[12px] text-mute"><span className="xi-spin-sm" /> Settling across chains…</div>
          )}
          {step === "done" && (
            <button onClick={onClose} className="primary-btn !py-2.5 w-full">Done</button>
          )}
        </div>
      </div>
    </div>
  );
}

window.RedeemModal = RedeemModal;
