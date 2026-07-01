// ── Left column: Choose your assets (catalog grid + search + filters) ─
const { Monogram, StatusPill, WeightSlider, AllocationBar, FamilyBreakdown } = window;

function SearchIcon() {
  return (
    <svg viewBox="0 0 16 16" className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round">
      <circle cx="7" cy="7" r="4.5" />
      <path d="M10.5 10.5 L14 14" />
    </svg>
  );
}

// deterministic mini price chart per asset
function hashStr(s) { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; }
function rngFrom(seed) { let a = seed >>> 0; return () => { a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }

function Sparkline({ token, h = 36 }) {
  const W = 140;
  const up = token.change >= 0;
  const rng = rngFrom(hashStr(token.id));
  const N = 24;
  const drift = (token.change / 100) * 0.55;
  let v = 0; const pts = [];
  for (let i = 0; i < N; i++) { v += (rng() - 0.5) * 0.85 + drift; pts.push(v); }
  const min = Math.min(...pts), max = Math.max(...pts), range = (max - min) || 1;
  const xy = pts.map((p, i) => [(i / (N - 1)) * W, h - 2.5 - ((p - min) / range) * (h - 5)]);
  const line = xy.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`).join(" ");
  const area = `${line} L${W} ${h} L0 ${h} Z`;
  const col = up ? "#3FD08B" : "#FF6B6B";
  const gid = `spk-${token.id}`;
  return (
    <svg width="100%" height={h} viewBox={`0 0 ${W} ${h}`} preserveAspectRatio="none" className="block overflow-visible">
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor={col} stopOpacity="0.20" />
          <stop offset="1" stopColor={col} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={area} fill={`url(#${gid})`} />
      <path d={line} fill="none" stroke={col} strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

function FilterPills({ active, onChange, counts }) {
  const fams = ["All", ...window.FAMILIES];
  return (
    <div className="flex flex-wrap gap-1.5">
      {fams.map((f) => {
        const on = active === f;
        const n = f === "All" ? counts.all : counts[f] || 0;
        return (
          <button
            key={f}
            onClick={() => onChange(f)}
            className="filter-pill flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[12px] font-medium"
            style={{
              background: on ? "color-mix(in srgb, var(--brand) 15%, transparent)" : "rgba(255,255,255,0.03)",
              border: `1px solid ${on ? "color-mix(in srgb, var(--brand) 45%, transparent)" : "var(--line)"}`,
              color: on ? "var(--brand-200)" : "var(--mute)",
            }}
          >
            {f}
            <span className="font-mono text-[10px]" style={{ color: on ? "var(--brand-200)" : "var(--faint)", opacity: 0.85 }}>{n}</span>
          </button>
        );
      })}
    </div>
  );
}

function AssetCard({ token, selected, onToggle, locked }) {
  const up = token.change >= 0;
  return (
    <button
      type="button"
      disabled={locked}
      onClick={() => onToggle(token.id)}
      aria-pressed={selected}
      className={`asset-card group relative text-left rounded-2xl p-3.5 flex flex-col gap-2.5 disabled:opacity-50 disabled:cursor-not-allowed ${selected ? "is-selected" : ""}`}
      style={{
        background: selected ? `color-mix(in srgb, ${token.color} 10%, rgba(255,255,255,0.012))` : "rgba(255,255,255,0.018)",
        border: `1px solid ${selected ? token.color : "var(--line)"}`,
        boxShadow: selected ? `0 0 0 1px ${token.color}, 0 0 24px -6px ${token.color}, 0 14px 34px -16px ${token.color}` : "none",
      }}
    >
      <div className="flex items-start gap-2.5">
        <Monogram token={token} size={36} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <span className="font-medium text-ink text-[14px] truncate leading-tight">{token.name}</span>
            <span className="font-mono text-[10.5px] text-faint">{token.symbol}</span>
          </div>
          <div className="text-[11.5px] text-mute truncate">{token.chain}</div>
        </div>
        <span
          className="grid place-items-center w-6 h-6 rounded-lg shrink-0 transition-all duration-150"
          style={{
            background: selected ? token.color : "rgba(255,255,255,0.04)",
            color: selected ? "#0A0C11" : "var(--faint)",
            border: `1px solid ${selected ? "transparent" : "var(--line)"}`,
          }}
        >
          {selected ? (
            <svg viewBox="0 0 14 14" className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round"><path d="M2.5 7.5 L6 11 L11.5 3.5" /></svg>
          ) : (
            <svg viewBox="0 0 14 14" className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M7 2.5 V11.5 M2.5 7 H11.5" /></svg>
          )}
        </span>
      </div>

      <Sparkline token={token} />

      <div className="flex items-end justify-between gap-2">
        <div>
          <div className="font-mono text-[14px] text-ink tabular-nums leading-none">{window.price(token.price)}</div>
          <div className="font-mono text-[11px] tabular-nums mt-1.5 flex items-center gap-1" style={{ color: up ? "var(--green)" : "var(--red)" }}>
            <span style={{ fontSize: 9 }}>{up ? "▲" : "▼"}</span>{Math.abs(token.change).toFixed(2)}%
          </div>
        </div>
        <StatusPill status={token.status} mini />
      </div>
    </button>
  );
}

function Catalog({ basketIds, onToggle, locked }) {
  const [q, setQ] = useState("");
  const [fam, setFam] = useState("All");
  const query = q.trim().toLowerCase();

  const counts = { all: window.TOKENS.length };
  window.FAMILIES.forEach((f) => { counts[f] = window.TOKENS.filter((t) => t.family === f).length; });

  const list = window.TOKENS.filter((t) => {
    if (fam !== "All" && t.family !== fam) return false;
    if (query === "") return true;
    return (
      t.name.toLowerCase().includes(query) ||
      t.symbol.toLowerCase().includes(query) ||
      t.chain.toLowerCase().includes(query) ||
      t.family.toLowerCase().includes(query)
    );
  });

  return (
    <section className="panel flex flex-col min-h-0">
      <div className="px-5 sm:px-6 pt-5 pb-4 border-b" style={{ borderColor: "var(--line)" }}>
        <div className="flex items-center gap-2.5 mb-2.5">
          <span className="font-mono text-[11px] tracking-[0.18em] uppercase" style={{ color: "var(--brand-200)" }}>01 · Build</span>
          <span className="flex-1 h-px" style={{ background: "var(--line)" }} />
          {locked && <span className="font-mono text-[10.5px] text-faint">locked</span>}
        </div>
        <div className="flex items-baseline justify-between gap-3">
          <h2 className="text-[20px] font-semibold text-ink tracking-tight">Choose your assets</h2>
          <span className="font-mono text-[12px] shrink-0" style={{ color: basketIds.size ? "var(--brand-200)" : "var(--faint)" }}>{basketIds.size}<span className="text-faint">/15</span></span>
        </div>
        <p className="text-[12.5px] text-mute mt-1">Real coins across {window.FAMILIES.length} chain families — tap to add to your basket.</p>
        <div className="relative mt-3.5">
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-faint"><SearchIcon /></span>
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search symbol, name or chain…"
            aria-label="Search tokens"
            className="w-full rounded-xl bg-transparent pl-9 pr-3 py-2.5 text-[13.5px] text-ink placeholder:text-faint outline-none transition-colors"
            style={{ border: "1px solid var(--line)" }}
            onFocus={(e) => (e.target.style.borderColor = "color-mix(in srgb, var(--brand) 55%, transparent)")}
            onBlur={(e) => (e.target.style.borderColor = "var(--line)")}
          />
          {q && (
            <button onClick={() => setQ("")} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-faint hover:text-ink text-lg leading-none px-1" aria-label="Clear search">×</button>
          )}
        </div>
        <div className="mt-3"><FilterPills active={fam} onChange={setFam} counts={counts} /></div>
      </div>

      <div className="flex-1 overflow-y-auto xi-scroll p-3 sm:p-3.5">
        {list.length === 0 ? (
          <div className="text-center text-mute text-[13px] py-16">No assets match your filters.</div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            {list.map((t) => (
              <AssetCard key={t.id} token={t} selected={basketIds.has(t.id)} onToggle={onToggle} locked={locked} />
            ))}
          </div>
        )}
      </div>
    </section>
  );
}

// ── Right column: Your basket ───────────────────────────────────────
function BasketRow({ item, token, onWeight, onRemove, locked }) {
  return (
    <div className="flex items-center gap-3 px-3.5 py-3 rounded-xl" style={{ background: "rgba(255,255,255,0.022)", border: "1px solid var(--line)" }}>
      <Monogram token={token} size={30} />
      <div className="w-[88px] min-w-0 shrink-0">
        <div className="font-medium text-ink text-[13.5px] truncate leading-tight">{token.name}</div>
        <div className="text-[11.5px] text-mute truncate">{token.chain}</div>
      </div>
      <div className="flex-1 min-w-0">
        <WeightSlider value={item.weight} onChange={(v) => onWeight(item.id, v)} accent={token.color} disabled={locked} />
      </div>
      <div className="relative shrink-0">
        <input
          type="number"
          min="0"
          max="100"
          value={item.weight}
          disabled={locked}
          onChange={(e) => {
            let v = Number(e.target.value);
            if (isNaN(v)) v = 0;
            onWeight(item.id, Math.max(0, Math.min(100, Math.round(v))));
          }}
          aria-label={`${token.symbol} weight percent`}
          className="w-[58px] rounded-lg bg-transparent pl-2 pr-4 py-1.5 text-[13px] font-mono tabular-nums text-ink text-right outline-none xi-num"
          style={{ border: "1px solid var(--line)" }}
          onFocus={(e) => (e.target.style.borderColor = "color-mix(in srgb, var(--brand) 55%, transparent)")}
          onBlur={(e) => (e.target.style.borderColor = "var(--line)")}
        />
        <span className="absolute right-2 top-1/2 -translate-y-1/2 text-[11px] text-faint pointer-events-none">%</span>
      </div>
      <button onClick={() => onRemove(item.id)} disabled={locked} className="grid place-items-center w-7 h-7 rounded-lg text-faint hover:text-[color:var(--red)] shrink-0 transition-colors disabled:opacity-40" style={{ border: "1px solid var(--line)" }} aria-label={`Remove ${token.symbol}`}>
        <svg viewBox="0 0 14 14" className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"><path d="M3.5 3.5 L10.5 10.5 M10.5 3.5 L3.5 10.5" /></svg>
      </button>
    </div>
  );
}

function Basket({ basket, onWeight, onRemove, onEven, onNormalize, onCreate, created, locked, nameDraft, symbolDraft, autoName, onName, onSymbol }) {
  const total = basket.reduce((s, b) => s + b.weight, 0);
  const exact = total === 100;
  const empty = basket.length === 0;

  const totalColor = empty ? "var(--mute)" : exact ? "var(--green)" : "var(--red)";

  let createLabel = "Create index";
  if (empty) createLabel = "Add at least one asset";
  else if (!exact) createLabel = `Total must be 100% (now ${total}%)`;

  return (
    <section className="panel flex flex-col min-h-0">
      <div className="px-5 pt-5 pb-4 border-b" style={{ borderColor: "var(--line)" }}>
        <div className="flex items-baseline justify-between gap-3">
          <h2 className="text-[15px] font-semibold text-ink tracking-tight">Your basket</h2>
          <span className="font-mono text-[11px] text-faint">{basket.length} {basket.length === 1 ? "asset" : "assets"}</span>
        </div>
        <p className="text-[12.5px] text-mute mt-1">Assign each asset a target weight. Weights must sum to 100%.</p>
      </div>

      <div className="flex-1 overflow-y-auto xi-scroll px-3.5 py-3.5 flex flex-col gap-2">
        {empty ? (
          <div className="flex-1 grid place-items-center text-center py-10">
            <div>
              <div className="mx-auto w-12 h-12 rounded-2xl grid place-items-center mb-3" style={{ border: "1px dashed var(--line)" }}>
                <svg viewBox="0 0 20 20" className="w-5 h-5 text-faint" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="3" y="3" width="6" height="6" rx="1.5"/><rect x="11" y="3" width="6" height="6" rx="1.5"/><rect x="3" y="11" width="6" height="6" rx="1.5"/><rect x="11" y="11" width="6" height="6" rx="1.5"/></svg>
              </div>
              <div className="text-[14px] text-ink font-medium">Your basket is empty</div>
              <div className="text-[12.5px] text-mute mt-1 max-w-[240px]">Pick assets from the catalog to start composing your omnichain index.</div>
            </div>
          </div>
        ) : (
          basket.map((b) => (
            <BasketRow key={b.id} item={b} token={window.TOKEN_BY_ID[b.id]} onWeight={onWeight} onRemove={onRemove} locked={locked} />
          ))
        )}
      </div>

      {!empty && (
        <div className="px-5 py-4 border-t flex flex-col gap-3.5" style={{ borderColor: "var(--line)" }}>
          <div>
            <div className="flex items-center justify-between mb-2">
              <FamilyBreakdown basket={basket} />
              <div className="flex items-baseline gap-1.5">
                <span className="text-[12px] text-mute">Total</span>
                <span className="font-mono text-[18px] font-semibold tabular-nums transition-colors" style={{ color: totalColor }}>{total}%</span>
              </div>
            </div>
            <AllocationBar basket={basket} />
          </div>

          <div className="flex items-center gap-2">
            <button onClick={onEven} disabled={locked} className="ghost-btn flex-1">Even split</button>
            <button onClick={onNormalize} disabled={locked} className="ghost-btn flex-1">Normalize to 100%</button>
          </div>

          <div className="flex items-end gap-2.5">
            <div className="flex-1 min-w-0">
              <label className="block text-[10.5px] uppercase tracking-[0.08em] text-faint mb-1.5">Index name</label>
              <input
                value={nameDraft}
                onChange={(e) => onName(e.target.value.slice(0, 40))}
                placeholder={autoName}
                disabled={locked}
                aria-label="Index name"
                className="w-full rounded-xl bg-transparent px-3 py-2 text-[13.5px] text-ink placeholder:text-faint outline-none disabled:opacity-60 truncate"
                style={{ border: "1px solid var(--line)" }}
                onFocus={(e) => (e.target.style.borderColor = "color-mix(in srgb, var(--brand) 55%, transparent)")}
                onBlur={(e) => (e.target.style.borderColor = "var(--line)")}
              />
            </div>
            <div className="w-[104px] shrink-0">
              <label className="block text-[10.5px] uppercase tracking-[0.08em] text-faint mb-1.5">Symbol</label>
              <input
                value={symbolDraft}
                onChange={(e) => onSymbol(e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 6))}
                placeholder="XIDX"
                disabled={locked}
                aria-label="Index ticker symbol"
                className="w-full rounded-xl bg-transparent px-3 py-2 text-[13.5px] font-mono text-ink placeholder:text-faint outline-none disabled:opacity-60 text-center tracking-wide"
                style={{ border: "1px solid var(--line)" }}
                onFocus={(e) => (e.target.style.borderColor = "color-mix(in srgb, var(--brand) 55%, transparent)")}
                onBlur={(e) => (e.target.style.borderColor = "var(--line)")}
              />
            </div>
          </div>

          <button
            onClick={onCreate}
            disabled={!exact || empty || locked}
            className="primary-btn w-full"
            style={{ opacity: !exact || empty ? 0.5 : 1, cursor: !exact || empty ? "not-allowed" : "pointer" }}
          >
            {created ? "Update index" : createLabel}
          </button>
        </div>
      )}
    </section>
  );
}

Object.assign(window, { Catalog, Basket });
