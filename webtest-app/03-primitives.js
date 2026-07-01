// ── Shared UI primitives ────────────────────────────────────────────
const { useState, useEffect, useRef } = React;

// Circular real coin logo (CDN) with a colored-letter fallback
function Monogram({ token, size = 34 }) {
  const [err, setErr] = useState(false);
  const src = window.iconUrl ? window.iconUrl(token) : null;
  const showImg = src && !err;
  return (
    <div className="relative shrink-0 rounded-full select-none" style={{ width: size, height: size }}>
      {showImg ? (
        <img
          src={src}
          alt={token.symbol}
          width={size}
          height={size}
          draggable={false}
          onError={() => setErr(true)}
          className="block rounded-full"
          style={{ width: size, height: size, boxShadow: `0 0 0 1px ${token.color}33` }}
        />
      ) : (
        <div
          className="w-full h-full rounded-full grid place-items-center font-mono font-semibold"
          style={{
            background: `radial-gradient(120% 120% at 30% 20%, ${token.color}2E, ${token.color}14)`,
            border: `1px solid ${token.color}66`,
            color: token.color,
            fontSize: size * 0.42,
            letterSpacing: "-0.02em",
            boxShadow: `inset 0 0 12px ${token.color}1A`,
          }}
        >
          {token.symbol[0]}
        </div>
      )}
      <span
        className="absolute -bottom-0.5 -right-0.5 w-2 h-2 rounded-full"
        style={{ background: token.color, boxShadow: `0 0 0 2px var(--panel)` }}
      />
    </div>
  );
}

// live (green) / integrating (muted)
function StatusPill({ status, mini = false }) {
  const live = status === "live";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full font-medium whitespace-nowrap ${
        mini ? "px-1.5 py-0.5 text-[10px]" : "px-2 py-0.5 text-[11px]"
      }`}
      style={{
        background: live ? "rgba(63,208,139,0.10)" : "rgba(255,255,255,0.04)",
        color: live ? "var(--green)" : "var(--faint)",
        border: `1px solid ${live ? "rgba(63,208,139,0.28)" : "rgba(255,255,255,0.08)"}`,
      }}
    >
      <span
        className="w-1.5 h-1.5 rounded-full"
        style={{
          background: live ? "var(--green)" : "var(--faint)",
          boxShadow: live ? "0 0 6px var(--green)" : "none",
          animation: live ? "pulseDot 2s ease-in-out infinite" : "none",
        }}
      />
      {live ? "live" : "integrating"}
    </span>
  );
}

// Styled range slider bound to a value
function WeightSlider({ value, onChange, accent = "var(--brand)", disabled }) {
  return (
    <input
      type="range"
      min="0"
      max="100"
      step="1"
      value={value}
      disabled={disabled}
      onChange={(e) => onChange(Number(e.target.value))}
      className="xi-slider"
      style={{
        "--pct": `${value}%`,
        "--accent": accent,
      }}
      aria-label="weight percent"
    />
  );
}

// ── Lifecycle stepper ───────────────────────────────────────────────
// steps: [label,...]; phase: index of active step (-1 idle, length = done)
function Lifecycle({ steps, phase, accent = "var(--brand)" }) {
  return (
    <div className="flex items-stretch gap-2 flex-wrap">
      {steps.map((label, i) => {
        const done = i < phase;
        const active = i === phase;
        return (
          <div key={i} className="flex items-center gap-2">
            <div
              className="flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-[12.5px] font-medium transition-all duration-300"
              style={{
                background: done
                  ? "rgba(63,208,139,0.10)"
                  : active
                  ? "color-mix(in srgb, var(--brand) 16%, transparent)"
                  : "rgba(255,255,255,0.025)",
                border: `1px solid ${
                  done ? "rgba(63,208,139,0.30)" : active ? "color-mix(in srgb, var(--brand) 50%, transparent)" : "var(--line)"
                }`,
                color: done ? "var(--green)" : active ? "var(--brand-200)" : "var(--faint)",
              }}
            >
              <span className="grid place-items-center w-4 h-4 shrink-0">
                {done ? (
                  <svg viewBox="0 0 14 14" className="w-3.5 h-3.5" fill="none" stroke="var(--green)" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M2.5 7.5 L6 11 L11.5 3.5" />
                  </svg>
                ) : active ? (
                  <span className="relative grid place-items-center">
                    <span className="w-2 h-2 rounded-full" style={{ background: accent }} />
                    <span className="absolute w-4 h-4 rounded-full" style={{ border: `1.5px solid ${accent}`, animation: "ping 1.2s cubic-bezier(0,0,0.2,1) infinite" }} />
                  </span>
                ) : (
                  <span className="w-1.5 h-1.5 rounded-full" style={{ background: "var(--faint)" }} />
                )}
              </span>
              {label}
            </div>
            {i < steps.length - 1 && (
              <span
                className="w-4 h-px transition-colors duration-300"
                style={{ background: done ? "rgba(63,208,139,0.45)" : "var(--line)" }}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── Allocation bar (stacked, by asset, grouped visually) ────────────
function AllocationBar({ basket }) {
  const total = basket.reduce((s, b) => s + b.weight, 0) || 1;
  return (
    <div className="flex h-2.5 w-full overflow-hidden rounded-full" style={{ background: "rgba(255,255,255,0.05)" }}>
      {basket.map((b) => {
        const t = window.TOKEN_BY_ID[b.id];
        const w = (b.weight / total) * 100;
        if (w <= 0) return null;
        return (
          <div
            key={b.id}
            className="h-full transition-all duration-300"
            style={{ width: `${w}%`, background: t.color, boxShadow: `inset 0 0 0 0.5px rgba(0,0,0,0.25)` }}
            title={`${t.symbol} ${b.weight}%`}
          />
        );
      })}
    </div>
  );
}

// Per-family allocation summary chips
function FamilyBreakdown({ basket }) {
  const total = basket.reduce((s, b) => s + b.weight, 0);
  const byFam = {};
  basket.forEach((b) => {
    const t = window.TOKEN_BY_ID[b.id];
    byFam[t.family] = (byFam[t.family] || 0) + b.weight;
  });
  const fams = window.FAMILIES.filter((f) => byFam[f] > 0);
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1.5">
      {fams.map((f) => (
        <div key={f} className="flex items-center gap-1.5 text-[12px]">
          <span className="text-mute">{f}</span>
          <span className="font-mono text-ink tabular-nums">
            {total ? Math.round((byFam[f] / total) * 100) : 0}%
          </span>
        </div>
      ))}
    </div>
  );
}

Object.assign(window, { Monogram, StatusPill, WeightSlider, Lifecycle, AllocationBar, FamilyBreakdown });
