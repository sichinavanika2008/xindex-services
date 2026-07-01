// ── Xindex data layer ───────────────────────────────────────────────
// 15-token omnichain universe, brand colors, formatters, NAV math.

const FAMILIES = ["UTXO", "EVM", "Cosmos", "XRP", "Solana", "TRON"];

const TOKENS = [
  // UTXO
  { id: "btc",  name: "Bitcoin",      symbol: "BTC",  chain: "Bitcoin",        family: "UTXO",   price: 100000, change: 2.41,  status: "live",        color: "#F7931A" },
  { id: "ltc",  name: "Litecoin",     symbol: "LTC",  chain: "Litecoin",       family: "UTXO",   price: 90,     change: -1.18, status: "integrating", color: "#5C6B8A" },
  { id: "bch",  name: "Bitcoin Cash", symbol: "BCH",  chain: "Bitcoin Cash",   family: "UTXO",   price: 450,    change: 0.82,  status: "integrating", color: "#0AC18E" },
  { id: "doge", name: "Dogecoin",     symbol: "DOGE", chain: "Dogecoin",       family: "UTXO",   price: 0.40,   change: 5.63,  status: "integrating", color: "#C2A633" },
  { id: "zec",  name: "Zcash",        symbol: "ZEC",  chain: "Zcash",          family: "UTXO",   price: 45,     change: -3.10, status: "integrating", color: "#ECB244" },
  // EVM
  { id: "eth",  name: "Ether",        symbol: "ETH",  chain: "Ethereum",       family: "EVM",    price: 3500,   change: 1.74,  status: "integrating", color: "#7B8AF0" },
  { id: "bnb",  name: "BNB",          symbol: "BNB",  chain: "BNB Smart Chain", family: "EVM",   price: 650,    change: 0.36,  status: "integrating", color: "#F3BA2F" },
  { id: "avax", name: "Avalanche",    symbol: "AVAX", chain: "Avalanche",      family: "EVM",    price: 40,     change: -2.27, status: "integrating", color: "#E84142" },
  { id: "ethb", name: "Ether",        symbol: "ETH",  chain: "Base",           family: "EVM",    price: 3500,   change: 1.74,  status: "integrating", color: "#3B7BFF" },
  { id: "pol",  name: "Polygon",      symbol: "POL",  chain: "Polygon",        family: "EVM",    price: 0.55,   change: 3.19,  status: "integrating", color: "#9A6BE8" },
  // Cosmos
  { id: "atom", name: "Cosmos Hub",   symbol: "ATOM", chain: "Cosmos Hub",     family: "Cosmos", price: 7,      change: -0.91, status: "integrating", color: "#6F7CA8" },
  { id: "usdc", name: "Noble USDC",   symbol: "USDC", chain: "Noble",          family: "Cosmos", price: 1.00,   change: 0.01,  status: "integrating", color: "#3E7BC4" },
  // XRP
  { id: "xrp",  name: "XRP",          symbol: "XRP",  chain: "XRP Ledger",     family: "XRP",    price: 2.20,   change: 4.12,  status: "integrating", color: "#62A9E6" },
  // Solana
  { id: "sol",  name: "Solana",       symbol: "SOL",  chain: "Solana",         family: "Solana", price: 150,    change: 6.24,  status: "integrating", color: "#A06BFF" },
  // TRON
  { id: "trx",  name: "TRON",         symbol: "TRX",  chain: "TRON",           family: "TRON",   price: 0.25,   change: -0.58, status: "integrating", color: "#EF4351" },
];

const TOKEN_BY_ID = Object.fromEntries(TOKENS.map((t) => [t.id, t]));

// ── Real coin logos (CDN) with per-id overrides; falls back to letter ──
const ICON_BASE = "https://cdn.jsdelivr.net/npm/cryptocurrency-icons@0.18.1/svg/color/";
const ICON_OVERRIDE = { pol: "matic", ethb: "eth" };
function iconUrl(token) {
  const key = ICON_OVERRIDE[token.id] || token.symbol.toLowerCase();
  return ICON_BASE + key + ".svg";
}

// ── Formatters ──────────────────────────────────────────────────────
const usd = (n, opts = {}) => {
  if (n === null || n === undefined || isNaN(n)) return "$0.00";
  const abs = Math.abs(n);
  let max = 2;
  if (abs > 0 && abs < 1) max = 4;
  if (abs >= 1000) max = 0;
  return "$" + n.toLocaleString("en-US", { minimumFractionDigits: 0, maximumFractionDigits: max, ...opts });
};

// price formatter keeps small prices legible
const price = (n) => {
  if (n >= 1000) return "$" + n.toLocaleString("en-US", { maximumFractionDigits: 0 });
  if (n >= 1) return "$" + n.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  return "$" + n.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 4 });
};

// native token amount: more decimals for high-value assets
const native = (n, p) => {
  if (n === 0) return "0";
  let dec = 4;
  if (p >= 10000) dec = 6;
  else if (p >= 100) dec = 4;
  else if (p >= 1) dec = 3;
  else dec = 2;
  const s = n.toLocaleString("en-US", { minimumFractionDigits: 0, maximumFractionDigits: dec });
  return s;
};

const fmtNum = (n, d = 2) =>
  n.toLocaleString("en-US", { minimumFractionDigits: d, maximumFractionDigits: d });

const round2 = (n) => Math.round(n * 100) / 100;

// ── Math: basket → holdings / NAV ───────────────────────────────────
// basket: [{ id, weight }]. deposit in USDT. Returns native legs.
function legsFor(basket, depositUSDT) {
  return basket.map((b) => {
    const t = TOKEN_BY_ID[b.id];
    const usdLeg = (depositUSDT * b.weight) / 100;
    return { id: b.id, usd: usdLeg, amount: usdLeg / t.price };
  });
}

// ── Per-chain destination address specs (demo-grade validators) ─────
const ADDR_SPEC = {
  UTXO:   { test: (a) => /^(bc1|[13mLMD]|t1|q|p)[0-9a-z]{20,60}$/i.test(a) },
  EVM:    { test: (a) => /^0x[0-9a-fA-F]{40}$/.test(a) },
  Cosmos: { test: (a) => /^[a-z]{3,8}1[0-9a-z]{30,50}$/.test(a) },
  XRP:    { test: (a) => /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(a) },
  Solana: { test: (a) => /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(a) },
  TRON:   { test: (a) => /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(a) },
};
const ADDR_PLACEHOLDER = {
  btc: "bc1q… (native segwit)", ltc: "ltc1… or L…", bch: "bitcoincash:q… or q…",
  doge: "D…", zec: "t1… (transparent)",
  eth: "0x… (Ethereum)", ethb: "0x… (Base)", bnb: "0x… (BNB Chain)", avax: "0x… (C-Chain)", pol: "0x… (Polygon)",
  atom: "cosmos1…", usdc: "noble1…", xrp: "r… (XRP Ledger)", sol: "Base58 address", trx: "T… (TRON)",
};
function addrPlaceholder(token) { return ADDR_PLACEHOLDER[token.id] || "destination address"; }
function validateAddress(token, addr) {
  const a = (addr || "").trim();
  if (!a) return { valid: false, empty: true };
  const spec = ADDR_SPEC[token.family];
  return { valid: spec ? spec.test(a) : a.length >= 12, empty: false };
}
function shortAddr(a) {
  if (!a) return "";
  return a.length > 16 ? `${a.slice(0, 8)}…${a.slice(-6)}` : a;
}

Object.assign(window, {
  FAMILIES, TOKENS, TOKEN_BY_ID,
  usd, price, native, fmtNum, round2, legsFor,
  iconUrl, ICON_BASE,
  addrPlaceholder, validateAddress, shortAddr,
});
