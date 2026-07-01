// ── Shared motion utilities: CountUp + Reveal (used by app + landing) ─
(function () {
  const { useState, useEffect, useRef } = React;
  const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Animated number that eases toward `value`. Optional custom `format(v)`.
  function CountUp({ value, decimals = 0, prefix = "", suffix = "", format, duration = 1000, startOnView = false, className, style }) {
    const [disp, setDisp] = useState(reduce ? value : 0);
    const [armed, setArmed] = useState(!startOnView || reduce);
    const ref = useRef(null);
    const fromRef = useRef(0);
    const rafRef = useRef(0);
    useEffect(() => {
      if (!startOnView || reduce) return;
      const el = ref.current;
      if (!el) return;
      const io = new IntersectionObserver(
        (ents) => ents.forEach((e) => { if (e.isIntersecting) { setArmed(true); io.disconnect(); } }),
        { threshold: 0.35 }
      );
      io.observe(el);
      const safety = setTimeout(() => setArmed(true), 2800); // never stay at 0
      return () => { io.disconnect(); clearTimeout(safety); };
    }, [startOnView]);
    useEffect(() => {
      if (reduce) { setDisp(value); fromRef.current = value; return; }
      if (!armed) return;
      const from = fromRef.current;
      const to = value;
      const t0 = performance.now();
      const tick = (now) => {
        const p = Math.min(1, (now - t0) / duration);
        const e = 1 - Math.pow(1 - p, 3);
        setDisp(from + (to - from) * e);
        if (p < 1) rafRef.current = requestAnimationFrame(tick);
        else fromRef.current = to;
      };
      cancelAnimationFrame(rafRef.current);
      rafRef.current = requestAnimationFrame(tick);
      return () => cancelAnimationFrame(rafRef.current);
    }, [value, duration, armed]);
    const txt = format
      ? format(disp)
      : prefix + disp.toLocaleString("en-US", { minimumFractionDigits: decimals, maximumFractionDigits: decimals }) + suffix;
    return <span ref={ref} className={className} style={style}>{txt}</span>;
  }

  // Fade-up wrapper that triggers when scrolled into view.
  function Reveal({ children, delay = 0, className = "", style, as = "div" }) {
    const ref = useRef(null);
    const [vis, setVis] = useState(reduce);
    useEffect(() => {
      if (reduce) return;
      const el = ref.current;
      if (!el) return;
      const io = new IntersectionObserver(
        (ents) => ents.forEach((e) => { if (e.isIntersecting) { setVis(true); io.disconnect(); } }),
        { threshold: 0.12, rootMargin: "0px 0px -8% 0px" }
      );
      io.observe(el);
      const safety = setTimeout(() => setVis(true), 2500); // never stay hidden
      return () => { io.disconnect(); clearTimeout(safety); };
    }, []);
    const Tag = as;
    return (
      <Tag ref={ref} className={`xi-reveal ${vis ? "in" : ""} ${className}`} style={{ ...style, transitionDelay: `${delay}ms` }}>
        {children}
      </Tag>
    );
  }

  // ── Global scroll engine: parallax layers + progress, one rAF ──────
  // Any element with data-px="<speed>" gets translateY(scrollY*speed).
  // Optional data-px-fade="<startPx>" fades/shrinks it out as it leaves.
  // Elements with [data-scroll-progress] get scaleX bound to page progress.
  function initScrollEngine() {
    if (window.__xiScrollEngine || reduce) return;
    window.__xiScrollEngine = true;
    let ticking = false;
    const apply = () => {
      ticking = false;
      const y = window.scrollY || window.pageYOffset;
      const docH = document.documentElement.scrollHeight - window.innerHeight;
      const prog = docH > 0 ? Math.min(1, Math.max(0, y / docH)) : 0;

      document.querySelectorAll("[data-px]").forEach((el) => {
        const sp = parseFloat(el.getAttribute("data-px")) || 0;
        const fade = el.getAttribute("data-px-fade");
        let tr = `translate3d(0, ${(y * sp).toFixed(2)}px, 0)`;
        if (fade != null) {
          const start = parseFloat(fade) || 0;
          const span = parseFloat(el.getAttribute("data-px-span")) || 520;
          const k = Math.min(1, Math.max(0, (y - start) / span));
          el.style.opacity = (1 - k * 0.9).toFixed(3);
          tr += ` scale(${(1 - k * 0.05).toFixed(4)})`;
        }
        el.style.transform = tr;
      });

      document.querySelectorAll("[data-scroll-progress]").forEach((el) => {
        el.style.transform = `scaleX(${prog.toFixed(4)})`;
      });
    };
    const onScroll = () => { if (!ticking) { ticking = true; requestAnimationFrame(apply); } };
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll, { passive: true });
    apply();
  }

  function ScrollProgress() {
    useEffect(() => { initScrollEngine(); initSmoothScroll(); }, []);
    return (
      <div className="fixed top-0 left-0 right-0 z-50 pointer-events-none" style={{ height: 2.5 }}>
        <div data-scroll-progress className="h-full origin-left" style={{ width: "100%", transform: "scaleX(0)", background: "linear-gradient(90deg, var(--brand-200), var(--brand) 55%, var(--cyan))", boxShadow: "0 0 12px color-mix(in srgb, var(--brand) 60%, transparent)" }} />
      </div>
    );
  }

  // ── Smooth inertia scroll (Lenis-style lerp) ───────────────────────
  function initSmoothScroll() {
    if (window.__xiSmooth || reduce) return;
    if (window.matchMedia && window.matchMedia("(pointer: coarse)").matches) return; // touch = native momentum
    window.__xiSmooth = true;
    document.documentElement.style.scrollBehavior = "auto"; // our lerp drives it; avoid double-smoothing
    const ease = 0.11;
    let target = window.scrollY, current = target, running = false, raf = 0;
    const maxY = () => Math.max(0, document.documentElement.scrollHeight - window.innerHeight);
    const clamp = (v) => Math.max(0, Math.min(maxY(), v));
    const loop = () => {
      current += (target - current) * ease;
      if (Math.abs(target - current) < 0.4) { current = target; window.scrollTo(0, current); running = false; return; }
      window.scrollTo(0, current);
      raf = requestAnimationFrame(loop);
    };
    const start = () => { if (!running) { running = true; current = window.scrollY; raf = requestAnimationFrame(loop); } };
    const onWheel = (e) => {
      if (e.ctrlKey) return; // pinch-zoom
      // let inner scrollable areas (e.g. tweaks panel) scroll themselves
      let el = e.target;
      while (el && el !== document.body && el !== document.documentElement) {
        if (el.scrollHeight > el.clientHeight) {
          const oy = getComputedStyle(el).overflowY;
          if (oy === "auto" || oy === "scroll") return;
        }
        el = el.parentElement;
      }
      const unit = e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? window.innerHeight : 1;
      const next = clamp(target + e.deltaY * unit);
      if (next === target) return; // at an edge — let it be
      e.preventDefault();
      target = next;
      start();
    };
    // keep target synced for keyboard / scrollbar / anchor jumps
    const onScroll = () => { if (!running) { target = window.scrollY; current = window.scrollY; } };
    // route in-page anchor clicks through the lerp
    const onClick = (e) => {
      const a = e.target.closest && e.target.closest('a[href^="#"]');
      if (!a) return;
      const id = a.getAttribute("href");
      if (!id || id === "#") return;
      const dest = id === "#top" ? document.body : document.querySelector(id);
      if (!dest) return;
      e.preventDefault();
      const rect = dest.getBoundingClientRect();
      target = clamp(window.scrollY + rect.top - 68);
      start();
    };
    window.addEventListener("wheel", onWheel, { passive: false });
    window.addEventListener("scroll", onScroll, { passive: true });
    document.addEventListener("click", onClick);
    window.addEventListener("resize", () => { target = clamp(target); }, { passive: true });
  }

  window.CountUp = CountUp;
  window.Reveal = Reveal;
  window.ScrollProgress = ScrollProgress;
  window.initScrollEngine = initScrollEngine;
  window.initSmoothScroll = initSmoothScroll;
})();
