/* ipme.wtf — client-side enhancements.
   Everything here is stuff the SERVER can't know (device facts, the other IP stack,
   WebRTC leaks) plus the copy-to-clipboard sugar. */

const $ = (s, r = document) => r.querySelector(s);
const kv = (k, v) => `<div class="kv"><span>${k}</span><span>${v == null || v === "" ? "—" : esc(v)}</span></div>`;
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const famOf = (ip) => (ip.includes(":") ? 6 : 4);

/* ── copy to clipboard ───────────────────────────────────────────── */
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.hidden = false;
  t.classList.add("show");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => {
    t.classList.remove("show");
    setTimeout(() => (t.hidden = true), 250);
  }, 1300);
}
async function copy(value) {
  try {
    await navigator.clipboard.writeText(value);
    toast("copied: " + value.slice(0, 42));
  } catch {
    toast("copy failed — select & ⌘C");
  }
}
// Any element with [data-copy] (bubbles, chips) copies on click.
document.addEventListener("click", (e) => {
  const el = e.target.closest("[data-copy]");
  if (el && el.getAttribute("data-copy")) copy(el.getAttribute("data-copy"));
});

/* ── dual-stack: show BOTH the v4 and v6 address ─────────────────────
   A single page load only reveals one stack. We ask the per-stack
   subdomains, each pinned to one address family by its DNS records. */
async function fetchStack(host) {
  try {
    const r = await fetch(`https://${host}/ip.json`, { cache: "no-store" });
    if (!r.ok) return null;
    return (await r.json()).ip || null;
  } catch {
    return null;
  }
}
// Fill the second-IP row (the family you did NOT arrive on). Won't overwrite a row
// that's already shown.
function showSecondaryIP(ip, note) {
  const wrap = $("#ip-secondary-wrap");
  if (!wrap.hidden) return;
  wrap.querySelector("[data-fam]").textContent = `IPv${famOf(ip)}`;
  $("#ip-secondary").textContent = note ? `${ip}  · ${note}` : ip;
  wrap.setAttribute("data-copy", ip);
  wrap.hidden = false;
}
async function dualStack() {
  const primary = $("#ip-primary").textContent.trim();
  const primaryFam = famOf(primary);
  // Label the primary bubble's family.
  $("#ip-primary").insertAdjacentHTML("beforebegin", `<span class="lbl-inline">IPv${primaryFam}</span>`);
  const otherFam = primaryFam === 4 ? 6 : 4;
  $("#ip-secondary-wrap").querySelector("[data-fam]").textContent = `IPv${otherFam}`;
  // Try the per-stack subdomain — but behind Cloudflare's proxy it can answer either
  // family, so only trust a result that's genuinely the other one. (WebRTC also fills
  // this row when it discovers your other-stack IP — see webrtcLeak.)
  const other = await fetchStack(primaryFam === 4 ? "v6.ipme.wtf" : "v4.ipme.wtf");
  if (other && famOf(other) === otherFam) showSecondaryIP(other);
}

/* ── device facts (only the browser knows these) ─────────────────────── */
function deviceInfo() {
  const ua = navigator.userAgent;
  const browser = detectBrowser(ua);
  const os = detectOS(ua);
  const dpr = window.devicePixelRatio || 1;
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const langs = (navigator.languages || [navigator.language]).join(", ");
  const dnt = navigator.doNotTrack === "1" || window.doNotTrack === "1" ? "enabled" : "off";
  $("#device").innerHTML =
    kv("browser / OS", `${browser} · ${os}`) +
    kv("screen", `${screen.width}×${screen.height} @ ${dpr}× · ${screen.colorDepth}-bit`) +
    kv("viewport", `${innerWidth}×${innerHeight}`) +
    kv("languages", langs) +
    kv("browser timezone", tz) +
    kv("local time", new Date().toLocaleString()) +
    kv("do not track", dnt) +
    kv("cookies", navigator.cookieEnabled ? "enabled" : "blocked");
}
function detectBrowser(ua) {
  if (/Edg\//.test(ua)) return "Edge " + (ua.match(/Edg\/(\d+)/) || [])[1];
  if (/OPR\//.test(ua)) return "Opera " + (ua.match(/OPR\/(\d+)/) || [])[1];
  if (/Firefox\//.test(ua)) return "Firefox " + (ua.match(/Firefox\/(\d+)/) || [])[1];
  if (/Chrome\//.test(ua)) return "Chrome " + (ua.match(/Chrome\/(\d+)/) || [])[1];
  if (/Safari\//.test(ua) && /Version\//.test(ua)) return "Safari " + (ua.match(/Version\/(\d+)/) || [])[1];
  return "unknown";
}
function detectOS(ua) {
  if (/Windows NT 10/.test(ua)) return "Windows 10/11";
  if (/Windows/.test(ua)) return "Windows";
  if (/Android/.test(ua)) return "Android " + (ua.match(/Android (\d+)/) || [])[1];
  if (/iPhone|iPad|iPod/.test(ua)) return "iOS";
  if (/Mac OS X/.test(ua)) return "macOS";
  if (/CrOS/.test(ua)) return "ChromeOS";
  if (/Linux/.test(ua)) return "Linux";
  return "unknown";
}

/* ── WebRTC leak check ───────────────────────────────────────────────
   Browsers can leak local + public IPs over WebRTC even behind a VPN.
   We gather ICE candidates, classify them, and judge a leak only when a
   SAME-family public IP differs from the server-seen IP. A different family
   is just your other stack — we surface it as your second IP instead. */
function classifyCandidate(addr) {
  if (/\.local$/i.test(addr)) return "mdns"; // hostname-obfuscated (modern, safe)
  if (addr.includes(":")) {
    // IPv6: link-local (fe80::/10) + ULA (fc00::/7) + loopback are private; rest is global
    if (/^fe[89ab]/i.test(addr) || /^f[cd]/i.test(addr) || addr === "::1") return "private";
    return "public";
  }
  if (/^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(addr)) return "private";
  return "public";
}
function webrtcLeak(serverIP) {
  const box = $("#webrtc");
  if (!window.RTCPeerConnection) {
    box.innerHTML = kv("status", "WebRTC unavailable — nothing to leak ✅");
    return;
  }
  const found = new Set();
  const pc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.cloudflare.com:3478" }] });
  pc.createDataChannel("x");
  pc.onicecandidate = (e) => {
    if (!e.candidate) return finish();
    // ICE candidate line: "candidate:<foundation> <component> <transport> <priority> <ADDRESS> <port> typ ..."
    // The connection address is the 5th space-separated field — parse by position, not regex-scrape.
    const parts = e.candidate.candidate.split(" ");
    const addr = parts[4];
    if (addr && (/^\d+\.\d+\.\d+\.\d+$/.test(addr) || addr.includes(":") || /\.local$/i.test(addr))) found.add(addr);
  };
  pc.createOffer().then((o) => pc.setLocalDescription(o));
  let done = false;
  const finish = () => {
    if (done) return;
    done = true;
    pc.close();
    render();
  };
  setTimeout(finish, 1500);

  function render() {
    const cands = [...found];
    const klass = cands.map(classifyCandidate);
    const serverFam = famOf(serverIP);
    const publics = cands.filter((_, i) => klass[i] === "public");

    // Your OTHER-stack public IP (a different family than the server saw) is NOT a leak —
    // it's just your other address. Use it to fill the second-IP row if it's still empty
    // (this is how your IPv4 shows up when you arrived over IPv6, e.g. on mobile).
    const otherStack = publics.find((p) => famOf(p) !== serverFam);
    if (otherStack) showSecondaryIP(otherStack, "via WebRTC");

    // A REAL leak = a SAME-family public IP that differs from what the server sees
    // (your true IP escaping a VPN). A different *family* is normal dual-stack, not a leak.
    const sameFamilyLeak = publics.some((p) => famOf(p) === serverFam && p !== serverIP);
    // ── VERDICT ──
    let verdict, cls;
    if (sameFamilyLeak) {
      verdict = "⚠️ WebRTC exposes a different public IP on your own stack — if you're on a VPN, it's leaking";
      cls = "bad";
    } else if (publics.length) {
      verdict = "no leak ✅ — WebRTC only exposes your own address(es)";
      cls = "good";
    } else {
      verdict = "no public IP leaked ✅ (only local/mDNS candidates)";
      cls = "good";
    }
    box.innerHTML =
      `<div class="kv verdict ${cls}"><span>verdict</span><span>${esc(verdict)}</span></div>` +
      (cands.length ? cands.map((c, i) => kv("candidate", `${c}  ·  ${klass[i]}`)).join("") : kv("candidates", "none"));
  }
}

/* ── headers toggle ──────────────────────────────────────────────────── */
function wireHeaders() {
  const t = $("#hdr-toggle"), box = $("#headers");
  const flip = () => {
    box.hidden = !box.hidden;
    t.querySelector(".hint").textContent = (box.hidden ? "▸ show " : "▾ hide ") + box.children.length;
  };
  t.addEventListener("click", flip);
  t.addEventListener("keydown", (e) => (e.key === "Enter" || e.key === " ") && flip());
}

/* ── copy-all ─────────────────────────────────────────────────────────── */
function wireCopyAll() {
  $("#copy-all").addEventListener("click", async (e) => {
    e.stopPropagation();
    try {
      const r = await fetch("/json");
      copy(await r.text());
    } catch {
      toast("couldn't fetch /json");
    }
  });
}

/* ── boot ─────────────────────────────────────────────────────────────── */
const SERVER_IP = ($("#ip-primary")?.textContent || "").trim();
deviceInfo();
wireHeaders();
wireCopyAll();
dualStack();
webrtcLeak(SERVER_IP);
