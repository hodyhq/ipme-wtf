/**
 * ipme.wtf — your fucking IP address, all of it.
 *
 * A single Cloudflare Worker that:
 *   - renders the page server-side (works without JS),
 *   - answers `curl ipme.wtf` with plain text and `/json` with JSON,
 *   - does a reverse-DNS (PTR) lookup at request time,
 *   - and lets `public/` static assets (css/js/logo) ride along via env.ASSETS.
 *
 * The public IP is only ever visible to the *server* — it's the source address of
 * the TCP connection, exposed here as the `CF-Connecting-IP` header. Your browser
 * cannot see it on its own, which is the whole reason this needs a Worker and not a
 * static page. See README.md.
 */

const CURL_UA = /\b(curl|wget|httpie|libwww|python-requests|got|node-fetch|powershell)\b/i;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Per-stack minimal endpoint — fetched by the v4./v6. subdomains from app.js.
    if (path === "/ip.json") return cors(json({ ip: clientIP(request), family: family(clientIP(request)) }));

    // Bare IP, always plain text.
    if (path === "/ip") return text(clientIP(request) + "\n");

    // Full structured dump (browser or CLI).
    if (path === "/json") return json(await gather(request));

    // Root: content-negotiate between the HTML page and plain text for CLI tools.
    if (path === "/") {
      if (wantsPlainText(request)) return text(clientIP(request) + "\n");
      return html(await renderPage(request, env));
    }

    // Anything else: let static assets try (styles.css, app.js, /assets/*, favicon).
    if (env.ASSETS) {
      const res = await env.ASSETS.fetch(request);
      if (res.status !== 404) return res;
    }
    return text("not found\n", 404);
  },
};

/* ──────────────────────── connection facts ──────────────────────── */

function clientIP(request) {
  return request.headers.get("CF-Connecting-IP") || request.headers.get("x-real-ip") || "";
}

function family(ip) {
  return ip.includes(":") ? 6 : 4;
}

function flagEmoji(cc) {
  if (!cc || cc.length !== 2) return "";
  const base = 0x1f1e6;
  return String.fromCodePoint(base + cc.charCodeAt(0) - 65, base + cc.charCodeAt(1) - 65);
}

// Collect inbound request headers, minus noise we don't want to echo.
function collectHeaders(request) {
  const skip = new Set(["cf-connecting-ip", "cf-ray", "cf-visitor", "cf-ipcountry", "x-real-ip", "x-forwarded-for", "cf-worker"]);
  const out = {};
  for (const [k, v] of request.headers) if (!skip.has(k.toLowerCase())) out[k] = v;
  return out;
}

async function gather(request) {
  const cf = request.cf || {};
  const ip = clientIP(request);
  const ptr = await ptrLookup(ip);
  return {
    ip,
    family: family(ip),
    reverseDns: ptr,
    location: {
      city: cf.city ?? null,
      region: cf.region ?? null,
      regionCode: cf.regionCode ?? null,
      country: cf.country ?? null,
      countryFlag: flagEmoji(cf.country),
      continent: cf.continent ?? null,
      postalCode: cf.postalCode ?? null,
      latitude: cf.latitude ?? null,
      longitude: cf.longitude ?? null,
      timezone: cf.timezone ?? null,
    },
    network: {
      asn: cf.asn ?? null,
      organization: cf.asOrganization ?? null,
    },
    connection: {
      httpProtocol: cf.httpProtocol ?? null,
      tlsVersion: cf.tlsVersion ?? null,
      tlsCipher: cf.tlsCipher ?? null,
      colo: cf.colo ?? null,
    },
    headers: collectHeaders(request),
  };
}

/* ──────────────────────── reverse DNS (PTR) ──────────────────────── */

// PTR is not part of request.cf, so we ask a DNS-over-HTTPS resolver at request time.
async function ptrLookup(ip) {
  const name = reverseName(ip);
  if (!name) return null;
  try {
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=PTR`, {
      headers: { accept: "application/dns-json" },
      cf: { cacheTtl: 300, cacheEverything: true },
    });
    const j = await r.json();
    const answers = (j.Answer || []).filter((a) => a.type === 12); // 12 = PTR
    return answers.length ? answers[answers.length - 1].data.replace(/\.$/, "") : null;
  } catch {
    return null;
  }
}

function reverseName(ip) {
  if (!ip) return null;
  if (ip.includes(":")) {
    const full = expandIPv6(ip);
    if (!full) return null;
    return full.replace(/:/g, "").split("").reverse().join(".") + ".ip6.arpa";
  }
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  return parts.reverse().join(".") + ".in-addr.arpa";
}

// Expand a compressed IPv6 address to 32 hex nibbles for the .ip6.arpa name.
function expandIPv6(ip) {
  if (!ip.includes(":")) return null;
  let [head, tail] = ip.split("::");
  const headGroups = head ? head.split(":") : [];
  const tailGroups = tail !== undefined ? (tail ? tail.split(":") : []) : null;
  let groups;
  if (tailGroups === null) {
    groups = headGroups; // no "::"
  } else {
    const fill = 8 - headGroups.length - tailGroups.length;
    groups = [...headGroups, ...Array(fill).fill("0"), ...tailGroups];
  }
  if (groups.length !== 8) return null;
  return groups.map((g) => g.padStart(4, "0")).join("");
}

/* ──────────────────────── content negotiation ──────────────────────── */

function wantsPlainText(request) {
  const ua = request.headers.get("user-agent") || "";
  if (CURL_UA.test(ua)) return true;
  const accept = request.headers.get("accept") || "";
  // A browser sends Accept: text/html,…; CLI tools usually send */* or nothing.
  return accept !== "" && !accept.includes("text/html") && !accept.includes("application/xhtml");
}

/* ──────────────────────── responses ──────────────────────── */

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

function text(body, status = 200) {
  return new Response(body, { status, headers: { "content-type": "text/plain; charset=utf-8", ...SECURITY_HEADERS } });
}
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), { status, headers: { "content-type": "application/json; charset=utf-8", ...SECURITY_HEADERS } });
}
function html(body, status = 200) {
  return new Response(body, { status, headers: { "content-type": "text/html; charset=utf-8", ...SECURITY_HEADERS } });
}
function cors(res) {
  res.headers.set("access-control-allow-origin", "*");
  return res;
}

/* ──────────────────────── HTML render ──────────────────────── */

const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

// One labelled key/value row.
const row = (k, v, extra = "") => `<div class="kv"${extra}><span>${esc(k)}</span><span>${v === null || v === undefined || v === "" ? "—" : esc(v)}</span></div>`;

async function renderPage(request, env) {
  const d = await gather(request);
  const L = d.location;
  const coords = L.latitude && L.longitude ? `${L.latitude}, ${L.longitude}` : "—";
  const cityLine = [L.city, L.region].filter(Boolean).join(", ") || "—";
  const headerCount = Object.keys(d.headers).length;
  const headerRows = Object.entries(d.headers)
    .map(([k, v]) => `<div class="kv hdr"><span>${esc(k)}</span><span>${esc(v)}</span></div>`)
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ipme.wtf — your fucking IP address</title>
<meta name="description" content="Your fucking IP address, and everything else the internet can see about your connection. By hody.">
<meta name="theme-color" content="#05050a">
<link rel="icon" href="/favicon.png">
<meta property="og:title" content="ipme.wtf">
<meta property="og:description" content="Your fucking IP address — and everything else.">
<meta property="og:image" content="/og-icon.png">
<link rel="stylesheet" href="/styles.css">
</head>
<body>
<main class="page">
  <header class="top">
    <span class="brand"><span class="br">&lt;</span><span class="h">H</span><span class="br">&gt;</span> ipme.wtf</span>
    <span class="tag">● your fucking IP, all of it</span>
  </header>

  <p class="lead">your fucking IP address is</p>

  <div class="bubble" data-copy="${esc(d.ip)}" title="click to copy">
    <span class="v" id="ip-primary">${esc(d.ip)}</span>
    <button class="cp" aria-label="copy">⧉ copy</button>
  </div>
  <div class="bubble sm" id="ip-secondary-wrap" data-copy="" title="click to copy" hidden>
    <span class="lbl-inline" data-fam></span>
    <span class="v2" id="ip-secondary">looking…</span>
    <button class="cp" aria-label="copy">⧉</button>
  </div>

  <h2 class="lbl">📍 location</h2>
  ${row("city / region", cityLine)}
  ${row("country", L.country ? `${L.country} ${L.countryFlag}` : null)}
  ${row("continent", L.continent)}
  ${row("postal", L.postalCode)}
  ${row("timezone", L.timezone)}
  ${row("coordinates", coords)}

  <h2 class="lbl">🌐 network</h2>
  ${row("ISP / org", d.network.organization)}
  ${row("ASN", d.network.asn ? "AS" + d.network.asn : null)}
  ${row("reverse DNS", d.reverseDns)}

  <h2 class="lbl">🔌 connection</h2>
  ${row("protocol", d.connection.httpProtocol)}
  ${row("TLS", [d.connection.tlsVersion, d.connection.tlsCipher].filter(Boolean).join(" · ") || null)}
  ${row("edge datacenter", d.connection.colo)}

  <h2 class="lbl">🖥 your device <span class="hint">(seen by your browser, not the server)</span></h2>
  <div id="device">${row("status", "enable JavaScript to see device info")}</div>

  <h2 class="lbl">🛰 privacy <span class="hint">(WebRTC leak check)</span></h2>
  <div id="webrtc">${row("status", "checking…")}</div>

  <h2 class="lbl tog" id="hdr-toggle" role="button" tabindex="0">📨 request headers <span class="hint">▸ show ${headerCount}</span></h2>
  <div id="headers" hidden>${headerRows}</div>

  <footer class="ftr">
    <span class="chips">
      <code class="chip" data-copy="curl ipme.wtf">curl ipme.wtf</code>
      <a class="chip" href="/json">/json</a>
      <button class="chip" id="copy-all">copy all as JSON</button>
    </span>
    <a class="made" href="https://hody.dev" target="_blank" rel="noopener">
      <img src="/hody-logo.png" alt="hody" height="20">
    </a>
  </footer>
</main>
<div id="toast" class="toast" hidden></div>
<script src="/app.js" defer></script>
</body>
</html>`;
}
