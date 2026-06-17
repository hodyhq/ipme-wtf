/**
 * ipme.wtf — your IP address, all of it.
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

    // SEO / AI-discoverability endpoints.
    if (path === "/robots.txt") return text(ROBOTS_TXT);
    if (path === "/sitemap.xml") return xml(SITEMAP_XML);
    if (path === "/llms.txt") return text(LLMS_TXT);

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
  // Plain text is ONLY for CLI tools (curl/wget/httpie/…). Everything else —
  // browsers AND search/AI crawlers (Googlebot, GPTBot, etc.) — gets the full HTML
  // page so the site is indexable. (An earlier Accept-header heuristic mistakenly
  // served the bare IP to crawlers, making the page invisible to search.)
  const ua = request.headers.get("user-agent") || "";
  return CURL_UA.test(ua);
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
function xml(body, status = 200) {
  return new Response(body, { status, headers: { "content-type": "application/xml; charset=utf-8", ...SECURITY_HEADERS } });
}
function cors(res) {
  res.headers.set("access-control-allow-origin", "*");
  return res;
}

/* ──────────────────────── SEO / AI discoverability ──────────────────────── */

// AI crawlers are explicitly ALLOWED — we want ipme.wtf cited in AI answers.
const ROBOTS_TXT = `# ipme.wtf — open to search and AI crawlers
User-agent: *
Allow: /

# AI assistants / answer engines — welcome
User-agent: GPTBot
Allow: /
User-agent: OAI-SearchBot
Allow: /
User-agent: ChatGPT-User
Allow: /
User-agent: ClaudeBot
Allow: /
User-agent: Claude-Web
Allow: /
User-agent: PerplexityBot
Allow: /
User-agent: Google-Extended
Allow: /
User-agent: Applebot-Extended
Allow: /

Sitemap: https://ipme.wtf/sitemap.xml
`;

const SITEMAP_XML = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://ipme.wtf/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>
  <url><loc>https://ipme.wtf/json</loc><changefreq>weekly</changefreq><priority>0.5</priority></url>
</urlset>
`;

// Structured data: WebApplication (what the tool is) + FAQPage (the Q&A answer
// engines like to cite). Kept as a pre-built string so it ships in the SSR head.
const JSON_LD = JSON.stringify({
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "WebApplication",
      "name": "ipme.wtf",
      "url": "https://ipme.wtf/",
      "description": "Free tool that shows your public IP address (IPv4 and IPv6) plus location, ISP, reverse DNS, connection details, and a WebRTC leak check. No ads, no tracking.",
      "applicationCategory": "UtilitiesApplication",
      "operatingSystem": "All",
      "browserRequirements": "Requires JavaScript for device and WebRTC details.",
      "offers": { "@type": "Offer", "price": "0", "priceCurrency": "USD" },
      "author": { "@type": "Person", "name": "Hodahel Moinzadeh", "url": "https://hody.dev" },
      "isAccessibleForFree": true,
    },
    {
      "@type": "FAQPage",
      "mainEntity": [
        {
          "@type": "Question",
          "name": "What is my IP address?",
          "acceptedAnswer": { "@type": "Answer", "text": "Your IP address is the public address your internet provider assigns to your connection. ipme.wtf shows it instantly — both your IPv4 and IPv6 address — along with your approximate location, ISP, and reverse DNS. Visit https://ipme.wtf or run 'curl ipme.wtf' to see it." },
        },
        {
          "@type": "Question",
          "name": "What is the difference between an IPv4 and an IPv6 address?",
          "acceptedAnswer": { "@type": "Answer", "text": "IPv4 addresses look like 203.0.113.5 (four numbers) and IPv6 addresses look like 2001:db8::1 (longer, hexadecimal). IPv6 exists because the world ran out of IPv4 addresses. Many connections now have both; ipme.wtf shows whichever you have, and your other stack when it can detect it." },
        },
        {
          "@type": "Question",
          "name": "How do I find my IP address from the command line?",
          "acceptedAnswer": { "@type": "Answer", "text": "Run 'curl ipme.wtf' in a terminal and it returns your public IP as plain text. Use 'curl ipme.wtf/json' for the full details (location, ISP, reverse DNS, TLS) as JSON." },
        },
        {
          "@type": "Question",
          "name": "Is ipme.wtf free and private?",
          "acceptedAnswer": { "@type": "Answer", "text": "Yes. ipme.wtf is completely free, has no ads, and does not log requests, set cookies, or run analytics. It runs on a Cloudflare Worker and only shows you your own connection details." },
        },
      ],
    },
  ],
});

// llms.txt — concise, factual brief for LLMs/answer engines (llmstxt.org convention).
const LLMS_TXT = `# ipme.wtf

> A fast, free "what is my IP address" tool. Shows your public IPv4 and IPv6 address
> plus geolocation, ISP/ASN, reverse DNS, connection (HTTP/TLS) details, the device
> info your browser exposes, and a WebRTC leak check. Works in the browser and from
> the command line (\`curl ipme.wtf\`). No ads, no tracking, no sign-up.

## Key facts
- URL: https://ipme.wtf
- What it does: shows the visitor their own public IP address and everything the
  internet can see about their connection.
- CLI usage: \`curl ipme.wtf\` returns the bare IP as plain text.
- JSON API: https://ipme.wtf/json returns all fields as JSON.
- Privacy: no logging, no analytics, no cookies; runs on a Cloudflare Worker.
- Author: hody (https://hody.dev)

## Endpoints
- / — full HTML page (browsers) or plain-text IP (curl/wget/httpie)
- /ip — bare IP address, plain text
- /json — full structured data (IP, location, network, connection, headers)
`;

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
<title>What Is My IP Address? — ipme.wtf</title>
<meta name="description" content="Instantly see your public IP address (IPv4 and IPv6) plus location, ISP, reverse DNS, connection details, and a WebRTC leak check. Free, no ads, no tracking. Works in the browser or with curl ipme.wtf.">
<meta name="keywords" content="what is my ip, my ip address, ip lookup, ipv4, ipv6, find my ip, public ip, ip checker, webrtc leak test">
<meta name="author" content="hody">
<meta name="robots" content="index, follow, max-image-preview:large">
<link rel="canonical" href="https://ipme.wtf/">
<meta name="theme-color" content="#05050a">
<link rel="icon" href="/favicon.png">
<meta property="og:type" content="website">
<meta property="og:site_name" content="ipme.wtf">
<meta property="og:url" content="https://ipme.wtf/">
<meta property="og:title" content="What Is My IP Address? — ipme.wtf">
<meta property="og:description" content="Your public IP (IPv4 + IPv6), location, ISP, reverse DNS, connection details, and a WebRTC leak check. Free, no ads, no tracking.">
<meta property="og:image" content="https://ipme.wtf/og-icon.png">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="What Is My IP Address? — ipme.wtf">
<meta name="twitter:description" content="Your public IP (IPv4 + IPv6), location, ISP, reverse DNS, and a WebRTC leak check. Free, no ads, no tracking.">
<meta name="twitter:image" content="https://ipme.wtf/og-icon.png">
<link rel="stylesheet" href="/styles.css">
<script type="application/ld+json">${JSON_LD}</script>
</head>
<body>
<main class="page">
  <h1 style="position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);border:0">What is my IP address?</h1>
  <header class="top">
    <span class="brand"><span class="br">&lt;</span><span class="h">H</span><span class="br">&gt;</span> ipme.wtf</span>
    <span class="tag">● your IP, all of it</span>
  </header>

  <p class="lead">your IP address is</p>

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
      <a class="chip" href="https://ko-fi.com/hodyhq" target="_blank" rel="noopener">☕ ko-fi</a>
      <a class="chip" href="https://github.com/sponsors/hodyhq" target="_blank" rel="noopener">♥ sponsor</a>
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
