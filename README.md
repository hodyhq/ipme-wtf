# ipme.wtf

> your fucking IP address, all of it.

A single **Cloudflare Worker** that tells you your public IP — and everything else the
internet can see about your connection — in a clean terminal-style page. `curl`-friendly,
JSON-capable, with a WebRTC leak check. Built by [hody](https://hody.dev). MIT licensed.

```
$ curl ipme.wtf
73.92.146.20
```

## Why this needs a server (and can't be GitHub/GitLab Pages)

Your **browser cannot see your public IP**. Your device only knows its private LAN address
(`192.168.x.x`); the public IP is assigned by your ISP via NAT and is only observable by a
**server you connect to**, as the source address of the TCP connection. Cloudflare exposes
it to the Worker as the `CF-Connecting-IP` header.

Static hosts (GitHub/GitLab Pages) run no server code you control, so they can't read or
echo your IP. That's why this is a Worker. Git just stores the source.

## What it shows

- **IP:** IPv4 **and** IPv6 (dual-stack), address family
- **Location:** city, region, country (+flag), continent, postal, lat/long, timezone
- **Network:** ASN, ISP/org, reverse DNS (PTR)
- **Connection:** HTTP protocol, TLS version + cipher, Cloudflare edge datacenter
- **Device** (client-side): browser, OS, screen/viewport, languages, timezone, DNT, cookies
- **Privacy:** WebRTC leaked-IP candidates + a "is your VPN leaking?" verdict
- **Request headers** echo (collapsible)

## Endpoints

| Route | What |
|---|---|
| `/` | HTML page (browsers) / plain-text IP (`curl`, wget, httpie) |
| `/json` | full JSON dump |
| `/ip` | bare IP, plain text |
| `/ip.json` | `{ip, family}` — used by the `v4.`/`v6.` subdomains |

## Develop

```bash
npm install
npm run dev        # wrangler dev — local preview at http://localhost:8787
```
Note: `request.cf` geo fields are only fully populated on Cloudflare's edge, so some
location values show `—` in local dev. Deploy to see them live.

## Deploy

```bash
export CLOUDFLARE_API_TOKEN=...      # token with Workers Scripts:Edit + the zone
export CLOUDFLARE_ACCOUNT_ID=...
npm run deploy                       # → https://ipme-wtf.<subdomain>.workers.dev
```

### Custom domain (ipme.wtf)

1. Add the **ipme.wtf** zone to Cloudflare (point the registrar's nameservers at CF).
2. Create DNS records:
   - `ipme.wtf` → A **and** AAAA (proxied)
   - `v4.ipme.wtf` → **A only** (proxied) — forces IPv4 for the dual-stack lookup
   - `v6.ipme.wtf` → **AAAA only** (proxied) — forces IPv6
3. Uncomment the `routes` block in `wrangler.toml` and `npm run deploy`.

## Tuning

The WebRTC **leak verdict** in `public/app.js` (`webrtcLeak → render`) is a judgement call:
it flags a leak when a *public* candidate IP differs from the server-seen IP. Adjust the
thresholds/wording there if you want it stricter or friendlier.

## Cost

Cloudflare Workers free tier: 100k requests/day. Effective cost **$0/month** — the only
recurring expense is the `ipme.wtf` domain renewal (~$30–35/yr).
