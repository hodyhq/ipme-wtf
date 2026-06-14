# ipme.wtf

> your fucking IP address, all of it.

A single **Cloudflare Worker** that shows your public IP — and everything else the internet
can see about your connection — in a clean terminal-style page. `curl`-friendly,
JSON-capable, with a WebRTC leak check.

**→ [ipme.wtf](https://ipme.wtf)**

```
$ curl ipme.wtf
73.92.146.20
```

## Why this needs a server (not a static page)

Your browser can't see your public IP — it only knows your private LAN address. The public
IP is the source address of your TCP connection, visible only to a server you connect to
(Cloudflare exposes it to the Worker as `CF-Connecting-IP`). Static hosts run no server code,
so they can't read it. Hence a Worker.

## What it shows

- **IP:** IPv4 + IPv6, address family
- **Location:** city, region, country, postal, lat/long, timezone
- **Network:** ASN, ISP/org, reverse DNS (PTR)
- **Connection:** HTTP protocol, TLS, Cloudflare edge datacenter
- **Device** (client-side): browser, OS, screen, languages, timezone, DNT, cookies
- **Privacy:** WebRTC leaked-IP check
- **Request headers** echo

## Endpoints

| Route | What |
|---|---|
| `/` | HTML page, or plain-text IP for `curl`/wget/httpie |
| `/json` | full JSON dump |
| `/ip` | bare IP, plain text |

## Run your own

```bash
npm install
npm run dev       # local preview at http://localhost:8787
npm run deploy    # deploy to your own Cloudflare account
```

MIT © hody · [hody.dev](https://hody.dev)
