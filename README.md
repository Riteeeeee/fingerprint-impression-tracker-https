# ntrx — cross-site identity without third-party cookies

A single drop-in script + a tiny server that returns a **stable, consistent ID for
one user/browser across different domains**, working on Safari (iPhone/Mac), the
Instagram in-app browser, and Firefox. No cookies are used at all.

```
<script type="text/javascript" src="//your-domain.com/id-generator.js"></script>
```

## Why fingerprinting (and not storage)

On Safari, third-party cookies are blocked **and** third-party storage is *partitioned*
by top-level site (ITP). The classic "shared iframe on identity.com" trick therefore
gives you **different** storage on `shop.com` vs `crow.com`, so nothing that relies on
shared browser storage can link two origins.

The only thing that crosses origins with the user is the **device itself**. So:

1. **First-party `localStorage`** is used purely as a per-origin *cache* — instant and
   stable on repeat visits to the *same* site.
2. On a cache miss, the script collects a device **fingerprint** and POSTs it to a
   central server, which does `get_or_create` keyed on **(fingerprint + client IP)**.
   That server call is what links the same device across *different* origins: WebKit on
   one device produces a consistent fingerprint, and the server sees the same client IP
   for every site the user visits.

WebKit-on-Apple is what makes this reliable: Safari, the Instagram in-app browser, and
any WKWebView on the same device share one engine and GPU, so the canvas / WebGL / audio
signals stay consistent across "browsers." No cookies means 3p-cookie blocking is moot.

## Matching logic (server)

- **Exact device hash** → same ID. `coreHash = sha256(canvas|audio|webglVendor|webglRenderer|screen|tz|platform|cores|touch)`. Matches even when the user changes networks (different IP).
- **Fuzzy + same IP** → same ID. Weighted field overlap (threshold 9/14) absorbs small
  drift, e.g. Safari vs the Instagram in-app browser, or a browser update.
- **Otherwise** → a fresh `ntrx_<64 hex>` ID (69 chars, well over the 48-char minimum).

A new fingerprint that matches an existing identity is *added* to that identity's hash
set, so future visits hit the fast exact-match path.

## Files

| file | purpose |
|------|---------|
| `id-generator.js` | drop-in client; exposes `iDx`, prints `ID: ntrx_...`, caches per origin |
| `server.js` | zero-dependency Node server: `POST /id`, `GET /id-generator.js`, `GET /health` |
| `data.json` | auto-created identity store (atomic writes; survives restarts → "infinite time") |

### `iDx` API (matches the supplied test case)

```js
iDx.config = { /* optional; supports { endpoint: "https://..." } */ };
iDx.onIdAquired = function (id) { /* called with the id; fires even if set late */ };
iDx.id; // the resolved id, or null
```

The client auto-acquires the ID; the page just reads `iDx.onIdAquired`. The callback uses
an immediate-fire setter, so it works whether it is assigned before or after the ID is
resolved (handles the cached-id race).

## Deploy on a t3.small (DIY, no DevOps)

HTTPS is **mandatory** — host sites are HTTPS, and Safari blocks mixed content. You need a
domain pointed at the box's static/Elastic IP.

```bash
# 1. Elastic IP -> instance; DNS A record: your-domain.com -> that IP
# 2. Node 18+
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash - && sudo apt-get install -y nodejs

# 3. App
sudo mkdir -p /opt/ntrx && sudo cp server.js id-generator.js /opt/ntrx/

# 4. systemd service
sudo tee /etc/systemd/system/ntrx.service >/dev/null <<'UNIT'
[Unit]
Description=ntrx identity server
After=network.target
[Service]
WorkingDirectory=/opt/ntrx
Environment=PORT=8080
ExecStart=/usr/bin/node /opt/ntrx/server.js
Restart=always
User=www-data
[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl enable --now ntrx

# 5. nginx + TLS (Let's Encrypt)
sudo apt-get install -y nginx certbot python3-certbot-nginx
```

nginx site (`/etc/nginx/sites-available/ntrx`, then symlink + `nginx -t` + reload):

```nginx
server {
    server_name your-domain.com;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-Forwarded-For $remote_addr;   # server reads client IP from this
        proxy_set_header Host $host;
    }
}
```

```bash
sudo certbot --nginx -d your-domain.com   # issues TLS + rewrites the server block to 443
```

Then put `<script src="//your-domain.com/id-generator.js"></script>` on each site.

### Verify
```bash
curl https://your-domain.com/health
# {"ok":true,"identities":N}
```
Open the test page on two different domains in the same browser → identical `ID:` in the
console / on the page.

## Honest limitations

- **Collisions:** two identical device models on the same network/IP can fingerprint
  alike. Inherent to any cookieless cross-site scheme; the per-user, per-browser
  consistency the test requires is met. Adding fingerprint.js (allowed) as an extra signal
  raises uniqueness.
- **Privacy:** this is cross-site identity resolution. In production, surface it in your
  privacy policy and gate on consent where required (GDPR/DPDP) — both good engineering and
  often legally necessary.
