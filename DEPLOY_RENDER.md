# Deploy ntrx-id on Render

Render gives a **stable HTTPS URL** (e.g. `https://ntrx-id.onrender.com`) — no
cloudflared, no changing URLs. The server is zero-dependency Node, so deploy is trivial.

## 1. Push this folder to GitHub

```bash
cd ntrx-id
git init
git add .
git commit -m "ntrx-id: cross-site identity without cookies"
git branch -M main
git remote add origin https://github.com/<you>/ntrx-id.git
git push -u origin main
```

`data.json` and `node_modules/` are gitignored (runtime / not needed).

## 2. Create the service on Render

**Option A — Blueprint (uses `render.yaml`, recommended):**
1. Render dashboard → **New +** → **Blueprint**.
2. Connect your GitHub repo → Render reads `render.yaml` and sets everything up.
3. Click **Apply**. Done.

**Option B — manual Web Service:**
1. **New +** → **Web Service** → connect the repo.
2. Settings:
   - **Runtime:** Node
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
   - **Health Check Path:** `/health`
   - **Environment variable:** `UNIQUE_UNITS = 0`
3. **Create Web Service**.

## 3. Use it

Your URLs (replace with your real Render hostname):

| What | URL |
|------|-----|
| Drop-in script (the submission) | `https://ntrx-id.onrender.com/id-generator.js` |
| Demo UI | `https://ntrx-id.onrender.com/` |
| Official test page | `https://ntrx-id.onrender.com/testcase.html` |
| Health | `https://ntrx-id.onrender.com/health` |

Put the script on any site:

```html
<script type="text/javascript" src="https://ntrx-id.onrender.com/id-generator.js"></script>
```

`testcase.html` / `demo.html` load the script with a **relative** path, so they work on
the Render host automatically — no edits needed after deploy. CORS is open (`*`), so the
script also works when embedded on other domains.

## Notes / caveats

- **Free tier cold start:** a free instance spins down after ~15 min idle; the first
  request after that takes a few seconds to wake. Fine for a demo.
- **Persistence:** the free filesystem is **ephemeral** — `data.json` resets on each
  deploy and on cold-start. IDs stay stable while the instance is warm. For truly
  "infinite" IDs across restarts, upgrade the plan and enable the persistent disk +
  `DATA_FILE` block (commented in `render.yaml`).
- **Client IP:** the server reads `X-Forwarded-For`, which Render's proxy sets — so the
  fuzzy/same-IP matching uses the real visitor IP, not Render's.
- **Node version:** pinned to 22 via `.node-version` and `NODE_VERSION`.
