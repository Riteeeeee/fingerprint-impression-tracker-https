/*!
 * ntrx identity server — zero external dependencies (Node 18+).
 *
 *   POST /id              -> { id }   get_or_create from (fingerprint + client IP)
 *   GET  /id-generator.js -> serves the client script (CORS, text/javascript)
 *   GET  /health          -> ok
 *
 * Run:  node server.js          (PORT defaults to 8080)
 * Put nginx + TLS in front (Safari requires HTTPS when host sites are HTTPS).
 */
"use strict";

const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 8080;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, "data.json");
const SCRIPT_FILE = path.join(__dirname, "id-generator.js");
const PREFIX = "ntrx_";

// Per-signal weights = entropy (how distinguishing) x stability (survives revisits).
// Matching is CONFIDENCE based: confidence = matchedWeight / comparableWeight, so
// it self-normalises whether or not a signal (e.g. server-side JA4) is present.
//
//   server-side (spoof-proof, cross-site)  ja4, h2fp   -- only if a TLS/HTTP2 proxy
//                                                          forwards them as headers
//   high-entropy + stable                  voices, fonts, canvas, webglR/webglP
//   medium                                 screen, ua, tz, locale
//   low / high-collision                   the rest (weight 1)
// keyId / nonce are NOT here: they are handled as exact tiers (0/1) in identify().
// NOTE: deviceMemory dropped — Safari never implements it (always "na"), so it was
// dead weight on the must-run platform. colorDepth/dnt/cookieEnabled kept at low
// weight (near-constant). mathFP/apiMatrix/engineFP are engine+OS cohort + tamper bits.
const WEIGHTS = {
  ja4: 8, h2fp: 5,
  voices: 5, fonts: 4, canvas: 3, webglR: 2, webglP: 2, screen: 2, ua: 2, mathFP: 2, apiMatrix: 2,
  tz: 1, locale: 1, audio: 1, avail: 1, dpr: 1, orient: 1, engineFP: 1,
  platform: 1, cores: 1, touch: 1, vendor: 1, productSub: 1,
  gamut: 1, hdr: 1, colorDepth: 1, dnt: 1, cookieEnabled: 1
};
// Confidence thresholds for the fuzzy tier:
const CONF_SAME_IP   = 0.55;   // same network: looser (absorbs drift)
const CONF_CROSS_IP  = 0.72;   // different network: stricter (stay collision-safe)
const MIN_COMPARABLE = 6;      // need at least this much comparable weight to trust a match

// STABILITY-FIRST default (OFF). When OFF, the same device ALWAYS keeps its id —
// a fresh nonce/keyId on a known fingerprint is treated as the same device, never
// split. This is what guarantees the id never changes across cookie clears / new
// sessions. Set UNIQUE_UNITS=1 ONLY if you'd rather separate two identical-model
// devices at the cost of that stability (they look identical to the server).
const UNIQUE_UNITS = process.env.UNIQUE_UNITS === "1";

// ---------- store ----------
let records = [];                 // [{ id, hashes:[], nonces:[], ips:[], sig:{}, createdAt, lastSeen }]
const byCore = new Map();         // coreHash -> record
const byNonce = new Map();        // per-origin nonce -> record
const byKey = new Map();          // per-device crypto keyId -> record
const byEcToken = new Map();      // evercookie HTTP-cache token -> record

// ---------- collision / match telemetry ----------
// How each /id request was resolved. Fuzzy + (in UNIQUE_UNITS=0) bare exact-hash
// merges are the COLLISION-PRONE paths: that's where two different devices can be
// fused into one identity. We count them and keep a log of fuzzy merges to review.
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
const stats = { total: 0, keyId: 0, nonce: 0, exact: 0, fuzzy: 0, split: 0, fresh: 0 };
const fuzzyLog = [];              // recent fuzzy merges: {t, id, score, ip, keyId}
function logFuzzy(e) { fuzzyLog.push(e); if (fuzzyLog.length > 300) fuzzyLog.shift(); }

function load() {
  try {
    const raw = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    records = raw.records || [];
    byCore.clear(); byNonce.clear(); byKey.clear(); byEcToken.clear();
    for (const r of records) {
      if (!r.nonces) r.nonces = [];
      if (!r.keyIds) r.keyIds = [];
      if (!r.ecTokens) r.ecTokens = [];
      for (const h of r.hashes) byCore.set(h, r);
      for (const n of r.nonces) byNonce.set(n, r);
      for (const k of r.keyIds) byKey.set(k, r);
      for (const t of r.ecTokens) byEcToken.set(t, r);
    }
    console.log("[ntrx] loaded " + records.length + " identities");
  } catch (e) { records = []; }
}

let saveTimer = null;
function save() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    try {
      const tmp = DATA_FILE + ".tmp";
      fs.writeFileSync(tmp, JSON.stringify({ records }));
      fs.renameSync(tmp, DATA_FILE); // atomic
    } catch (e) { console.error("[ntrx] save error", e); }
  }, 500);
}

function newId() { return PREFIX + crypto.randomBytes(32).toString("hex"); } // 69 chars

function coreHash(s) {
  // Cross-site fingerprint: ONLY rock-stable, DETERMINISTIC, network-independent
  // signals — the ones that stay identical across storage/cookie clears too.
  // EXCLUDED on purpose:
  //   audio  -> WebAudio is non-deterministic (noise / 1.5s timeout -> "na"),
  //   dpr/avail/orient/dark/gamut/hdr -> change on zoom/rotate/toolbar/dark-mode,
  //   tzoff  -> DST,  nonce/quota/keyId -> per-origin (wiped on clear).
  // canvas + WebGL + screen + nav fields survive a full cookie/site-data clear,
  // so the SAME device re-resolves to the SAME id. (audio still helps in fuzzy.)
  const basis = [
    s.canvas, s.fonts, s.voices, s.webglV, s.webglR, s.webglP, s.mathFP, s.screen,
    s.tz, s.locale, s.platform, s.cores, s.touch, s.vendor, s.productSub
  ].join("|");
  return crypto.createHash("sha256").update(basis).digest("hex");
}

// Compare two signal sets -> { matched, comparable, confidence }.
// Only signals PRESENT (non-"na") in BOTH sides count toward "comparable", so
// confidence isn't punished for signals one side happens not to send.
function compare(a, b) {
  let matched = 0, comparable = 0;
  for (const k in WEIGHTS) {
    const av = a[k], bv = b[k];
    const aok = av != null && av !== "" && String(av) !== "na";
    const bok = bv != null && bv !== "" && String(bv) !== "na";
    if (aok && bok) {
      comparable += WEIGHTS[k];
      if (String(av) === String(bv)) matched += WEIGHTS[k];
    }
  }
  return { matched, comparable, confidence: comparable ? matched / comparable : 0 };
}

function touch(r, ip, sig, nonce, keyId) {
  r.lastSeen = Date.now();
  if (ip && r.ips.indexOf(ip) === -1) r.ips.push(ip);
  if (nonce && r.nonces.indexOf(nonce) === -1) { r.nonces.push(nonce); byNonce.set(nonce, r); }
  if (keyId && r.keyIds.indexOf(keyId) === -1) { r.keyIds.push(keyId); byKey.set(keyId, r); }
  r.sig = sig; // keep most recent observation
  save();
}

function identify(sig, ip) {
  const keyId = (sig.keyId && sig.keyId !== "na") ? sig.keyId : null;
  const nonce = (sig.nonce && sig.nonce !== "na") ? sig.nonce : null;
  const incognito = sig.incognito === "1" || sig.incognito === true;
  const h = coreHash(sig);
  stats.total++;

  // 0) known crypto keyId — STRONGEST signal: cryptographic proof of the same
  //    physical device. Cannot collide between two identical units.
  if (keyId && byKey.has(keyId)) {
    const r = byKey.get(keyId);
    if (r.hashes.indexOf(h) === -1) { r.hashes.push(h); byCore.set(h, r); }
    touch(r, ip, sig, nonce, keyId);
    stats.keyId++;
    return r.id;
  }

  // 1) known nonce — same physical device on this origin (weaker than keyId).
  if (nonce && byNonce.has(nonce)) {
    const r = byNonce.get(nonce);
    if (r.hashes.indexOf(h) === -1) { r.hashes.push(h); byCore.set(h, r); }
    touch(r, ip, sig, nonce, keyId);
    stats.nonce++;
    return r.id;
  }

  // Identical-unit collision check: same fingerprint already bound to a
  // DIFFERENT keyId/nonce on the SAME IP, and we carry a fresh one => different unit.
  const exact = byCore.get(h);
  const freshUnitMarker =
    (keyId && exact && exact.keyIds.length > 0 && exact.keyIds.indexOf(keyId) === -1) ||
    (nonce && exact && exact.nonces.length > 0 && exact.nonces.indexOf(nonce) === -1);
  // In incognito the keyId/nonce are absent or throwaway, so NEVER split — that
  // would mint a bogus new id for a device we'd otherwise recognise by fingerprint.
  const splitUnit = UNIQUE_UNITS && !incognito && exact && exact.ips.indexOf(ip) !== -1 && freshUnitMarker;

  if (!splitUnit) {
    // 2) exact device match — works even across networks / IP changes.
    // COLLISION RISK: a brand-new keyId landing on an existing fingerprint means
    // either the same device on a new origin (legit) or a different identical
    // device (collision). We flag it when it carries an unseen keyId.
    if (exact) {
      const collisionRisk = !!keyId && exact.keyIds.length > 0 && exact.keyIds.indexOf(keyId) === -1;
      touch(exact, ip, sig, nonce, keyId);
      stats.exact++;
      if (collisionRisk) logFuzzy({ t: Date.now(), id: exact.id, score: "exact-hash", ip: ip, keyId: keyId, keyIdsNow: exact.keyIds.length });
      return exact.id;
    }

    // 3) fuzzy match over ALL identities by CONFIDENCE (matched / comparable weight).
    //    - same IP  + confidence >= CONF_SAME_IP   -> match (absorbs drift)
    //    - any IP   + confidence >= CONF_CROSS_IP  -> match (survives network change)
    let best = null, bestCmp = { confidence: 0, comparable: 0 };
    for (const r of records) {
      const c = compare(sig, r.sig);
      if (c.comparable < MIN_COMPARABLE) continue;
      if (c.confidence > bestCmp.confidence) { bestCmp = c; best = r; }
    }
    if (best) {
      const sameIp = best.ips.indexOf(ip) !== -1;
      const conf = bestCmp.confidence;
      if ((sameIp && conf >= CONF_SAME_IP) || conf >= CONF_CROSS_IP) {
        best.hashes.push(h);
        byCore.set(h, best);
        touch(best, ip, sig, nonce, keyId);
        stats.fuzzy++;
        logFuzzy({ t: Date.now(), id: best.id, score: conf.toFixed(2) + (sameIp ? "" : " (cross-IP)"), ip: ip, keyId: keyId, keyIdsNow: best.keyIds.length });
        return best.id;
      }
    }
  } else {
    stats.split++;
  }

  // 4) new identity (also the unit-split path)
  const r = {
    id: newId(), hashes: [h], nonces: nonce ? [nonce] : [], keyIds: keyId ? [keyId] : [],
    ecTokens: [], ips: ip ? [ip] : [], sig: sig, createdAt: Date.now(), lastSeen: Date.now()
  };
  records.push(r);
  byCore.set(h, r);                 // newest unit wins the bare-fingerprint mapping
  if (nonce) byNonce.set(nonce, r);
  if (keyId) byKey.set(keyId, r);
  save();
  stats.fresh++;
  return r.id;
}

// ---------- http ----------
function clientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (xff) return String(xff).split(",")[0].trim();
  return (req.socket.remoteAddress || "").replace(/^::ffff:/, "");
}

function cors(res, origin) {
  res.setHeader("Access-Control-Allow-Origin", origin || "*");
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Max-Age", "86400");
}

const server = http.createServer((req, res) => {
  const origin = req.headers.origin;
  const url = (req.url || "/").split("?")[0];

  if (req.method === "OPTIONS") { cors(res, origin); res.writeHead(204); return res.end(); }

  if (req.method === "GET" && (url === "/id-generator.js" || url === "/shopify-ntrx.js")) {
    const jsFile = url === "/shopify-ntrx.js" ? path.join(__dirname, "shopify-ntrx.js") : SCRIPT_FILE;
    cors(res, origin);
    res.setHeader("Content-Type", "text/javascript; charset=utf-8");
    res.setHeader("Cache-Control", "public, max-age=300");
    return fs.readFile(jsFile, (e, buf) => {
      if (e) { res.writeHead(500); return res.end("// script unavailable"); }
      res.writeHead(200); res.end(buf);
    });
  }

  if (req.method === "GET" && (url === "/" || url === "/demo.html" || url === "/testcase.html" || url === "/dashboard" || url === "/dashboard.html")) {
    const file = url === "/testcase.html" ? "testcase.html"
               : (url === "/dashboard" || url === "/dashboard.html") ? "dashboard.html"
               : "demo.html";
    cors(res, origin);
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return fs.readFile(path.join(__dirname, file), (e, buf) => {
      if (e) { res.writeHead(500); return res.end(file + " unavailable"); }
      res.writeHead(200); res.end(buf);
    });
  }

  if (req.method === "GET" && url === "/stats") {
    cors(res, origin);
    res.setHeader("Content-Type", "application/json");
    // Gate with ADMIN_TOKEN if one is set (?token=... or X-Admin-Token header).
    if (ADMIN_TOKEN) {
      const q = (req.url.split("?")[1] || "").split("&").reduce((a, kv) => { const [k, v] = kv.split("="); a[k] = decodeURIComponent(v || ""); return a; }, {});
      const tok = q.token || req.headers["x-admin-token"];
      if (tok !== ADMIN_TOKEN) { res.writeHead(403); return res.end(JSON.stringify({ error: "forbidden" })); }
    }

    // Fan-out histogram: how many identities have N distinct device keyIds.
    // High keyId/IP fan-out on one identity = likely collision (different devices
    // fused), since a single device on a few sites yields only a few keyIds.
    const hist = { keyIds: {}, ips: {} };
    const bump = (m, n) => { const b = n >= 5 ? "5+" : String(n); m[b] = (m[b] || 0) + 1; };
    let multiKey = 0;
    const suspects = [];
    for (const r of records) {
      const k = (r.keyIds || []).length, i = (r.ips || []).length;
      bump(hist.keyIds, k); bump(hist.ips, i);
      if (k >= 2) multiKey++;
      suspects.push({ id: r.id.slice(0, 16) + "…", keyIds: k, ips: i, hashes: r.hashes.length, lastSeen: r.lastSeen });
    }
    suspects.sort((a, b) => (b.keyIds - a.keyIds) || (b.ips - a.ips) || (b.hashes - a.hashes));

    res.writeHead(200);
    return res.end(JSON.stringify({
      identities: records.length,
      matches: stats,                                 // how requests resolved (keyId/nonce/exact/fuzzy/split/fresh)
      riskyMergeRate: stats.total ? +(((stats.fuzzy + stats.exact) / stats.total)).toFixed(3) : 0,
      multiDeviceIdentities: multiKey,                // identities holding >=2 keyIds (collision candidates)
      fanout: hist,                                   // distribution of keyIds/ips per identity
      topSuspects: suspects.slice(0, 25),             // most-merged identities — inspect these
      recentRiskyMerges: fuzzyLog.slice(-50)          // fuzzy + bare-exact merges with an unseen keyId
    }, null, 2));
  }

  // Evercookie: a token pinned in the browser HTTP cache (ETag) that survives a
  // localStorage/IndexedDB clear. GET mints/echoes a token + reports any recovered
  // id; GET ?bind=<token>&id=<id> binds the token to an identity.
  if (req.method === "GET" && url === "/ec") {
    cors(res, origin);
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Cache-Control", "no-cache, private");
    const q = (req.url.split("?")[1] || "").split("&").reduce((a, kv) => { const [k, v] = kv.split("="); a[k] = decodeURIComponent(v || ""); return a; }, {});

    // bind token -> id
    if (q.bind && /^ntrx_[0-9a-f]+$/.test(q.id || "")) {
      const rec = records.find(r => r.id === q.id);
      if (rec) {
        if (!rec.ecTokens) rec.ecTokens = [];
        if (rec.ecTokens.indexOf(q.bind) === -1) { rec.ecTokens.push(q.bind); byEcToken.set(q.bind, rec); save(); }
      }
      res.setHeader("ETag", '"ec:' + q.bind + '"');
      res.writeHead(200); return res.end(JSON.stringify({ ok: true }));
    }

    // mint / recover: read token from If-None-Match (browser auto-sends cached ETag)
    const inm = req.headers["if-none-match"] || "";
    const m = inm.match(/ec:([a-z0-9]+)/i);
    let token = m ? m[1] : null;
    let recovered = null;
    if (token && byEcToken.has(token)) recovered = byEcToken.get(token).id;
    if (!token) token = crypto.randomBytes(16).toString("hex");
    res.setHeader("ETag", '"ec:' + token + '"');
    res.writeHead(200); return res.end(JSON.stringify({ token: token, recovered: recovered }));
  }

  if (req.method === "GET" && url === "/health") {
    cors(res, origin); res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ ok: true, identities: records.length }));
  }

  if (req.method === "POST" && url === "/id") {
    let body = "";
    req.on("data", (c) => { body += c; if (body.length > 1e5) req.destroy(); });
    req.on("end", () => {
      let sig;
      try { sig = JSON.parse(body || "{}"); } catch (e) { sig = null; }
      cors(res, origin);
      res.setHeader("Content-Type", "application/json");
      if (!sig || typeof sig !== "object") { res.writeHead(400); return res.end(JSON.stringify({ error: "bad signals" })); }
      // Server-side, spoof-proof signals — only present if a TLS/HTTP2-terminating
      // front (nginx+ja4 module, Cloudflare, the ja4-fingerprint server) forwards
      // them. JS can't set these, so they're high-trust when available.
      const ja4 = req.headers["x-ja4"] || req.headers["cf-ja4"] || req.headers["x-ja4-fingerprint"];
      if (ja4) sig.ja4 = String(ja4);
      const h2 = req.headers["x-h2fp"] || req.headers["x-http2-fingerprint"];
      if (h2) sig.h2fp = String(h2);
      const id = identify(sig, clientIp(req));
      res.writeHead(200); res.end(JSON.stringify({ id }));
    });
    return;
  }

  cors(res, origin); res.writeHead(404); res.end("not found");
});

load();
process.on("SIGINT", () => { try { fs.writeFileSync(DATA_FILE, JSON.stringify({ records })); } catch (e) {} process.exit(0); });
server.listen(PORT, () => console.log("[ntrx] listening on :" + PORT));
