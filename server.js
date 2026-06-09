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

// Fuzzy-match threshold (weights below sum to 38). With the SAME IP this links
// two slightly-different fingerprints (e.g. Safari vs the Instagram in-app browser)
// to one identity. Exact core-hash match links across IPs too.
//
// keyId carries the heaviest weight (8): it is a cryptographic per-device key
// (sha256 of a non-extractable browser keypair), far more reliable than any
// passive fingerprint field — it cannot collide between two identical devices.
// A matching keyId also short-circuits as a tier-0 exact match in identify().
const WEIGHTS = {
  keyId: 8,
  canvas: 3, audio: 3, webglR: 2, screen: 2, avail: 1, dpr: 1, orient: 1,
  locale: 1, tz: 1, platform: 1, cores: 1, touch: 1, vendor: 1, productSub: 1,
  gamut: 1, hdr: 1
};
const THRESHOLD = 13;

// When on (default), a fresh per-origin nonce arriving with an ALREADY-KNOWN
// fingerprint on the SAME IP is treated as a *different physical unit* of the
// same model, so identical devices get distinct ids. Trade-off: on Safari the
// nonce is partitioned per site, so this can also split one device across sites.
// Set UNIQUE_UNITS=0 to prioritise cross-site linking instead.
const UNIQUE_UNITS = process.env.UNIQUE_UNITS !== "0";

// ---------- store ----------
let records = [];                 // [{ id, hashes:[], nonces:[], ips:[], sig:{}, createdAt, lastSeen }]
const byCore = new Map();         // coreHash -> record
const byNonce = new Map();        // per-origin nonce -> record
const byKey = new Map();          // per-device crypto keyId -> record

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
    byCore.clear(); byNonce.clear(); byKey.clear();
    for (const r of records) {
      if (!r.nonces) r.nonces = [];
      if (!r.keyIds) r.keyIds = [];
      for (const h of r.hashes) byCore.set(h, r);
      for (const n of r.nonces) byNonce.set(n, r);
      for (const k of r.keyIds) byKey.set(k, r);
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
  // Cross-site fingerprint: stable model+browser signals only.
  // Deliberately EXCLUDES nonce + quota (those are per-origin / per-unit).
  const basis = [
    s.canvas, s.audio, s.webglV, s.webglR, s.screen, s.avail, s.dpr, s.orient,
    s.tz, s.locale, s.tzoff, s.platform, s.cores, s.touch, s.vendor,
    s.productSub, s.dark, s.gamut, s.hdr
  ].join("|");
  return crypto.createHash("sha256").update(basis).digest("hex");
}

function score(a, b) {
  let n = 0;
  for (const k in WEIGHTS) {
    if (a[k] != null && b[k] != null && String(a[k]) === String(b[k]) && String(a[k]) !== "na") n += WEIGHTS[k];
  }
  return n;
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
  const splitUnit = UNIQUE_UNITS && exact && exact.ips.indexOf(ip) !== -1 && freshUnitMarker;

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

    // 3) fuzzy match, but only among identities seen from the same IP
    let best = null, bestScore = 0;
    for (const r of records) {
      if (r.ips.indexOf(ip) === -1) continue;
      const s = score(sig, r.sig);
      if (s > bestScore) { bestScore = s; best = r; }
    }
    if (best && bestScore >= THRESHOLD) {
      best.hashes.push(h);
      byCore.set(h, best);
      touch(best, ip, sig, nonce, keyId);
      stats.fuzzy++;
      logFuzzy({ t: Date.now(), id: best.id, score: bestScore, ip: ip, keyId: keyId, keyIdsNow: best.keyIds.length });
      return best.id;
    }
  } else {
    stats.split++;
  }

  // 4) new identity (also the unit-split path)
  const r = {
    id: newId(), hashes: [h], nonces: nonce ? [nonce] : [], keyIds: keyId ? [keyId] : [],
    ips: ip ? [ip] : [], sig: sig, createdAt: Date.now(), lastSeen: Date.now()
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

  if (req.method === "GET" && (url === "/id-generator.js")) {
    cors(res, origin);
    res.setHeader("Content-Type", "text/javascript; charset=utf-8");
    res.setHeader("Cache-Control", "public, max-age=300");
    return fs.readFile(SCRIPT_FILE, (e, buf) => {
      if (e) { res.writeHead(500); return res.end("// script unavailable"); }
      res.writeHead(200); res.end(buf);
    });
  }

  if (req.method === "GET" && (url === "/" || url === "/demo.html" || url === "/testcase.html")) {
    const file = url === "/testcase.html" ? "testcase.html" : "demo.html";
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
