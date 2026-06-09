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

  // 0) known crypto keyId — STRONGEST signal: cryptographic proof of the same
  //    physical device. Cannot collide between two identical units.
  if (keyId && byKey.has(keyId)) {
    const r = byKey.get(keyId);
    if (r.hashes.indexOf(h) === -1) { r.hashes.push(h); byCore.set(h, r); }
    touch(r, ip, sig, nonce, keyId);
    return r.id;
  }

  // 1) known nonce — same physical device on this origin (weaker than keyId).
  if (nonce && byNonce.has(nonce)) {
    const r = byNonce.get(nonce);
    if (r.hashes.indexOf(h) === -1) { r.hashes.push(h); byCore.set(h, r); }
    touch(r, ip, sig, nonce, keyId);
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
    // 2) exact device match — works even across networks / IP changes
    if (exact) { touch(exact, ip, sig, nonce, keyId); return exact.id; }

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
      return best.id;
    }
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
