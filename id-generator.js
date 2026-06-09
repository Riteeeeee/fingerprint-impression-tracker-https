/*!
 * ntrx id-generator.js  —  cross-site identity without 3rd-party cookies
 * Drop-in: <script type="text/javascript" src="//your-server/id-generator.js"></script>
 *
 * Exposes a global `iDx`:
 *     iDx.config        - object the host page may set (optional; supports {endpoint})
 *     iDx.id            - the acquired id (null until ready)
 *     iDx.onIdAquired   - callback(id); fires as soon as id is known, even if
 *                         assigned AFTER acquisition (immediate-fire setter).
 *
 * Strategy:
 *   1. First-party localStorage cache -> instant + stable on repeat visits to SAME origin.
 *   2. On a cache miss, collect a device fingerprint and POST it to the central
 *      identity server, which does get_or_create using (fingerprint + client IP).
 *      That call links the same device across DIFFERENT origins, because WebKit on
 *      one device yields a consistent fingerprint and the server sees one client IP.
 *   No cookies are used (first- or third-party), so ITP / 3p-cookie blocking is moot.
 */
(function () {
  "use strict";

  var PREFIX = "ntrx_";
  var STORAGE_KEY = "ntrx_id";
  var w = window;

  // ---- expose iDx synchronously so the host page can set config/onIdAquired ----
  var iDx = w.iDx = w.iDx || {};
  iDx.config = iDx.config || {};
  iDx.id = iDx.id || null;
  iDx._id = iDx._id || null;
  iDx._cb = iDx._cb || null;

  if (!Object.getOwnPropertyDescriptor(iDx, "onIdAquired")) {
    Object.defineProperty(iDx, "onIdAquired", {
      configurable: true, enumerable: true,
      get: function () { return iDx._cb; },
      set: function (fn) {
        iDx._cb = fn;
        if (typeof fn === "function" && iDx._id) { try { fn(iDx._id); } catch (e) {} }
      }
    });
  }

  function deliver(id) {
    iDx.id = id; iDx._id = id;
    try { console.log("ID: " + id); } catch (e) {}
    if (typeof iDx._cb === "function") { try { iDx._cb(id); } catch (e) {} }
  }

  // Resolve the identity API from where THIS script was loaded (truly drop-in).
  function defaultEndpoint() {
    var src = "";
    try {
      if (document.currentScript && document.currentScript.src) src = document.currentScript.src;
      else {
        var s = document.getElementsByTagName("script");
        for (var i = s.length - 1; i >= 0; i--) {
          if (s[i].src && /id-generator\.js/.test(s[i].src)) { src = s[i].src; break; }
        }
      }
      return new URL(src).origin + "/id";
    } catch (e) { return "/id"; }
  }
  var ENDPOINT = defaultEndpoint();

  // ---- tiny string hash (FNV-1a, 32-bit) to keep payloads small ----
  function fnv1a(str) {
    var h = 0x811c9dc5;
    for (var i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
    }
    return ("0000000" + h.toString(16)).slice(-8);
  }

  // ---- per-origin random nonce: distinguishes two IDENTICAL devices.
  // NOTE: localStorage is partitioned per top-level site on Safari, so this
  // nonce is per-(device,origin). It can separate identical units, but cannot
  // by itself link the same device across different sites. ----
  function getNonce() {
    try {
      var n = localStorage.getItem("ntrx_nonce");
      if (!n) {
        var a = new Uint8Array(16);
        (window.crypto || window.msCrypto).getRandomValues(a);
        n = "";
        for (var i = 0; i < a.length; i++) n += ("0" + a[i].toString(16)).slice(-2);
        localStorage.setItem("ntrx_nonce", n);
      }
      return n;
    } catch (e) { return "na"; }
  }

  // ---- media-query signal (WebKit-safe display capabilities) ----
  function mq(q) { try { return window.matchMedia(q).matches ? 1 : 0; } catch (e) { return "na"; } }

  // ---- per-device cryptographic key: STRONGEST per-unit signal.
  // A non-extractable ECDSA keypair lives in IndexedDB; the private key never
  // leaves the browser, so the keyId (sha256 of the public key) is unique per
  // physical device — even two identical models differ. Like the nonce it is
  // per-origin (IndexedDB is partitioned on Safari), so it separates units but
  // does not by itself link across sites. ----
  function pubId(pub) {
    return crypto.subtle.exportKey("spki", pub).then(function (raw) {
      return crypto.subtle.digest("SHA-256", raw).then(function (h) {
        var b = new Uint8Array(h), s = "";
        for (var i = 0; i < b.length; i++) s += ("0" + b[i].toString(16)).slice(-2);
        return s;
      });
    });
  }
  function getKeyId() {
    return new Promise(function (resolve) {
      try {
        if (!window.indexedDB || !crypto.subtle) return resolve("na");
        var req = indexedDB.open("ntrx", 1);
        req.onupgradeneeded = function () { req.result.createObjectStore("kv"); };
        req.onerror = function () { resolve("na"); };
        req.onsuccess = function () {
          var db = req.result;
          var g = db.transaction("kv", "readonly").objectStore("kv").get("kp");
          g.onerror = function () { resolve("na"); };
          g.onsuccess = function () {
            if (g.result) return pubId(g.result.publicKey).then(resolve, function () { resolve("na"); });
            // first visit on this origin: mint a fresh non-extractable keypair
            crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
              .then(function (kp) {
                var tx = db.transaction("kv", "readwrite");
                tx.objectStore("kv").put(kp, "kp");
                tx.oncomplete = function () { pubId(kp.publicKey).then(resolve, function () { resolve("na"); }); };
                tx.onerror = function () { resolve("na"); };
              }, function () { resolve("na"); });
          };
        };
      } catch (e) { resolve("na"); }
    });
  }

  // ---- storage quota: varies with free disk space => weak per-unit signal ----
  function storageQuota() {
    try {
      if (navigator.storage && navigator.storage.estimate) {
        return navigator.storage.estimate()
          .then(function (e) { return String(e.quota || "na"); })
          .catch(function () { return "na"; });
      }
    } catch (e) {}
    return Promise.resolve("na");
  }

  // ---- fingerprint signals (all WebKit/Safari-safe) ----
  function canvasFP() {
    try {
      var c = document.createElement("canvas");
      c.width = 280; c.height = 60;
      var ctx = c.getContext("2d");
      ctx.textBaseline = "top";
      ctx.font = "14px 'Arial'";
      ctx.fillStyle = "#f60"; ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = "#069"; ctx.fillText("ntrx\u25CE id-9876543210", 2, 15);
      ctx.fillStyle = "rgba(102,204,0,0.7)"; ctx.fillText("ntrx\u25CE id-9876543210", 4, 17);
      return fnv1a(c.toDataURL());
    } catch (e) { return "na"; }
  }

  function webglFP() {
    try {
      var c = document.createElement("canvas");
      var gl = c.getContext("webgl") || c.getContext("experimental-webgl");
      if (!gl) return { v: "na", r: "na" };
      var dbg = gl.getExtension("WEBGL_debug_renderer_info");
      var v = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR);
      var r = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
      return { v: String(v), r: String(r) };
    } catch (e) { return { v: "na", r: "na" }; }
  }

  function audioFP() {
    return new Promise(function (resolve) {
      try {
        var Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        if (!Ctx) return resolve("na");
        var ctx = new Ctx(1, 5000, 44100);
        var osc = ctx.createOscillator();
        osc.type = "triangle";
        osc.frequency.setValueAtTime(10000, ctx.currentTime);
        var comp = ctx.createDynamicsCompressor();
        comp.threshold.setValueAtTime(-50, ctx.currentTime);
        comp.knee.setValueAtTime(40, ctx.currentTime);
        comp.ratio.setValueAtTime(12, ctx.currentTime);
        comp.attack.setValueAtTime(0, ctx.currentTime);
        comp.release.setValueAtTime(0.25, ctx.currentTime);
        osc.connect(comp); comp.connect(ctx.destination);
        osc.start(0);
        var done = false;
        ctx.oncomplete = function (e) {
          if (done) return; done = true;
          var buf = e.renderedBuffer.getChannelData(0), sum = 0;
          for (var i = 4500; i < 5000; i++) sum += Math.abs(buf[i]);
          resolve(sum.toString());
        };
        ctx.startRendering();
        setTimeout(function () { if (!done) { done = true; resolve("na"); } }, 1500);
      } catch (e) { resolve("na"); }
    });
  }

  function collect() {
    var wg = webglFP();
    return Promise.all([audioFP(), storageQuota(), getKeyId()]).then(function (arr) {
      var audio = arr[0], quota = arr[1], keyId = arr[2];
      var io = {};
      try { io = Intl.DateTimeFormat().resolvedOptions(); } catch (e) {}
      return {
        // --- stable, cross-site fingerprint signals (model + browser engine) ---
        canvas: canvasFP(),
        audio: audio,
        webglV: wg.v,
        webglR: wg.r,
        screen: [screen.width, screen.height, screen.colorDepth, window.devicePixelRatio || 1].join("x"),
        avail: [screen.availWidth, screen.availHeight].join("x"),
        dpr: window.devicePixelRatio || 1,
        orient: (screen.orientation && screen.orientation.type) || "na",
        tz: io.timeZone || "na",
        locale: io.locale || "na",
        tzoff: new Date().getTimezoneOffset(),
        platform: navigator.platform || "na",
        cores: navigator.hardwareConcurrency || 0,
        touch: navigator.maxTouchPoints || 0,
        langs: (navigator.languages || [navigator.language || ""]).join(","),
        vendor: navigator.vendor || "na",
        productSub: navigator.productSub || "na",
        // display capabilities (good WebKit signals)
        dark: mq("(prefers-color-scheme: dark)"),
        motion: mq("(prefers-reduced-motion: reduce)"),
        gamut: mq("(color-gamut: p3)"),
        hdr: mq("(dynamic-range: high)"),
        // --- per-unit signals (separate two identical devices) ---
        keyId: keyId,
        quota: quota,
        nonce: getNonce(),
        ua: navigator.userAgent || ""
      };
    });
  }

  // ---- acquisition ----
  function start() {
    if (iDx._started) return;
    iDx._started = true;

    var endpoint = (iDx.config && iDx.config.endpoint) || ENDPOINT;

    var cached = null;
    try { cached = localStorage.getItem(STORAGE_KEY); } catch (e) {}
    if (cached && cached.indexOf(PREFIX) === 0) { deliver(cached); return; }

    collect().then(function (sig) {
      return fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(sig)
      }).then(function (r) { return r.json(); });
    }).then(function (res) {
      if (res && res.id) {
        try { localStorage.setItem(STORAGE_KEY, res.id); } catch (e) {}
        deliver(res.id);
      }
    }).catch(function (err) {
      try { console.log("ID: error", err && err.message); } catch (e) {}
    });
  }

  // Re-run acquisition (used by the demo page to simulate landing on a new site).
  // Clears the in-memory id so onIdAquired fires fresh; honours the cache unless
  // the caller has already cleared localStorage/IndexedDB.
  iDx.reacquire = function () {
    iDx._started = false;
    iDx.id = null;
    iDx._id = null;
    start();
  };

  // Defer one tick so the host page's synchronous `iDx.config = {...}` lands first.
  setTimeout(start, 0);
})();
