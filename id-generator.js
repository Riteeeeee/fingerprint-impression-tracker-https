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

  var PREFIX = "br_";
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
  var EC_ENDPOINT = ENDPOINT.replace(/\/id$/, "/ec");   // evercookie (HTTP-cache ETag) restore

  // ---- evercookie: a token pinned in the HTTP cache (ETag) that survives a
  // localStorage/IndexedDB clear. The server maps token -> id. ----
  function ecGet() {
    return new Promise(function (resolve) {
      try {
        fetch(EC_ENDPOINT).then(function (r) { return r.json(); })
          .then(function (d) { resolve(d || {}); })
          .catch(function () { resolve({}); });
      } catch (e) { resolve({}); }
    });
  }
  function ecBind(token, id) {
    if (!token || !id) return;
    try { fetch(EC_ENDPOINT + "?bind=" + encodeURIComponent(token) + "&id=" + encodeURIComponent(id)); } catch (e) {}
  }

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

  // ---- installed fonts (high entropy, stable; great on Safari where canvas is generic) ----
  function fontsFP() {
    try {
      var base = ["monospace", "sans-serif", "serif"];
      var probe = ["Arial","Courier New","Georgia","Helvetica","Times New Roman","Verdana",
        "Comic Sans MS","Impact","Trebuchet MS","Palatino","Tahoma","Monaco","Menlo","Geneva",
        "Optima","Futura","Gill Sans","Baskerville","Andale Mono","Brush Script MT","Copperplate","Didot"];
      var host = document.body || document.documentElement;
      var span = document.createElement("span");
      span.style.cssText = "position:absolute;left:-9999px;top:-9999px;font-size:72px";
      span.textContent = "mmmmmmmmmmlli";
      host.appendChild(span);
      var def = {};
      base.forEach(function (b) { span.style.fontFamily = b; def[b] = { w: span.offsetWidth, h: span.offsetHeight }; });
      var found = [];
      probe.forEach(function (f) {
        var hit = false;
        base.forEach(function (b) {
          span.style.fontFamily = "'" + f + "'," + b;
          if (span.offsetWidth !== def[b].w || span.offsetHeight !== def[b].h) hit = true;
        });
        if (hit) found.push(f);
      });
      host.removeChild(span);
      return found.length ? found.join(",") : "na";
    } catch (e) { return "na"; }
  }

  // ---- extra WebGL parameters + extensions (GPU/driver profile) ----
  function webglParams() {
    try {
      var c = document.createElement("canvas");
      var gl = c.getContext("webgl") || c.getContext("experimental-webgl");
      if (!gl) return "na";
      var p = [
        gl.getParameter(gl.MAX_TEXTURE_SIZE), gl.getParameter(gl.MAX_COMBINED_TEXTURE_IMAGE_UNITS),
        gl.getParameter(gl.MAX_VERTEX_ATTRIBS), gl.getParameter(gl.MAX_VERTEX_UNIFORM_VECTORS),
        gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS), gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
        gl.getParameter(gl.MAX_VIEWPORT_DIMS)
      ].join("|");
      var ext = (gl.getSupportedExtensions() || []).sort().join(",");
      return fnv1a(p + "||" + ext);
    } catch (e) { return "na"; }
  }

  // ---- installed speech-synthesis voices (very identifying on macOS/Safari) ----
  function speechVoices() {
    return new Promise(function (resolve) {
      try {
        if (!window.speechSynthesis) return resolve("na");
        var done = false;
        function names() { var v = speechSynthesis.getVoices() || []; return v.map(function (x) { return x.name; }).sort().join(","); }
        function tryRead() { if (done) return; var s = names(); if (s) { done = true; resolve(fnv1a(s) + ":" + (speechSynthesis.getVoices() || []).length); } }
        tryRead();
        speechSynthesis.onvoiceschanged = tryRead;
        setTimeout(function () { if (!done) { done = true; var s = names(); resolve(s ? fnv1a(s) + ":" + (speechSynthesis.getVoices() || []).length : "na"); } }, 600);
      } catch (e) { resolve("na"); }
    });
  }

  // ---- JS-engine + CPU math fingerprint (transcendental ULP differs per engine/arch) ----
  function mathFP() {
    try {
      var v = [
        Math.tan(-1e300), Math.sin(1e300), Math.cos(1e300), Math.sinh(1), Math.cosh(10),
        Math.tanh(0.5), Math.asinh(1e300), Math.acosh(1e154), Math.atanh(0.5), Math.expm1(1),
        Math.exp(10), Math.log1p(100), Math.cbrt(1e300), Math.pow(Math.PI, -100), Math.atan2(1e300, 1e-300)
      ].map(function (x) { return String(x); }).join(",");
      return fnv1a(v);
    } catch (e) { return "na"; }
  }

  // ---- Web-API presence matrix (browser/engine/OS class + tamper detector) ----
  function apiMatrixFP() {
    try {
      var probes = [
        "AudioContext", "webkitAudioContext", "OfflineAudioContext", "RTCPeerConnection",
        "WebGL2RenderingContext", "BroadcastChannel", "SharedWorker", "PaymentRequest",
        "ApplePaySession", "OffscreenCanvas", "createImageBitmap", "PerformanceObserver",
        "ReportingObserver", "IntersectionObserver", "ResizeObserver", "queueMicrotask",
        "BigInt", "WeakRef", "FinalizationRegistry", "structuredClone"
      ];
      var navProbes = ["bluetooth", "usb", "hid", "serial", "wakeLock", "getBattery",
        "deviceMemory", "mediaDevices", "permissions", "clipboard", "share", "vibrate",
        "getGamepads", "requestMIDIAccess", "xr", "credentials", "storage", "gpu",
        "userActivation", "scheduling", "virtualKeyboard", "windowControlsOverlay", "ink"];
      var bits = "";
      for (var i = 0; i < probes.length; i++) bits += (probes[i] in window) ? "1" : "0";
      for (var j = 0; j < navProbes.length; j++) bits += (navProbes[j] in navigator) ? "1" : "0";
      bits += (window.crypto && window.crypto.subtle) ? "1" : "0";
      bits += (typeof Intl !== "undefined" && Intl.RelativeTimeFormat) ? "1" : "0";
      bits += (typeof CSS !== "undefined" && CSS.supports) ? "1" : "0";
      return fnv1a(bits);
    } catch (e) { return "na"; }
  }

  // ---- engine quirks: error.stack shape + native toString + sort (cohort + tamper) ----
  function engineFP() {
    try {
      var st = "";
      try { (null)(); } catch (e) { st = (e.name || "") + ":" + ((e.stack || "").split("\n").length) + ":" + (/@|at /.test(e.stack || "") ? (/^.*at /.test(e.stack || "") ? "at" : "@") : "?"); }
      var nativeLen = Function.prototype.toString.call(Array.prototype.push).replace(/\s/g, "").length;
      return fnv1a(st + "|" + nativeLen);
    } catch (e) { return "na"; }
  }

  // ---- private/incognito heuristic (tiny storage quota) so server won't mis-split ----
  function incognitoCheck() {
    return new Promise(function (resolve) {
      try {
        if (navigator.storage && navigator.storage.estimate) {
          navigator.storage.estimate().then(function (e) {
            var q = e.quota || 0;
            resolve(q > 0 && q < 300 * 1024 * 1024 ? "1" : "0");
          }).catch(function () { resolve("na"); });
          return;
        }
      } catch (e) {}
      resolve("na");
    });
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
    return Promise.all([audioFP(), storageQuota(), getKeyId(), speechVoices(), incognitoCheck()]).then(function (arr) {
      var audio = arr[0], quota = arr[1], keyId = arr[2], voices = arr[3], incognito = arr[4];
      var io = {};
      try { io = Intl.DateTimeFormat().resolvedOptions(); } catch (e) {}
      return {
        // --- stable, cross-site fingerprint signals (model + browser engine) ---
        canvas: canvasFP(),
        audio: audio,
        fonts: fontsFP(),
        voices: voices,
        webglV: wg.v,
        webglR: wg.r,
        webglP: webglParams(),
        screen: [screen.width, screen.height, screen.colorDepth].join("x"),
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
        deviceMemory: navigator.deviceMemory || "na",
        colorDepth: screen.colorDepth || "na",
        dnt: navigator.doNotTrack || window.doNotTrack || "na",
        cookieEnabled: (typeof navigator.cookieEnabled === "boolean") ? String(navigator.cookieEnabled) : "na",
        // --- cohort / tamper signals (browser+engine class; harden matching) ---
        mathFP: mathFP(),
        apiMatrix: apiMatrixFP(),
        engineFP: engineFP(),
        incognito: incognito,
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

  // Re-seed EVERY storage vector so a partial clear self-heals and ITP eviction
  // timers get refreshed. Called on every acquisition (hit or miss).
  function reseed(id, ecToken) {
    try { localStorage.setItem(STORAGE_KEY, id); } catch (e) {}
    try { getNonce(); } catch (e) {}                 // recreate localStorage nonce if cleared
    try { getKeyId(); } catch (e) {}                 // recreate IndexedDB crypto key if cleared
    if (ecToken) ecBind(ecToken, id);                // bind evercookie token -> id
    else ecGet().then(function (ec) { if (ec && ec.token) ecBind(ec.token, id); });
  }

  // ---- TIER 0: cryptographic device key (challenge-response) ----
  var BASE = ENDPOINT.replace(/\/id$/, "");

  function abToB64url(ab) { var b = new Uint8Array(ab), s = ""; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
  function b64urlToU8(str) { str = String(str).replace(/-/g, "+").replace(/_/g, "/"); while (str.length % 4) str += "="; var bin = atob(str), u = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; }

  // Load the device's non-extractable ECDSA P-256 keypair from IndexedDB, or mint one.
  function getKeypair() {
    return new Promise(function (resolve) {
      try {
        if (!window.indexedDB || !crypto.subtle) return resolve(null);
        var req = indexedDB.open("ntrx", 1);
        req.onupgradeneeded = function () { req.result.createObjectStore("kv"); };
        req.onerror = function () { resolve(null); };
        req.onsuccess = function () {
          var db = req.result;
          var g = db.transaction("kv", "readonly").objectStore("kv").get("kp");
          g.onerror = function () { resolve(null); };
          g.onsuccess = function () {
            if (g.result && g.result.privateKey) return resolve(g.result);
            crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
              .then(function (kp) {
                var tx = db.transaction("kv", "readwrite");
                tx.objectStore("kv").put(kp, "kp");
                tx.oncomplete = function () { resolve(kp); };
                tx.onerror = function () { resolve(kp); };
              }, function () { resolve(null); });
          };
        };
      } catch (e) { resolve(null); }
    });
  }
  // { spki, keyId } from the public key (keyId = b64url(sha256(SPKI)))
  function pubInfo(pub) {
    return crypto.subtle.exportKey("spki", pub).then(function (spki) {
      return crypto.subtle.digest("SHA-256", spki).then(function (h) {
        return { spki: abToB64url(spki), keyId: abToB64url(h) };
      });
    });
  }
  // sign nonce||browserId with the non-extractable private key -> b64url(64B P1363)
  function signChallenge(priv, challengeB64, browserId) {
    var nonce = b64urlToU8(challengeB64);
    var bid = new TextEncoder().encode(browserId);
    var msg = new Uint8Array(nonce.length + bid.length);
    msg.set(nonce, 0); msg.set(bid, nonce.length);
    return crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, priv, msg).then(function (sig) { return abToB64url(sig); });
  }
  function jpost(path, body) {
    return fetch(BASE + path, { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "include", body: JSON.stringify(body) })
