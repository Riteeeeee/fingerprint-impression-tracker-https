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
 *
 * Canvas strategy (Safari-stable):
 *   Old approach: draw small text + shapes, hash toDataURL() — lossy, Safari-unstable.
 *   New approach: draw on 800x400 canvas, read ALL pixel bytes via getImageData(),
 *   run FNV-1a over the full pixel buffer. This is the same checksum that stays
 *   identical across reloads on the same device/browser/OS, making it a far stronger
 *   and more stable signal on Safari / WebKit.
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

  // ---- FNV-1a over raw Uint8Array (pixel buffer variant) ----
  function fnv1aBytes(bytes) {
    var h = 0x811c9dc5;
    for (var i = 0; i < bytes.length; i++) {
      h ^= bytes[i];
      h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
    }
    return h >>> 0; // unsigned 32-bit integer
  }

  // ---- per-origin random nonce: distinguishes two IDENTICAL devices.
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

  // ---- media-query signal ----
  function mq(q) { try { return window.matchMedia(q).matches ? 1 : 0; } catch (e) { return "na"; } }

  // ---- per-device cryptographic key ----
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

  // ---- storage quota ----
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

  // ---- installed fonts ----
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

  // ---- WebGL parameters + extensions ----
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

  // ---- speech synthesis voices ----
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

  // =========================================================================
  // CANVAS FINGERPRINT — Safari-stable pixel-level checksum
  // =========================================================================
  // Replaces the old toDataURL()-based canvasFP().
  //
  // Why this is better for Safari / WebKit:
  //   - toDataURL() goes through PNG encoding, which can vary slightly across
  //     OS versions, GPU drivers, and color management profiles.
  //   - Reading raw RGBA pixels with getImageData() captures the actual
  //     rendered output bytes before any encoding step.
  //   - On the same device / browser / OS the pixel bytes are deterministic,
  //     so the FNV-1a checksum over all 800×400×4 = 1,280,000 bytes is
  //     identical across every page reload — making it a stable signal.
  //
  // Scene: line + circle + large text — chosen to exercise the text rasteriser
  // and anti-aliasing path, which differ across rendering engines.
  // =========================================================================
  function canvasFP() {
    try {
      var c = document.createElement("canvas");
      c.width = 800; c.height = 400;
      var ctx = c.getContext("2d");

      // White background
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, c.width, c.height);

      // Diagonal line — exercises sub-pixel anti-aliasing
      ctx.lineWidth = 1.5;
      ctx.strokeStyle = "#000000";
      ctx.beginPath();
      ctx.moveTo(100, 100);
      ctx.lineTo(500, 200);
      ctx.stroke();

      // Circle — exercises arc rasterisation
      ctx.beginPath();
      ctx.arc(300, 150, 40, 0, Math.PI * 2);
      ctx.stroke();

      // Large text — exercises font rendering / hinting (biggest diff on WebKit)
      ctx.font = "32px Arial";
      ctx.fillStyle = "#000000";
      ctx.fillText("CONSISTENCY_TEST", 100, 300);

      // Read ALL pixel bytes
      var pixels = ctx.getImageData(0, 0, c.width, c.height).data; // Uint8ClampedArray

      // FNV-1a over the full pixel buffer → stable 32-bit unsigned int
      var checksum = fnv1aBytes(pixels);

      return String(checksum); // e.g. "2847193056"
    } catch (e) { return "na"; }
  }

  // ---- WebGL renderer ----
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

  // ---- audio fingerprint ----
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

  // ---- Battery API ----
  function batteryFP() {
    return new Promise(function (resolve) {
      try {
        if (!navigator.getBattery) return resolve("na");
        navigator.getBattery().then(function (b) {
          resolve([
            b.charging ? 1 : 0,
            Math.round(b.level * 100),
            isFinite(b.chargingTime) ? Math.round(b.chargingTime / 60) : "inf",
            isFinite(b.dischargingTime) ? Math.round(b.dischargingTime / 60) : "inf"
          ].join(":"));
        }).catch(function () { resolve("na"); });
      } catch (e) { resolve("na"); }
    });
  }

  // ---- Network Information API ----
  function networkInfo() {
    try {
      var c = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
      if (!c) return "na";
      return [
        c.effectiveType || "na",
        c.type || "na",
        c.rtt !== undefined ? c.rtt : "na",
        c.downlink !== undefined ? c.downlink : "na",
        c.saveData ? 1 : 0
      ].join("|");
    } catch (e) { return "na"; }
  }

  // ---- Media codec support matrix ----
  function codecsFP() {
    try {
      var v = document.createElement("video");
      var a = document.createElement("audio");
      function vc(t) { try { return v.canPlayType(t) || "na"; } catch (e) { return "na"; } }
      function ac(t) { try { return a.canPlayType(t) || "na"; } catch (e) { return "na"; } }
      var bits = [
        vc('video/mp4; codecs="avc1.42E01E"'),
        vc('video/mp4; codecs="avc1.640028"'),
        vc('video/mp4; codecs="hev1.1.6.L93.B0"'),
        vc('video/webm; codecs="vp8"'),
        vc('video/webm; codecs="vp9"'),
        vc('video/webm; codecs="vp09.00.10.08"'),
        vc('video/webm; codecs="av01.0.08M.08"'),
        vc('video/ogg; codecs="theora"'),
        ac('audio/mp4; codecs="mp4a.40.2"'),
        ac('audio/mp4; codecs="mp4a.40.5"'),
        ac('audio/mp4; codecs="mp4a.69"'),
        ac('audio/mpeg'),
        ac('audio/ogg; codecs="vorbis"'),
        ac('audio/ogg; codecs="opus"'),
        ac('audio/wav; codecs="1"'),
        ac('audio/flac'),
        ac('audio/webm; codecs="opus"')
      ].join(",");
      return fnv1a(bits) + ":" + bits.length;
    } catch (e) { return "na"; }
  }

  // ---- MediaCapabilities ----
  function mediaCapsFP() {
    return new Promise(function (resolve) {
      try {
        if (!navigator.mediaCapabilities || !navigator.mediaCapabilities.decodingInfo) return resolve("na");
        var configs = [
          { type: "file", video: { contentType: 'video/mp4; codecs="avc1.42E01E"', width: 1920, height: 1080, bitrate: 4000000, framerate: 30 } },
          { type: "file", video: { contentType: 'video/webm; codecs="vp9"', width: 3840, height: 2160, bitrate: 20000000, framerate: 60 } },
          { type: "file", video: { contentType: 'video/webm; codecs="av01.0.08M.08"', width: 1920, height: 1080, bitrate: 4000000, framerate: 30 } }
        ];
        Promise.all(configs.map(function (cfg) {
          return navigator.mediaCapabilities.decodingInfo(cfg)
            .then(function (r) { return [r.supported ? 1 : 0, r.smooth ? 1 : 0, r.powerEfficient ? 1 : 0].join(""); })
            .catch(function () { return "na"; });
        })).then(function (results) { resolve(results.join("|")); }).catch(function () { resolve("na"); });
      } catch (e) { resolve("na"); }
    });
  }

  // ---- CSS media query precision signals ----
  function cssMQFP() {
    try {
      var dprExact = "na";
      try {
        var lo = 0.5, hi = 4.0, mid;
        for (var i = 0; i < 7; i++) {
          mid = Math.round((lo + hi) / 2 * 20) / 20;
          if (window.matchMedia("(min-resolution: " + mid + "dppx)").matches) lo = mid;
          else hi = mid;
        }
        dprExact = lo.toFixed(2);
      } catch (e) {}

      return [
        dprExact,
        mq("(pointer: fine)"),
        mq("(pointer: coarse)"),
        mq("(any-pointer: fine)"),
        mq("(hover: hover)"),
        mq("(any-hover: hover)"),
        mq("(forced-colors: active)"),
        mq("(inverted-colors: inverted)"),
        mq("(prefers-contrast: more)"),
        mq("(prefers-reduced-transparency: reduce)"),
        mq("(update: fast)"),
        mq("(update: slow)"),
        mq("(overflow-block: scroll)"),
        mq("(color-gamut: rec2020)"),
        mq("(color-gamut: p3)"),
        mq("(color-gamut: srgb)")
      ].join(",");
    } catch (e) { return "na"; }
  }

  // ---- Exact screen resolution via matchMedia ----
  function screenMQFP() {
    try {
      function findVal(prop, lo, hi) {
        for (var i = 0; i < 12; i++) {
          var mid = Math.floor((lo + hi) / 2);
          if (window.matchMedia("(" + prop + ": " + mid + "px)").matches) return mid;
          if (window.matchMedia("(min-" + prop + ": " + mid + "px)").matches) lo = mid + 1;
          else hi = mid - 1;
        }
        return lo;
      }
      return findVal("device-width", 200, 7680) + "x" + findVal("device-height", 200, 4320);
    } catch (e) { return "na"; }
  }

  // ---- Gamepad ----
  function gamepadFP() {
    try {
      if (!navigator.getGamepads) return "na";
      var gps = navigator.getGamepads();
      var connected = 0, haptic = 0;
      for (var i = 0; i < gps.length; i++) {
        if (gps[i]) {
          connected++;
          if (gps[i].hapticActuators && gps[i].hapticActuators.length) haptic++;
        }
      }
      return connected + ":" + haptic;
    } catch (e) { return "na"; }
  }

  // ---- MIDI ----
  function midiFP() {
    return new Promise(function (resolve) {
      try {
        if (!navigator.requestMIDIAccess) return resolve("na");
        var done = false;
        var timer = setTimeout(function () { if (!done) { done = true; resolve("na"); } }, 400);
        navigator.requestMIDIAccess().then(function (m) {
          if (done) return; done = true; clearTimeout(timer);
          var inputs = [], outputs = [];
          m.inputs.forEach(function (p) { inputs.push(p.manufacturer || "?"); });
          m.outputs.forEach(function (p) { outputs.push(p.manufacturer || "?"); });
          resolve(fnv1a(inputs.sort().join(",") + "|" + outputs.sort().join(",")) +
            ":" + inputs.length + ":" + outputs.length);
        }).catch(function () { if (!done) { done = true; clearTimeout(timer); resolve("denied"); } });
      } catch (e) { resolve("na"); }
    });
  }

  // ---- Permissions ----
  function permissionsFP() {
    return new Promise(function (resolve) {
      try {
        if (!navigator.permissions || !navigator.permissions.query) return resolve("na");
        var names = ["camera", "microphone", "notifications", "geolocation",
                     "accelerometer", "gyroscope", "magnetometer"];
        Promise.all(names.map(function (name) {
          return navigator.permissions.query({ name: name })
            .then(function (r) { return r.state ? r.state[0] : "?"; })
            .catch(function () { return "n"; });
        })).then(function (states) { resolve(states.join("")); })
          .catch(function () { resolve("na"); });
      } catch (e) { resolve("na"); }
    });
  }

  // ---- WebRTC local IP hash ----
  function webrtcFP() {
    return new Promise(function (resolve) {
      try {
        var RTC = window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection;
        if (!RTC) return resolve("na");
        var ips = [];
        var done = false;
        var timer = setTimeout(function () {
          if (!done) { done = true; pc.close(); resolve(ips.length ? fnv1a(ips.sort().join(",")) : "na"); }
        }, 600);
        var pc = new RTC({ iceServers: [] });
        pc.createDataChannel("");
        pc.onicecandidate = function (e) {
          if (!e || !e.candidate || !e.candidate.candidate) return;
          var m = e.candidate.candidate.match(/(\d{1,3}\.){3}\d{1,3}|[0-9a-f]{1,4}(:[0-9a-f]{0,4}){2,7}/i);
          if (m && ips.indexOf(m[0]) === -1) ips.push(m[0]);
        };
        pc.onicegatheringstatechange = function () {
          if (pc.iceGatheringState === "complete" && !done) {
            done = true; clearTimeout(timer); pc.close();
            resolve(ips.length ? fnv1a(ips.sort().join(",")) : "na");
          }
        };
        pc.createOffer().then(function (offer) { return pc.setLocalDescription(offer); }).catch(function () {
          if (!done) { done = true; clearTimeout(timer); resolve("na"); }
        });
      } catch (e) { resolve("na"); }
    });
  }

  // ---- Performance timing entropy ----
  function perfTimingFP() {
    try {
      if (!window.performance || !performance.now) return "na";
      var samples = [];
      var t0 = performance.now();
      for (var i = 0; i < 20; i++) {
        var t = performance.now();
        samples.push(Math.round((t - t0) * 1000));
        t0 = t;
      }
      var navTiming = "na";
      try {
        var nt = performance.getEntriesByType("navigation")[0] ||
                 (performance.timing ? {
                   domainLookupEnd: performance.timing.domainLookupEnd,
                   domainLookupStart: performance.timing.domainLookupStart,
                   connectEnd: performance.timing.connectEnd,
                   connectStart: performance.timing.connectStart,
                   responseEnd: performance.timing.responseEnd,
                   responseStart: performance.timing.responseStart
                 } : null);
        if (nt) {
          navTiming = [
            Math.round(nt.domainLookupEnd - nt.domainLookupStart),
            Math.round(nt.connectEnd - nt.connectStart),
            Math.round(nt.responseEnd - nt.responseStart)
          ].join(":");
        }
      } catch (e) {}
      return fnv1a(samples.join(",")) + "|" + navTiming;
    } catch (e) { return "na"; }
  }

  // ---- WebGL2 shader precision ----
  function webgl2FP() {
    try {
      var c = document.createElement("canvas");
      var gl = c.getContext("webgl2");
      if (!gl) return "na";
      var prec = [];
      var shaderTypes = [gl.VERTEX_SHADER, gl.FRAGMENT_SHADER];
      var precTypes = [gl.LOW_FLOAT, gl.MEDIUM_FLOAT, gl.HIGH_FLOAT, gl.LOW_INT, gl.MEDIUM_INT, gl.HIGH_INT];
      for (var si = 0; si < shaderTypes.length; si++) {
        for (var pi = 0; pi < precTypes.length; pi++) {
          try {
            var f = gl.getShaderPrecisionFormat(shaderTypes[si], precTypes[pi]);
            if (f) prec.push(f.rangeMin + "," + f.rangeMax + "," + f.precision);
          } catch (e) { prec.push("e"); }
        }
      }
      var aniso = "na";
      try {
        var extA = gl.getExtension("EXT_texture_filter_anisotropic") ||
                   gl.getExtension("WEBKIT_EXT_texture_filter_anisotropic");
        if (extA) aniso = gl.getParameter(extA.MAX_TEXTURE_MAX_ANISOTROPY_EXT);
      } catch (e) {}
      return fnv1a(prec.join("|")) + ":" + aniso;
    } catch (e) { return "na"; }
  }

  // ---- CSS feature detection ----
  function cssFeaturesFP() {
    try {
      if (!window.CSS || !CSS.supports) return "na";
      var checks = [
        "display:grid",
        "display:subgrid",
        "(display:masonry)",
        "content-visibility:auto",
        "contain:layout",
        "container-type:inline-size",
        "backdrop-filter:blur(1px)",
        "-webkit-backdrop-filter:blur(1px)",
        "color:oklch(50% 0.2 270)",
        "color:color(display-p3 1 0 0)",
        "font-variant-alternates:stylistic(a)",
        "animation-timeline:scroll()",
        "overscroll-behavior:contain",
        "text-decoration-thickness:auto",
        "accent-color:auto",
        "(transform-style:preserve-3d) and (perspective:1px)"
      ];
      return checks.map(function (q) {
        try { return CSS.supports(q) ? 1 : 0; } catch (e) { return 0; }
      }).join("");
    } catch (e) { return "na"; }
  }

  // ---- Math JIT fingerprint ----
  function mathFP() {
    try {
      var v = [
        Math.tan(-1e300), Math.sin(Math.PI),
        Math.cos(1e300),  Math.atan(2),
        Math.atan2(-0, -0), Math.exp(1),
        Math.log(1 + 1e-10), Math.sinh(1),
        Math.cosh(0.000001), Math.tanh(0.5)
      ].map(function (x) { return isFinite(x) ? x.toFixed(15) : String(x); }).join(",");
      return fnv1a(v);
    } catch (e) { return "na"; }
  }

  // ---- Intl / locale depth ----
  function intlFP() {
    try {
      var results = [];
      try { results.push(Intl.supportedValuesOf("calendar").length); } catch (e) { results.push("na"); }
      try { results.push(Intl.supportedValuesOf("currency").length); } catch (e) { results.push("na"); }
      try { results.push(new Intl.NumberFormat().format(1000000)); } catch (e) { results.push("na"); }
      try {
        var hour = new Intl.DateTimeFormat([], { hour: "numeric" }).format(new Date(2000, 0, 1, 13));
        results.push(/pm|am/i.test(hour) ? "12h" : "24h");
      } catch (e) { results.push("na"); }
      try {
        var col = new Intl.Collator();
        results.push(col.compare("a", "b") < 0 ? 1 : 0);
      } catch (e) { results.push("na"); }
      return fnv1a(results.join("|"));
    } catch (e) { return "na"; }
  }

  // ---- Hardware sensors ----
  function sensorsFP() {
    return new Promise(function (resolve) {
      try {
        var detected = [];
        var checks = [
          ["Accelerometer", "acc"],
          ["Gyroscope", "gyro"],
          ["LinearAccelerationSensor", "lin"],
          ["AbsoluteOrientationSensor", "abs"],
          ["RelativeOrientationSensor", "rel"],
          ["AmbientLightSensor", "als"],
          ["Magnetometer", "mag"]
        ];
        var pending = checks.length;
        checks.forEach(function (pair) {
          try {
            if (!(pair[0] in window)) { pending--; if (!pending) done(); return; }
            var s = new window[pair[0]]({ frequency: 1 });
            s.onerror = function () { pending--; if (!pending) done(); };
            s.onreading = function () { detected.push(pair[1]); s.stop(); pending--; if (!pending) done(); };
            s.start();
            setTimeout(function () { try { s.stop(); } catch (e) {} }, 200);
          } catch (e) {
            if (e.name === "NotAllowedError") detected.push(pair[1] + "?");
            pending--; if (!pending) done();
          }
        });
        var timer = setTimeout(function () { resolve(detected.sort().join(",") || "none"); }, 500);
        function done() { clearTimeout(timer); resolve(detected.sort().join(",") || "none"); }
      } catch (e) { resolve("na"); }
    });
  }

  // ---- collect all signals ----
  function collect() {
    var wg = webglFP();
    return Promise.all([
      audioFP(),
      storageQuota(),
      getKeyId(),
      speechVoices(),
      batteryFP(),
      mediaCapsFP(),
      midiFP(),
      permissionsFP(),
      webrtcFP(),
      sensorsFP()
    ]).then(function (arr) {
      var audio = arr[0], quota = arr[1], keyId = arr[2], voices = arr[3],
          battery = arr[4], mediaCaps = arr[5], midi = arr[6],
          perms = arr[7], rtcIP = arr[8], sensors = arr[9];

      var io = {};
      try { io = Intl.DateTimeFormat().resolvedOptions(); } catch (e) {}

      return {
        // ---------------------------------------------------------------
        // Canvas: pixel-level FNV-1a checksum (Safari-stable)
        // Replaces old toDataURL()-based hash. Same device/browser/OS
        // always yields the same 32-bit unsigned integer string.
        // ---------------------------------------------------------------
        canvas: canvasFP(),

        // --- other stable, cross-site fingerprint signals ---
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
        dark: mq("(prefers-color-scheme: dark)"),
        motion: mq("(prefers-reduced-motion: reduce)"),
        gamut: mq("(color-gamut: p3)"),
        hdr: mq("(dynamic-range: high)"),

        // --- per-unit signals ---
        keyId: keyId,
        quota: quota,
        nonce: getNonce(),
        ua: navigator.userAgent || "",

        // --- hardware ---
        battery: battery,
        gamepads: gamepadFP(),
        midi: midi,
        sensors: sensors,
        webgl2: webgl2FP(),

        // --- network / HTTP-adjacent ---
        netInfo: networkInfo(),
        rtcIP: rtcIP,
        onLine: navigator.onLine ? 1 : 0,

        // --- codec & media capabilities ---
        codecs: codecsFP(),
        mediaCaps: mediaCaps,

        // --- CSS / display precision ---
        cssMQ: cssMQFP(),
        screenMQ: screenMQFP(),

        // --- performance / timing ---
        perfTiming: perfTimingFP(),

        // --- JS engine math fingerprint ---
        mathFP: mathFP(),

        // --- permissions state ---
        perms: perms,

        // --- locale / Intl depth ---
        intlFP: intlFP(),

        // --- CSS feature support bitfield ---
        cssFeatures: cssFeaturesFP()
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
  iDx.reacquire = function () {
    iDx._started = false;
    iDx.id = null;
    iDx._id = null;
    start();
  };

  setTimeout(start, 0);
})();
