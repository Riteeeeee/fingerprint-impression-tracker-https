/* ============================================================================
 * ntrx-shopify.js  —  cross-site identity (cookieless) for Shopify themes
 * ----------------------------------------------------------------------------
 * HOW TO USE (pick one):
 *   A) Paste the whole contents of this file into your theme's global.js.
 *   B) Upload as a theme asset and load it from layout/theme.liquid:
 *        {{ 'ntrx-shopify.js' | asset_url | script_tag }}
 *      ...or with a normal tag before </head>:
 *        <script src="{{ 'ntrx-shopify.js' | asset_url }}" defer></script>
 *
 * It is SILENT — no UI, no DOM/layout changes. It loads the fingerprint
 * client from the identity server, acquires a stable `ntrx_` id for this
 * browser (consistent across sites / sessions, no cookies), prints it to the
 * console ("ID: ntrx_..."), and exposes it as window.ntrxId + getNtrxId().
 * ============================================================================ */
(function () {
  "use strict";

  // The deployed identity server. Change only if you host it elsewhere.
  var NTRX_SRC = "https://fingerprint-impression-tracker-https.onrender.com/id-generator.js";

  /**
   * getNtrxId() -> Promise<string|null>
   * Loads the fingerprint client once and resolves with the id.
   * Safe to call any number of times, anywhere, on any page.
   */
  window.getNtrxId = function getNtrxId() {
    return new Promise(function (resolve) {
      // The id-generator exposes `iDx` and uses an immediate-fire setter, so
      // assigning onIdAquired works whether the id is ready now or later.
      function bind() {
        try { window.iDx.onIdAquired = function (id) { resolve(id); }; }
        catch (e) { resolve(null); }
      }

      if (window.iDx) return bind();                          // already loaded

      var tag = document.querySelector("script[data-ntrx]");
      if (tag) { tag.addEventListener("load", bind); return; } // load in flight

      tag = document.createElement("script");
      tag.src = NTRX_SRC;
      tag.async = true;
      tag.setAttribute("data-ntrx", "1");
      tag.onload = bind;
      tag.onerror = function () { resolve(null); };            // never block the store
      (document.head || document.documentElement).appendChild(tag);
    });
  };

  // Auto-acquire on every page load.
  window.getNtrxId().then(function (id) {
    if (!id) return;
    try { console.log("ID: " + id); } catch (e) {}            // required: print on console
    window.ntrxId = id;                                       // global, for convenience

    // --- OPTIONAL: forward the id to your own analytics / Shopify events ---
    // Google Tag Manager dataLayer:
    // window.dataLayer && window.dataLayer.push({ event: "ntrx_id", ntrx_id: id });
    //
    // Shopify customer event (custom pixel) — if you use one:
    // window.Shopify && Shopify.analytics && Shopify.analytics.publish &&
    //   Shopify.analytics.publish("ntrx_id", { id: id });
  });
})();
