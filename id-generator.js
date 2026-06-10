(function () {
  "use strict";

  // ---- FNV-1a over raw Uint8Array (Aapka exact checksum logic) ----
  function getChecksum(bytes) {
    var checksum = 2166136261;
    for (var i = 0; i < bytes.length; i++) {
      checksum ^= bytes[i];
      checksum +=
        (checksum << 1) +
        (checksum << 4) +
        (checksum << 7) +
        (checksum << 8) +
        (checksum << 24);
    }
    return checksum >>> 0;
  }

  // ---- Canvas create aur render karna ----
  function generateId() {
    try {
      var c = document.createElement("canvas");
      c.width = 800; c.height = 400;
      var ctx = c.getContext("2d");

      // Background
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, c.width, c.height);

      // Elements
      ctx.lineWidth = 1.5;
      ctx.strokeStyle = "#000";

      ctx.beginPath();
      ctx.moveTo(100, 100);
      ctx.lineTo(500, 200);
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(300, 150, 40, 0, Math.PI * 2);
      ctx.stroke();

      ctx.font = "32px Arial";
      ctx.fillStyle = "#000";
      ctx.fillText("CONSISTENCY_TEST", 100, 300);

      // Get pixels and hash
      var pixels = ctx.getImageData(0, 0, c.width, c.height).data;
      return getChecksum(pixels);
    } catch (e) {
      return null;
    }
  }

  // Globally expose kar diya bina kisi object jhamela ke
  window.canvasChecksum = generateId();

  // Console me check karne ke liye
  console.log("Canvas ID Checksum:", window.canvasChecksum);
})();
