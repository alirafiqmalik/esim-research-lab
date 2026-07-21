// Observe eSIM RSP (ES9+/ES11) plaintext at the LPA application layer.
// Hooks the Google LPA's non-obfuscated RSP client. No MITM — reads the
// software's own buffers before TLS. Target: com.google.android.euicc
//
//   frida -U -n com.google.android.euicc -l rsp_observe.js --runtime=v8 -q
//
// SmdxApiImplV2.sendRequest(String path, JSONObject body) is the ES9+/ES11
// HTTP sender. NOTE: in testing this hook sometimes did not fire (likely ART
// JIT inlining); conscrypt_dump.js is the robust fallback that catches the
// same traffic at the TLS layer.
Java.perform(function () {
  var Api = Java.use("com.android.euicc.smdp.SmdxApiImplV2");
  var n = 0;
  function wrap(methodName) {
    if (!Api[methodName]) return;
    Api[methodName].overloads.forEach(function (ov) {
      ov.implementation = function (path, body) {
        n++;
        console.log("\n========== RSP[" + n + "] " + methodName + " REQUEST ==========");
        console.log("path: " + path);
        try { console.log("body: " + (body ? body.toString() : "(null)")); } catch (e) { console.log("body err: " + e); }
        var res = ov.apply(this, arguments);
        console.log("---------- RSP[" + n + "] RESPONSE ----------");
        try { console.log("resp: " + (res ? res.toString() : "(null)")); } catch (e) { console.log("resp err: " + e); }
        console.log("==================================\n");
        return res;
      };
    });
  }
  wrap("sendRequest");
  wrap("sendRequestInternal");
  console.log("[hook installed] sendRequest+sendRequestInternal");
});
