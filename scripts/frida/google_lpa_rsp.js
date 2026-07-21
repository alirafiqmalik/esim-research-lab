// Capture the STOCK Google LPA's eSIM RSP (ES9+) exchange in plaintext.
// The Google LPA has no verbose logging (unlike our OpenEUICC), so we instrument:
//   1. its RSP client com.android.euicc.smdp.SmdxApiImplV2.sendRequest (structured JSON)
//   2. the conscrypt TLS app-data streams (robust catch-all vs ART JIT-inlining)
// Target: com.google.android.euicc
//   tail -f /dev/null | frida -U -n com.google.android.euicc -l google_lpa_rsp.js --runtime=v8 -q
Java.perform(function () {
  var JStr = Java.use("java.lang.String");
  var n = 0;

  // 1. RSP client (structured request/response)
  try {
    var Api = Java.use("com.android.euicc.smdp.SmdxApiImplV2");
    ["sendRequest", "sendRequestInternal"].forEach(function (m) {
      if (!Api[m]) return;
      Api[m].overloads.forEach(function (ov) {
        ov.implementation = function (path, body) {
          n++;
          console.log("\n##RSP[" + n + "] " + m + " path=" + path);
          try { console.log("##REQ " + (body ? body.toString() : "(null)")); } catch (e) {}
          var r = ov.apply(this, arguments);
          try { console.log("##RESP " + (r ? r.toString() : "(null)")); } catch (e) {}
          return r;
        };
      });
    });
    console.log("[hooked SmdxApiImplV2]");
  } catch (e) { console.log("[SmdxApiImplV2 absent] " + e); }

  // 2. conscrypt TLS plaintext catch-all (filtered to RSP)
  var re = /gsma|es9plus|es11|initiateAuth|authenticateClient|getBoundProfile|euiccChallenge|smdp|rsp2|matchingId|transactionId|profileMetadata/i;
  function toStr(b, o, l) { try { return JStr.$new(b, o, l, "ISO-8859-1"); } catch (e) { return "<conv>"; } }
  [["com.android.org.conscrypt.ConscryptEngineSocket$SSLOutputStream", "out"],
   ["com.android.org.conscrypt.ConscryptEngineSocket$SSLInputStream", "in"],
   ["com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream", "out"],
   ["com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLInputStream", "in"]
  ].forEach(function (p) {
    try {
      var C = Java.use(p[0]);
      if (p[1] === "out") {
        C.write.overload('[B', 'int', 'int').implementation = function (b, o, l) {
          if (l > 0) { var s = toStr(b, o, l); if (re.test(s)) console.log("\n##TLS-OUT " + l + "B\n" + s); }
          return this.write(b, o, l);
        };
      } else {
        C.read.overload('[B', 'int', 'int').implementation = function (b, o, l) {
          var r = this.read(b, o, l);
          if (r > 0) { var s = toStr(b, o, r); if (re.test(s)) console.log("\n##TLS-IN " + r + "B\n" + s); }
          return r;
        };
      }
      console.log("[hooked " + p[0].replace(/.*\$/, '') + " " + p[1] + "]");
    } catch (e) {}
  });
  console.log("[google_lpa_rsp hooks installed]");
});
