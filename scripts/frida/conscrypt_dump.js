// Robust RSP plaintext capture: dump conscrypt TLS app-data in the LPA process.
// Catches ES9+/ES11 HTTP regardless of which client sends it, before encryption.
// No MITM — reads the device's own TLS buffers. Target: com.google.android.euicc
//
//   frida -U -n com.google.android.euicc -l conscrypt_dump.js --runtime=v8 -q
//
// Filtered to RSP/eSIM traffic by the `re` regex below. Widen it to capture more.
Java.perform(function () {
  var JStr = Java.use("java.lang.String");
  var re = /gsma|es9plus|es11|initiateAuth|authenticateClient|getBoundProfile|euiccChallenge|smdp|smds|rsp2|euiccInfo|matchingId|profileMetadata|HTTP\//i;
  function toStr(buf, off, len) { try { return JStr.$new(buf, off, len, "ISO-8859-1"); } catch (e) { return "<conv>"; } }
  function hookStream(cls, dir) {
    try {
      var C = Java.use(cls);
      if (dir === "out") {
        C.write.overload('[B', 'int', 'int').implementation = function (b, o, l) {
          if (l > 0) { var s = toStr(b, o, l); if (re.test(s)) console.log("\n>>> TLS OUT [" + cls.replace(/.*\$/, '') + "] " + l + "B >>>\n" + s + "\n>>>"); }
          return this.write(b, o, l);
        };
      } else {
        C.read.overload('[B', 'int', 'int').implementation = function (b, o, l) {
          var r = this.read(b, o, l);
          if (r > 0) { var s = toStr(b, o, r); if (re.test(s)) console.log("\n<<< TLS IN [" + cls.replace(/.*\$/, '') + "] " + r + "B <<<\n" + s + "\n<<<"); }
          return r;
        };
      }
      console.log("[hooked] " + cls + " (" + dir + ")");
    } catch (e) { console.log("[skip] " + cls + ": " + e); }
  }
  hookStream("com.android.org.conscrypt.ConscryptEngineSocket$SSLOutputStream", "out");
  hookStream("com.android.org.conscrypt.ConscryptEngineSocket$SSLInputStream", "in");
  hookStream("com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream", "out");
  hookStream("com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLInputStream", "in");
  console.log("[conscrypt dump ready]");
});
