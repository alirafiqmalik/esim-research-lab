# Frida RSP observation (rooted Pixel 7a)

Read the LPA's plaintext ES9+/ES11 RSP messages directly from
`com.google.android.euicc` — no MITM. We own the device and have root, so the
TLS happens in software (okhttp/conscrypt) and the plaintext is in-process.
ES8+ BPP stays opaque (encrypted to the eUICC secure element).

## Setup

```bash
# match frida-server to the laptop's frida version (here 17.8.3), arm64
adb -s 35181JEHN08662 push frida-server /data/local/tmp/frida-server
adb -s 35181JEHN08662 shell "su -c 'chmod 755 /data/local/tmp/frida-server; nohup /data/local/tmp/frida-server >/dev/null 2>&1 &'"
frida-ps -U | grep euicc   # com.google.android.euicc should appear
```

## Capture

```bash
# resident hook MUST stay attached while you trigger RSP traffic.
# run it in the SAME shell session as the trigger, or keep stdin open.
frida -U -n com.google.android.euicc -l conscrypt_dump.js --runtime=v8 -q
```

`conscrypt_dump.js` is the robust catch-all (TLS layer). `rsp_observe.js`
hooks the named RSP method `SmdxApiImplV2.sendRequest` but can miss due to ART
JIT inlining — prefer conscrypt_dump.

## Triggering RSP traffic

- SM-DS discovery (`am start -a android.telephony.euicc.action.PROVISION_EMBEDDED_SUBSCRIPTION`)
  is **throttled** and returns nothing when no profiles wait for the EID. Not
  reliable on demand.
- An **activation code download** runs a fresh, un-throttled ES9+ exchange every
  time — the reliable trigger. Even a throwaway code yields initiateAuthentication
  + the SM-DP+ response before it fails.

## Gotchas found

- frida 17 raw Python `create_script` lacks the Java bridge ("Java is not
  defined"). Use the `frida` CLI (bundles the bridge), not a bare Python driver.
- `frida ... -q` exits when stdin closes (background/no-tty). Keep it resident:
  `tail -f /dev/null | frida ...`, or run trigger + capture in one shell call.
- The RSP client classes are un-obfuscated: `com.android.euicc.smdp.SmdxApiImplV2`,
  `SmdxClient`, `ProfileDownloadTransaction`.
