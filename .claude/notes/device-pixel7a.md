---
name: device-pixel7a
description: Google Pixel 7a (lynx) — ROOTED research device. Verified ADB facts, root capabilities, and the root-enabled capture approach that replaces the hotspot/proxy workarounds.
---

# Device: Google Pixel 7a (lynx) — ROOTED

This is the primary research device. Root removes the constraints that shaped
the rest of the project. See [[device-s24plus]] and [[device-cph2515]] for the
non-rooted devices.

## Identity

- ADB serial: `35181JEHN08662`
- Codename: `lynx`, SoC: GS201 (Tensor G2)
- Android 17, SDK 37, build `user` (release-keys)
- Fingerprint: `google/lynx/lynx:17/CP2A.260605.012/15430684:user/release-keys`
- Security patch: 2026-06-05

## Root

- Manager: **Magisk v30.7** (`magisk -V` → 30700)
- su provider: **MagiskSU** at `/system_ext/bin/su`
- SELinux: **Enforcing**
- **GRANT REQUIRED:** ADB shell su returns `Permission denied` until Magisk
  authorizes the shell. In the Magisk app → Superuser, set the shell/ADB
  request to Grant (or approve the on-device prompt when `adb shell su -c id`
  runs). Verify with: `adb shell "su -c id"` → expect `uid=0(root)`.

## eUICC status

- `Euicc enabled=true` — working eUICC hardware
- LPA: **AOSP** `com.android.euicc.service.EuiccServiceImpl`
  (`euicc_card_controller` mBestComponent resolves — unlike Samsung's
  proprietary service on [[device-s24plus]]). `esim eid` should work here.
- MEP supported: `android.hardware.telephony.euicc.mep`
- **0 profiles provisioned** — clean slate. Ideal for capturing a full fresh
  download (ES9+ transport + ES8+ BPP), the richest RSP exchange.

## What root unlocks vs the non-rooted devices

| Capability | Non-rooted (S24+/CPH2515) | Rooted Pixel 7a |
|------------|---------------------------|-----------------|
| System-trusted CA cert | No (user cert only; many apps ignore) | **Yes** — install into APEX conscrypt store |
| Global proxy without per-Wi-Fi config | No | **Yes** — `settings put global http_proxy` |
| On-device traffic redirect | No | **Yes** — `iptables` REDIRECT to local/remote mitmproxy |
| EID via ADB | No (scrubbed / Samsung) | Likely (AOSP `euicc_card_controller`) |
| Frida hooking of LPA | No | **Yes** — push frida-server |
| Raw APDU capture | No (scrubbed on user builds) | Possible via LPA/RIL hooks (needs investigation) |
| ES8+ BPP plaintext | No (keys in SE) | Still likely NO — profile keys live in the eUICC secure element, not extractable even with root. TLS-layer decryption (ES9+) is what root gives us. |

## Current direction (2026-06-27): passive LPA observation, not MITM

We own the device and have root, so the plan is to **read the LPA's plaintext
RSP messages directly** from `com.google.android.euicc` (ES9+/ES11 are built and
TLS-encrypted in software — root reaches the plaintext before/after TLS). This
is observation, not interception. ES8+ BPP stays opaque (secure element).

The MITM pipeline below is **torn down** (system cert umounted, proxy unset,
tunnel removed, device tmp cleaned) and kept documented for later MITM testing.
A reboot clears any residual per-process cert mounts.

## MITM capture pipeline — works, currently torn down (2026-06-27)

The hotspot/UFW/per-Wi-Fi-proxy struggle is gone. The setup uses an
**adb-reverse USB tunnel** plus a **system-trusted CA cert**. No firewall
changes, no hotspot, no LAN reachability needed. One command:
`scripts/setup/setup_capture_pixel7a.sh`. Re-run it when MITM testing resumes.

Chain (all three verified end to end):
1. `adb reverse tcp:8083 tcp:8083` — device `127.0.0.1:8083` → laptop mitmproxy.
2. `settings put global http_proxy 127.0.0.1:8083` — routes app traffic into the
   tunnel. Takes a few seconds + a network re-eval to take effect.
3. CA cert installed into the conscrypt APEX store via `tools/install_system_cert.sh`
   (bind-mounts a cert dir into the global ns + each zygote + running
   system_server/phone/euicc/settings/chrome namespaces). TLS is decrypted —
   confirmed by capturing plaintext `POST update.googleapis.com`.

Verified facts during setup:
- mitmproxy CA hash (subject_hash_old): `c8750f0d` → installed as `c8750f0d.0`.
- `nsenter` at `/system/bin/nsenter`; Magisk busybox also has it.
- Cert SELinux context: `u:object_r:system_security_cacerts_file:s0`.
- Use port **8083** (8081 is held by an unrelated `node` process on the laptop).
- Phone Wi-Fi `GreatThinkers` 10.0.0.76; laptop 10.0.0.127. Phone→laptop LAN
  on 8083 **times out** (UFW or AP client isolation) — the reason the USB
  tunnel approach wins.

### Teardown (IMPORTANT)

While the global proxy points at `127.0.0.1:8083`, the phone has internet ONLY
while mitmproxy + the reverse tunnel are up. Before disconnecting, restore it:

```
adb -s 35181JEHN08662 shell "su -c 'settings delete global http_proxy'"
adb -s 35181JEHN08662 reverse --remove tcp:8083
```

The system cert bind-mounts are not persistent — they vanish on reboot (re-run
the installer after a reboot).

### RSP capture finding (2026-06-27) — RSP pins to GSMA CI roots

SM-DS discovery was triggered via `am start -a
android.telephony.euicc.action.PROVISION_EMBEDDED_SUBSCRIPTION` (stops at
`SimMissingActivity`, but `ProfileDiscoverySidecar` fires regardless). Result:

- The LPA queries the root SM-DS at **`lpa.ds.gsma.com`**, path
  `/gsma/rsp2/es9plus/initiateAuthentication`. Root SM-DS address comes from
  `EsimActivation.rootSmdsAddressList` (settings `default_sm_dp_plus_address` is null).
- The connection **goes through the proxy** (mitmproxy logged `server connect
  lpa.ds.gsma.com:443`). The LPA honors the global proxy.
- The LPA **rejected mitmproxy's cert**: `SSLHandshakeException:
  CertPathValidatorException: Trust anchor for certification path not found`.
  RSP (SGP.22) validates the SM-DS/SM-DP+ server cert against **GSMA CI roots**,
  not the Android system store. A system CA cert CANNOT MITM RSP TLS — by
  design, independent of root.
- mitmproxy also can't verify the real server upstream (`unable to get local
  issuer certificate`) — GSMA CI roots aren't in the system bundle. Run with
  `--ssl-insecure` so the upstream leg succeeds once the client is unpinned.

Proof the cert install itself works: `GET https://www.gstatic.com/esim/icons/verizon-logo.png
<< 200 OK` decrypted fine. Non-pinning HTTPS is intercepted; pinned endpoints
(RSP, and Google's own `*.googleapis.com`/`accounts.google.com`) are not.

### Frida observation (2026-06-27) — works; blocked on a fresh trigger

Pivoted from MITM to **passive observation**: read the LPA's plaintext RSP at
the application layer (we own the device, TLS is software). Tools in
`scripts/frida/` (`conscrypt_dump.js` robust TLS-layer capture, `rsp_observe.js`
named-method hook, `README.md`). frida-server 17.8.3 (arm64) pushed to
`/data/local/tmp/frida-server`, runs as root.

Confirmed:
- RSP client classes are **un-obfuscated**: `com.android.euicc.smdp.SmdxApiImplV2`
  (`.sendRequest(String path, JSONObject body)`), `SmdxClient`,
  `ProfileDownloadTransaction`. conscrypt TLS streams
  (`ConscryptEngineSocket$SSL{In,Out}putStream`) hook cleanly.
- Discovery runs in `com.google.android.euicc` (logcat:
  `requestEuiccChallenge → authenticateServer` to `lpa.ds.gsma.com`).

Blocker — **the trigger, not the hook**: SM-DS discovery is throttled and there
are 0 profiles for this EID, so after one query it serves a cached "nothing
found" and won't re-query on demand. `rsp_observe.js`'s named hook also may miss
due to ART JIT inlining — use `conscrypt_dump.js`.

Reliable triggers for a future session: an **activation-code download**
(fresh un-throttled ES9+ every time) or a **reboot** (boot-time discovery ~12s
in, per JobScheduler history).

Frida gotchas: frida 17 raw Python `create_script` has no Java bridge — use the
`frida` CLI. `frida -q` exits on stdin EOF — keep it resident
(`tail -f /dev/null | frida ...`) or run trigger+capture in one shell call.

### Wi-Fi "connected, no internet" — root cause + fix (2026-06-27, RESOLVED)

Two compounding bugs, both from the capture teardown:

1. **Leftover proxy.** `settings delete global http_proxy` only clears the combined
   key. The system actually uses `global_http_proxy_host` / `global_http_proxy_port`,
   which were still `127.0.0.1:8083` (dead tunnel) — so every app + the
   connectivity-validation probe failed. Fix: delete all proxy keys:
   ```
   settings delete global http_proxy
   settings delete global global_http_proxy_host
   settings delete global global_http_proxy_port
   settings delete global global_http_proxy_exclusion_list
   settings delete global global_proxy_pac_url
   ```
2. **Network permanently disabled.** Repeated no-internet (from the proxy) made
   Android mark `GreatThinkers` `NETWORK_SELECTION_DISABLED_NO_INTERNET_PERMANENT`
   — it refused to auto-join even with strong signal. Normally cleared by the user
   tapping the network; device was locked, so fixed via root in
   `/data/misc/apexdata/com.android.wifi/WifiConfigStore.xml`:
   set `SelectionStatus`→`NETWORK_SELECTION_ENABLED`,
   `DisableReason`→`NETWORK_SELECTION_ENABLE`, then `chattr +i` (so the shutdown
   flush can't revert it), reboot, `chattr -i`, `svc wifi enable`.

Lessons: (a) clearing the global proxy means clearing the host/port keys, not just
`http_proxy`; (b) **do not** use `svc wifi disable/enable` or airplane toggling on
this device to force discovery — it destabilizes association and, combined with a
dead proxy, triggers the permanent-disable. Verified fixed: VALIDATED, ping 0% loss.

## OpenEUICC (open-source LPA) — built + installed privileged (2026-06-27)

Built from source and installed as a privileged system app so we have a hackable
LPA for experiments. Source: `../OpenEUICC` (sibling of this repo), cloned from
`https://gitea.angry.im/PeterCxy/OpenEUICC` + submodules (`lpac` v2.3.0, cJSON).

Build recipe (laptop has JDK 21, SDK at `/opt/android-sdk`):
- Installed exact toolchain: NDK `26.1.10909125` (pinned by `libs/lpac-jni`) + platform `android-35`.
- `local.properties` → `sdk.dir=/opt/android-sdk`; generated `openeuicc-research.jks` + `keystore.properties`.
- `./gradlew :app:assembleDebugMagiskModuleDir` → `app/build/magisk/debug/` (module dir).
- Zipped → `../OpenEUICC/openeuicc-magisk-debug.zip`, installed `magisk --install-module`, reboot.

Result:
- Package `im.angry.openeuicc`, `privateFlags=[ PRIVILEGED SYSTEM_EXT ]`, perms granted:
  `WRITE_EMBEDDED_SUBSCRIPTIONS`, `SECURE_ELEMENT_PRIVILEGED_OPERATION`,
  `READ_PRIVILEGED_PHONE_STATE`, `MODIFY_PHONE_STATE`.
- Launcher: `im.angry.openeuicc/.ui.PrivilegedMainActivity`.
- **Privileged APDU access works**: OMAPI to the internal ISD-R is blocked (expected),
  but the telephony `TransmitApduLogicalChannel` path opens and returns `0x9000`.
- **Fully working when unlocked.** The "channel invalid ... aborting" abort only
  happens while the device is **locked** — telephony APDU access for a non-default
  LPA is gated behind the keyguard. Unlock + open OpenEUICC and it enumerates the
  internal eUICC cleanly: UI shows "No profiles (yet) on this eSIM" and "MEP is
  supported by this slot" (a successful EID + profile-list + capability read). It
  exposes a Slot Mapping tool and a "+" to download/add profiles. **Lesson: drive
  OpenEUICC with the device unlocked.**

## Verified ADB commands (no root needed)

- `dumpsys isub` → eUICC enabled, subscription list (currently empty)
- `dumpsys euicc_card_controller` → AOSP LPA component resolves
- `pm list features | grep euicc` → euicc + euicc.mep present
- `ls /apex/com.android.conscrypt/cacerts/` → system cert store present

## Paths worth remembering

- System CA store (Android 14+): `/apex/com.android.conscrypt/cacerts/`
- Legacy CA store: `/system/etc/security/cacerts/`
- su: `/system_ext/bin/su`, magisk: `/system_ext/bin/magisk`
- iptables: `/system/bin/iptables`
