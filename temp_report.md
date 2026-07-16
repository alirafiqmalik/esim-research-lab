> **SUPERSEDED (2026-07-16).** This document describes the pre-testbed **no-root /
> physical-SIM** scenario and is **obsolete**. The current work uses a **rooted
> (Magisk) Pixel 7a** with two disabled eSIM profiles and **no physical SIM**. Every
> "❌ Not possible" here (raw APDU capture, `EuiccCardManager` access, profile
> install) is now **done** on the rooted testbed. For the current state see
> `status-update.md` and `docs/euicc-api-frontier.md`. Kept for historical context only.

# eSIM RSP Interaction on a No-Root, ADB-Enabled Android Phone with Physical SIM and 5G

## Executive Summary

This report covers the full range of capabilities available for collecting, observing, and interacting with the eSIM (eUICC) system on a standard Android device without root access, using only ADB over USB and network-level tools. The device scenario is a retail Android phone with USB Debugging enabled, a physical SIM card active on Slot 1 with 5G access, and an embedded eUICC. The three RSP interfaces of interest — ES11 (Discovery), ES9+ (Transport), and ES8+ (End-to-End Security) — are assessed individually. Each capability is rated by what is achievable, what tools are needed, and what limitations apply.

***

## Device Configuration Context

The target configuration is:

- **Physical SIM**: Active in Slot 1, providing 5G mobile data and voice
- **eSIM (eUICC)**: Embedded (soldered), managed by the OEM or Google LPA
- **Android build**: Retail `user` build (not `userdebug` or `eng`)
- **ADB access**: Enabled via USB Debugging in Developer Options
- **Root**: None

This is the most common real-world scenario for an Android developer or researcher. The physical SIM with 5G provides a stable internet path for the tools described below, which is important because some tracing setups (notably mitmproxy) require a Wi-Fi connection — the 5G SIM can serve as an alternative data path via USB tethering or hotspot when Wi-Fi is occupied by the proxy setup.

***

## What You Can Do: Capability Overview

| Capability | Interface | Tool | Root Required | Notes |
|---|---|---|---|---|
| Capture full ES11 HTTP bodies | ES11 | mitmproxy | ❌ No | Wi-Fi proxy + CA cert install |
| Capture full ES9+ HTTP bodies | ES9+ | mitmproxy | ❌ No | Same setup; TLS pinning caveat |
| View ES10x call names and errors | ES8+ (indirect) | `adb logcat` | ❌ No | No raw APDU bytes on retail builds |
| Dump eUICC state and profile list | ES10b | `adb bugreport` | ❌ No | Snapshot only, not live |
| Toggle eSIM profile on/off via ADB | ES10b | `adb shell service call phone` | ❌ No | Requires correct subscription ID |
| Switch default data between physical SIM and eSIM | N/A | `adb shell settings put` | ❌ No | Multi-SIM routing commands |
| Read eSIM EID | ES10a | `adb shell service call` | ❌ No | Returns EID of embedded chip |
| List installed eSIM profiles | ES10b | `adb shell dumpsys` | ❌ No | Partial — profile names/states |
| Decrypt ES8+ Bound Profile Package | ES8+ | ❌ Not possible | — | Keys inside secure element |
| Raw APDU byte capture | ES8+ | ❌ Not possible | — | Scrubbed on retail builds |
| Access `EuiccCardManager` directly | ES10x | ❌ Not possible | — | System-privileged API only |

***

## ES11: The Discovery Interface

### What It Is

ES11 is the HTTPS interface between the LPA (Local Profile Assistant) on the device and the SM-DS (Subscription Manager Discovery Server). Its job is to notify the device that a pending eSIM event (typically a profile ready to download) exists at a specific SM-DP+ server.[1] The traffic is plain HTTP/2 over TLS, making it fully interceptable at the network layer without any device-level privilege.

### What You Can Capture (No Root)

**mitmproxy** configured as a Wi-Fi proxy is the primary tool.[2] The full JSON request and response bodies of all ES11 calls are visible, including:

- The SM-DS address queried
- Event Record IDs returned
- Authentication tokens and transactionIds
- The SM-DP+ address returned to the LPA for subsequent ES9+ contact

**Setup steps:**

```bash
# 1. On PC — start mitmproxy
pip install mitmproxy
mitmproxy --listen-port 8080

# 2. On phone — set Wi-Fi proxy to PC's IP:8080
#    Settings → Wi-Fi → long-press network → Modify → Proxy → Manual

# 3. On phone browser — visit http://mitm.it
#    Download and install the mitmproxy CA certificate as a trusted credential

# 4. Trigger eSIM discovery — attempt to download a profile, scan a QR code,
#    or use the LPA app. ES11 calls will appear in the mitmproxy console.
```

**5G SIM as data backup:** Since the Wi-Fi interface is occupied by the proxy, use the physical SIM's 5G connection via USB tethering or mobile hotspot if internet access is needed on other devices during the test.[3]

**ADB logcat complement:**

```bash
adb logcat | grep -iE "EuiccManager|SM-DS|discovery|ES11"
```

This correlates ES11 network call timing with framework-level log events, providing a combined view of what the Android telephony stack is doing at the same time as the network exchange.[4]

***

## ES9+: The Transport Interface

### What It Is

ES9+ is the primary HTTPS interface between the LPA and the SM-DP+ (Subscription Manager Data Preparation Plus) server. It carries the full RSP profile download session, including mutual authentication, the Bound Profile Package download, and confirmation steps.[1] Like ES11, it is HTTPS/TLS traffic and fully visible to a proxy.

### What You Can Capture (No Root)

The same **mitmproxy** setup used for ES11 captures ES9+ simultaneously. The key RSP calls visible at the HTTP body level include:

- `initiateAuthentication` — initial session setup with the SM-DP+
- `authenticateClient` — mutual authentication (contains device certificate chain)
- `getBoundProfilePackage` — the actual encrypted profile download (BPP blob)
- `handleNotification` — post-installation confirmation sent back to SM-DP+

**Important limitation — TLS certificate pinning:**

Some OEM LPA implementations enforce TLS certificate pinning, which causes the LPA to reject mitmproxy's CA certificate and terminate the connection.[5] The likelihood by device:

| Device / LPA | TLS Pinning Risk | Notes |
|---|---|---|
| Google Pixel (Google LPA) | Low | Google's LPA generally does not pin in standard flows |
| Samsung (Samsung LPA) | Medium–High | Samsung may enforce stricter TLS for its LPA |
| Xiaomi / MIUI | Medium | Varies by firmware version |
| OnePlus / OxygenOS | Low–Medium | Generally permissive |

If pinning is encountered, the LPA connection will fail and no ES9+ traffic will appear in mitmproxy. There is no workaround on an unrooted retail device — this requires root + Frida-based SSL unpinning.[2]

**adb logcat for ES9+ call sequencing:**

```bash
adb logcat | grep -iE "prepareDownload|loadBoundProfilePackage|authenticateServer|cancelSession"
```

Even without mitmproxy, logcat shows the ES10x call names that correspond to each ES9+ network transaction, allowing you to reconstruct the RSP protocol sequence from the Android side.[4]

***

## ES8+: The End-to-End Security Interface

### What It Is

ES8+ refers to the Bound Profile Package (BPP) — the encrypted payload that travels end-to-end between the SM-DP+ and the eUICC secure element. It is carried inside the ES9+ `getBoundProfilePackage` response as a Base64-encoded opaque blob. The decryption keys exist exclusively inside the eUICC chip and are never exposed to the Android OS layer.[6]

### What You Can See (No Root)

- **The encrypted BPP blob is visible** inside the mitmproxy ES9+ capture — it appears as a Base64-encoded field in the `getBoundProfilePackage` JSON response
- **You cannot decrypt it** without root, a test eUICC with exportable keys, or hardware-level tooling
- **ES10x call outcomes** (success/failure of loading the BPP into the eUICC) are visible in `adb logcat` as `EuiccCardManager` log entries

### ADB Commands for ES8+ Indirect Observation

The `dumpsys` interface exposes post-facto eUICC state that reflects the result of ES8+ operations:

```bash
# Full eUICC controller dump — shows profiles, EID, notification list
adb shell dumpsys euicc_card_controller

# Telephony registry — shows active subscriptions including eSIM
adb shell dumpsys telephony.registry

# Phone state — subscription IDs, SIM slot assignments, active bearers
adb shell dumpsys phone
```

These commands require only USB Debugging — no root — and return the current installed profile list, EID, and notification records that were generated by the most recent ES8+ profile installation.[7]

***

## ADB Commands: eSIM State Interaction (No Root)

Beyond passive observation, ADB provides a limited but useful set of active interactions with the eSIM system.

### Read the EID (eUICC Identifier)

```bash
adb shell service call phone 198 i32 0
```

Returns the EID of the embedded eUICC — the unique identifier of the chip itself, independent of any installed profile. This is useful for correlating with SM-DP+ server logs.[7]

### List Subscription IDs (Physical SIM + eSIM)

```bash
adb shell dumpsys phone | grep -i "subid\|subscriptionId\|iccid"
```

Returns the subscription IDs assigned to both the physical SIM (Slot 0) and any active eSIM profile. These IDs are used in subsequent commands.[7]

### Toggle eSIM Profile On/Off

```bash
# Enable eSIM profile (replace X with eSIM subscription ID)
adb shell service call phone 193 i32 X i32 1

# Disable eSIM profile
adb shell service call phone 193 i32 X i32 0
```

This mirrors the Settings → SIM Manager toggle and works without root. It triggers an ES10b `enableProfile` or `disableProfile` APDU on the eUICC, visible in logcat.[7]

### Switch Default Data Between Physical SIM and eSIM

```bash
# Set data SIM to physical SIM (subId for physical SIM)
adb shell settings put global multi_sim_data_call <physical_subId>

# Set data SIM to eSIM profile
adb shell settings put global multi_sim_data_call <esim_subId>
```

On a device with both a physical 5G SIM and an eSIM profile, this lets you switch the data path via ADB without touching the UI.[8]

### Full eUICC Snapshot (Bug Report)

```bash
adb bugreport > bugreport.zip
# Unzip and examine: bugreport.txt → search for "euicc_card_controller" or "EuiccCard"
```

The bug report bundles a snapshot of `dumpsys euicc_card_controller`, logcat history, and telephony state. It is the most complete passive data collection available without root and requires no special setup.[4]

***

## The Physical SIM + 5G Interaction

Having an active physical SIM with 5G on the device while tracing eSIM RSP operations creates a useful split-path configuration:

- **Wi-Fi** → dedicated to mitmproxy proxy interception of ES9+/ES11 traffic
- **5G (physical SIM)** → available as an independent internet path, or as a fallback if the LPA fails to use Wi-Fi

This also allows testing **dual-SIM RSP scenarios** — triggering an eSIM profile download while keeping the physical SIM active and observing how the Android telephony stack manages subscription priority, notification routing, and profile activation alongside an existing carrier connection.[3] The `dumpsys phone` output will reflect both subscriptions simultaneously, making it easy to compare their states before and after an RSP operation.

***

## Limitations Summary

The following capabilities are **not possible on an unrooted retail Android device**, regardless of ADB access:

- **Raw APDU byte capture**: The Android telephony framework scrubs APDU content from logs on `user` builds for security reasons.[4]
- **ES8+ BPP decryption**: Decryption keys reside inside the eUICC secure element and are never exposed to the Android OS layer.[6]
- **EuiccCardManager API access**: This API requires a system-privileged LPA app signed with the platform key. Third-party apps and ADB shell commands cannot invoke it directly.[9]
- **TLS certificate pinning bypass**: If the OEM LPA enforces certificate pinning, ES9+ traffic cannot be decrypted by mitmproxy on a retail device.
- **Profile installation via ADB**: Triggering a new eSIM profile download from scratch via ADB requires system LPA privileges — it cannot be done with standard ADB shell commands alone.

***

## Recommended No-Root Tool Stack

| Tool | Purpose | Interface Covered |
|---|---|---|
| `mitmproxy` | Full ES9+/ES11 HTTP body capture via Wi-Fi proxy | ES11, ES9+ |
| `adb logcat` | ES10x call sequence and error events | ES8+ (indirect) |
| `adb shell dumpsys` | eUICC state, profile list, EID, notification records | ES10a/b |
| `adb bugreport` | Full telephony + eUICC snapshot | All (passive) |
| `adb shell service call phone` | Toggle eSIM profile, read EID, switch data SIM | ES10b (active) |
| Sysmocom test SM-DP+ (`test.rsp.sysmocom.de`) | Controlled RSP sessions for generating predictable traces | ES9+, ES11, ES8+ |

Using the Sysmocom public test SM-DP+ to generate controlled eSIM provisioning sessions is strongly recommended when the goal is trace collection — it provides known, repeatable RSP flows against which all captured data can be verified.[10]

***

## Conclusion

Without root, an ADB-enabled Android phone with a physical 5G SIM provides a meaningful subset of eSIM RSP tracing capability. ES11 and ES9+ are fully interceptable using mitmproxy over Wi-Fi, providing complete HTTP request/response body visibility for the discovery and transport layers of the RSP protocol. The 5G physical SIM serves as an independent data path that does not interfere with the Wi-Fi proxy setup. ADB shell commands provide active interaction with eSIM profile state (enable/disable, data routing, EID retrieval) and passive state inspection via `dumpsys` and bug reports. The only hard barrier is ES8+ decryption — the Bound Profile Package remains inaccessible at the OS level by design, requiring either root plus source instrumentation via OpenEUICC, or dedicated hardware tooling such as the COMPRION eSIM Tracer, to observe its contents.
