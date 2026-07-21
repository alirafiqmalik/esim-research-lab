# Default-LPA exploration — unlocking the IEuiccCardController path

Can we unlock the `esim euicc card-*` second command path (framework
`IEuiccCardController`), which returns `-3 RESULT_CALLER_NOT_ALLOWED`, by making
OpenEUICC the phone's default LPA? Investigated and tested live on the rooted
Pixel 7a (2026-07-16). Companion to `docs/reference/euicc-api.md` (row 1).

## Answer up front

- **The gate is LPA-identity.** `EuiccCardController.checkCallingPackage` requires
  the caller's package to equal the resolved LPA package. Not a permission, not
  carrier privileges, not a platform signature.
- **Becoming the LPA passes the gate — verified.** After the switch,
  `card-challenge` flipped from `-3 RESULT_CALLER_NOT_ALLOWED` to
  `-1 RESULT_UNKNOWN_ERROR`. The caller check stopped rejecting us.
- **But the path is still dead on this device.** `RESULT_UNKNOWN_ERROR` is the
  stock card stack failing its own eUICC I/O. `EuiccCardController` talks to the
  card over the platform RIL/QMI path, which the Samsung S.LSI modem does not
  expose — the same reason lpac uses OMAPI. So the gate is beatable; the transport
  is not.
- **A safe, reversible switch method exists** (manifest priority bump). Used and
  reverted here.

## The gate (AOSP source)

`EuiccCardController.checkCallingPackage` runs before each card command:

```java
private void checkCallingPackage(String callingPackage) {
    mAppOps.checkPackage(Binder.getCallingUid(), callingPackage);
    mCallingPackage = callingPackage;
    mBestComponent = EuiccConnector.findBestComponent(mContext.getPackageManager());
    if (mBestComponent == null
        || !TextUtils.equals(mCallingPackage, mBestComponent.packageName)) {
        throw new SecurityException("The calling package can only be LPA.");
    }
}
```

The caller must be `EuiccConnector.findBestComponent().packageName`. On this build
the thrown `SecurityException` surfaces to the `EuiccCardManager` callback as
`RESULT_CALLER_NOT_ALLOWED` (-3).

## How the LPA is chosen (`EuiccConnector.findBestComponent`)

- A candidate must be a **privileged system** app that holds
  `WRITE_EMBEDDED_SUBSCRIPTIONS` and requires `BIND_EUICC_SERVICE`, queried with
  `MATCH_SYSTEM_ONLY`.
- Selection is by intent-filter **priority, strict `>`**. Equal priority →
  **first found wins**. No `config_euicc_lpa_service` or carrier-config override in
  this code path.

Device state before the test — two candidates, both priority 100:

| Order | Package | Priority |
|---|---|---|
| #0 (wins) | `com.google.android.euicc` (stock) | 100 |
| #1 | `im.angry.openeuicc` | 100 |

OpenEUICC already declares `EuiccService` (`OpenEuiccService`) and qualifies as a
candidate. It loses only the tie — the stock LPA is enumerated first.

## Mechanisms to become the LPA

| Method | Feasible | Reversible | Risk |
|---|---|---|---|
| **Raise OpenEUICC's `EuiccService` priority above 100** (manifest, rebuild) | ✅ used here | ✅ reinstall the priority-100 APK (one `adb install -r`) | Low — no system component touched; only LPA resolution changes |
| `pm disable` the stock `EuiccServiceImpl` component | ✅ | ◐ `pm enable` restores, but wider effect on stock eSIM UI | Medium |
| Carrier-config / `config_euicc_lpa_service` overlay | ✗ not used by this code path | — | — |
| Platform-sign OpenEUICC | ✗ needs the platform key (not available) | — | — |

The priority bump is the clean one: privileged priv-app, strict `>` selection, so
priority 200 wins deterministically without disabling anything.

## What was tested, and the result

1. Backed up the installed APK.
2. Raised the `OpenEuiccService` filter priority `100 → 200`, rebuilt, installed.
3. Confirmed resolution flipped — OpenEUICC now `findBestComponent`:

```
Service #0  priority=200  im.angry.openeuicc/.service.OpenEuiccService
Service #1  priority=100  com.google.android.euicc/...EuiccServiceImpl
```

4. Ran the card ops. Every one moved off the caller gate:

| op | before | after switch |
|---|---|---|
| `card-challenge` | `-3 RESULT_CALLER_NOT_ALLOWED` | `-1 RESULT_UNKNOWN_ERROR` |
| `card-info2` | `-3` | `-1 RESULT_UNKNOWN_ERROR` |
| `card-default-smdp` | `-3` | `-1 RESULT_UNKNOWN_ERROR` |
| `card-smds` | `-3` | `-1 RESULT_UNKNOWN_ERROR` |

5. Reverted: reinstalled the priority-100 APK, restored the manifest. Resolution
   returned to stock-first; `card-challenge` returned to
   `RESULT_CALLER_NOT_ALLOWED`. eUICC untouched (2 profiles, EID reads).

## Why it still fails after the gate

`EuiccCardController` does not route card I/O through the LPA's `EuiccService`. It
drives the card itself through the platform's `UiccController` / APDU sender —
the RIL path. On this Samsung S.LSI modem that path cannot reach the eUICC (no
QMI; `iccOpenLogicalChannel` returns unavailable for the ISD-R AID). So once the
identity gate passes, the stock stack fails its own transport with
`RESULT_UNKNOWN_ERROR`. This is the same wall that made us use OMAPI for lpac.

## Takeaways

- The `card-*` path is **authorization-unlockable but transport-dead** on this
  device. Making OpenEUICC the LPA is necessary but not sufficient.
- It could work on a device whose modem exposes QMI/RIL logical channels to the
  eUICC. There, the priority bump would turn `card-*` into a live second command
  path.
- For this testbed, lpac-over-OMAPI stays the only working command path. The
  `card-*` ops remain useful as a boundary probe (they now demonstrate both the
  identity gate and, past it, the RIL transport wall).
- Leaving OpenEUICC as the permanent LPA is **not recommended** here: it yields no
  working card path and would hand eSIM UI/handling to OpenEUICC for no gain. The
  switch stays a reversible experiment, reverted after use.
