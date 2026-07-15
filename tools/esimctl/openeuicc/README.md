# OpenEUICC EsimCtlActivity — phase-2 backend source

`EsimCtlActivity.kt` is the headless, exported activity added to our OpenEUICC
build so `esimctl`'s `lpac`/`fw` backends can drive eSIM ops deterministically
(no UI automation) and log a JSON result to the `ESIMCTL` logcat tag.

## Integrate into the OpenEUICC source tree

1. Copy `EsimCtlActivity.kt` to
   `app/src/main/java/im/angry/openeuicc/ui/EsimCtlActivity.kt`.
2. Register it in `app/src/main/AndroidManifest.xml` inside `<application>`:

   ```xml
   <activity
       android:name=".ui.EsimCtlActivity"
       android:exported="true"
       android:excludeFromRecents="true"
       android:noHistory="true" />
   ```
   (Do NOT give it a translucent/NoDisplay theme — the activity must fully
   resume for its `lifecycleScope` coroutine to run.)
3. Build + hot-update (no reboot needed; retains privileged status):

   ```bash
   JAVA_HOME=/usr/lib/jvm/java-21-openjdk \
     ./gradlew --no-daemon :app:assembleDebugMagiskModuleDir
   adb install -r app/build/magisk/debug/system/system_ext/priv-app/OpenEUICC/OpenEUICC.apk
   ```

## Invoke directly (what esimctl does under the hood)

```bash
adb shell am start -n im.angry.openeuicc/.ui.EsimCtlActivity \
  --es id <reqid> --es op <op> --es backend <lpac|fw> [--es code '…'] [--es iccid …]
# result: logcat  ->  ESIMCTL: <reqid> RESULT {json}
```

ops: `eid info list notifications download enable disable delete` (lpac);
`eid info download delete switch` (fw = framework EuiccManager). Device must be
UNLOCKED (eUICC APDU access is keyguard-gated).
