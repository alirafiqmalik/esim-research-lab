#!/usr/bin/env bash
# Reproduce the full research testbed from scratch: build OpenEUICC (with the
# EsimCtlActivity patch) from source, install it privileged, provision
# frida-server, set the datastore prefs it needs, and run the smoke test.
#
# Idempotent: safe to re-run. Each step guards on "already done". Precondition
# failures print the exact command to fix and exit non-zero.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERIAL="${ESIMCTL_SERIAL:-$(adb devices | awk '$2=="device"{print $1;exit}')}"
OPENEUICC_DIR="${OPENEUICC_DIR:-$REPO/../OpenEUICC}"
ANDROID_SDK="${ANDROID_SDK:-${ANDROID_HOME:-/opt/android-sdk}}"
JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk}"
ADB="adb -s $SERIAL"

die() { echo "setup_testbed: $*" >&2; exit 1; }

echo "== step 0: preconditions =="
for c in adb git python3 dot keytool; do
  command -v "$c" >/dev/null 2>&1 || die "missing required command: $c"
done
frida --version >/dev/null 2>&1 || die "host 'frida --version' failed — install the frida-tools python package"
[ -n "$SERIAL" ] || die "no adb device in 'device' state"
$ADB get-state >/dev/null 2>&1 || die "device $SERIAL not in 'device' state"
$ADB shell dumpsys window 2>/dev/null | grep -q 'isKeyguardShowing=false' || die "unlock the phone"
java -version 2>&1 | grep -q 'version "21' || die "need JAVA_HOME pointing at a JDK 21 (java -version must show \"21\")"
[ -d "$ANDROID_SDK/ndk/26.1.10909125" ] || {
  "$ANDROID_SDK/cmdline-tools/latest/bin/sdkmanager" "ndk;26.1.10909125" "platforms;android-35" 2>/dev/null
  [ -d "$ANDROID_SDK/ndk/26.1.10909125" ] || die "run: \"$ANDROID_SDK/cmdline-tools/latest/bin/sdkmanager\" 'ndk;26.1.10909125' 'platforms;android-35'"
}
[ -d "$ANDROID_SDK/platforms/android-35" ] || {
  "$ANDROID_SDK/cmdline-tools/latest/bin/sdkmanager" "ndk;26.1.10909125" "platforms;android-35" 2>/dev/null
  [ -d "$ANDROID_SDK/platforms/android-35" ] || die "run: \"$ANDROID_SDK/cmdline-tools/latest/bin/sdkmanager\" 'ndk;26.1.10909125' 'platforms;android-35'"
}
echo "preconditions OK (serial=$SERIAL)"

echo "== step 1: clone/refresh OpenEUICC =="
if [ ! -d "$OPENEUICC_DIR" ]; then
  git clone https://gitea.angry.im/PeterCxy/OpenEUICC.git "$OPENEUICC_DIR" || die "clone failed"
  git -C "$OPENEUICC_DIR" submodule update --init --recursive || die "submodule update failed"
else
  echo "OpenEUICC already cloned at $OPENEUICC_DIR, skipping"
fi

echo "== step 2: apply EsimCtlActivity patch =="
cp "$REPO/testbed/openeuicc/EsimCtlActivity.kt" \
   "$OPENEUICC_DIR/app/src/main/java/im/angry/openeuicc/ui/EsimCtlActivity.kt" || die "patch copy failed"
# The copied snapshot already contains the same-channel `seq` primitive. seq-primitive.patch
# records that change as a standalone diff; apply it only if the copied file lacks seq
# (guarded, idempotent — normally a no-op because the snapshot is the source of truth).
if ! grep -q '"seq"' "$OPENEUICC_DIR/app/src/main/java/im/angry/openeuicc/ui/EsimCtlActivity.kt"; then
  git -C "$OPENEUICC_DIR" apply "$REPO/testbed/openeuicc/seq-primitive.patch" \
    || die "seq-primitive.patch failed to apply"
else
  echo "seq primitive already present in snapshot, skipping seq-primitive.patch"
fi
# large-seq delivery: file-based --es apdus_file / --es results_file path for big
# sequences (records the seqTokens() change as a standalone diff; the snapshot already
# contains it, so this is normally a no-op).
if ! grep -q 'seqTokens' "$OPENEUICC_DIR/app/src/main/java/im/angry/openeuicc/ui/EsimCtlActivity.kt"; then
  git -C "$OPENEUICC_DIR" apply "$REPO/testbed/openeuicc/largeseq.patch" \
    || die "largeseq.patch failed to apply"
else
  echo "large-seq file delivery already present in snapshot, skipping largeseq.patch"
fi
# frontier patch: ES11 discovery + AuthenticateServer JNI + card wrapper override
if ! grep -q es11Discovery "$OPENEUICC_DIR/libs/lpac-jni/src/main/jni/lpac-jni/lpac-jni.c" 2>/dev/null; then
  git -C "$OPENEUICC_DIR" apply "$REPO/testbed/openeuicc/es11-discovery.patch" \
    || die "es11-discovery.patch failed to apply"
else
  echo "es11-discovery.patch already applied, skipping"
fi
MANIFEST="$OPENEUICC_DIR/app/src/main/AndroidManifest.xml"
if ! grep -q EsimCtlActivity "$MANIFEST"; then
  awk '
    /<\/application>/ && !done {
      print "        <activity"
      print "            android:name=\".ui.EsimCtlActivity\""
      print "            android:exported=\"true\""
      print "            android:excludeFromRecents=\"true\""
      print "            android:noHistory=\"true\" />"
      done=1
    }
    { print }
  ' "$MANIFEST" > "$MANIFEST.tmp" && mv "$MANIFEST.tmp" "$MANIFEST" || die "manifest patch failed"
  grep -q EsimCtlActivity "$MANIFEST" || die "manifest patch verification failed"
  python3 -c "import xml.dom.minidom,sys; xml.dom.minidom.parse('$MANIFEST')" \
    || die "manifest patch produced invalid XML"
else
  echo "manifest already patched, skipping"
fi

echo "== step 3: keystore + local.properties =="
if [ ! -f "$OPENEUICC_DIR/keystore.properties" ]; then
  keytool -genkeypair -v -keystore "$OPENEUICC_DIR/openeuicc-research.jks" -storepass research123 \
    -keypass research123 -alias oeuicc -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=OpenEUICC Research, O=research, C=US" || die "keytool failed"
  cat > "$OPENEUICC_DIR/keystore.properties" <<EOF
storePassword=research123
keyPassword=research123
keyAlias=oeuicc
unprivKeyPassword=research123
unprivKeyAlias=oeuicc
storeFile=$OPENEUICC_DIR/openeuicc-research.jks
EOF
else
  echo "keystore.properties already present, skipping"
fi
if [ ! -f "$OPENEUICC_DIR/local.properties" ]; then
  echo "sdk.dir=$ANDROID_SDK" > "$OPENEUICC_DIR/local.properties"
else
  echo "local.properties already present, skipping"
fi

echo "== step 4: build =="
(cd "$OPENEUICC_DIR" && JAVA_HOME="$JAVA_HOME" ./gradlew --no-daemon :app:assembleDebugMagiskModuleDir) \
  || die "gradle build failed"
APK="$OPENEUICC_DIR/app/build/magisk/debug/system/system_ext/priv-app/OpenEUICC/OpenEUICC.apk"
[ -f "$APK" ] || die "build did not produce $APK"

echo "== step 5: install privileged =="
INSTALLED_PKGS=$($ADB shell pm list packages im.angry.openeuicc 2>/dev/null)
IS_PRIV=false
if [ -n "$INSTALLED_PKGS" ]; then
  $ADB shell pm dump im.angry.openeuicc 2>/dev/null | grep -q PRIVILEGED && IS_PRIV=true
fi
if [ -z "$INSTALLED_PKGS" ] || [ "$IS_PRIV" = false ]; then
  echo "first-time privileged install via magisk module"
  (cd "$OPENEUICC_DIR/app/build/magisk/debug" && zip -r -q /tmp/oeuicc-mod.zip .) || die "zip failed"
  $ADB push /tmp/oeuicc-mod.zip /data/local/tmp/ || die "push module failed"
  $ADB shell su -c 'magisk --install-module /data/local/tmp/oeuicc-mod.zip' || die "magisk install-module failed"
  echo "REBOOT REQUIRED — rerun setup after reboot"
  $ADB reboot
  exit 0
else
  echo "already privileged, updating in place"
  $ADB install -r "$APK" || die "adb install -r failed"
  $ADB shell pm dump im.angry.openeuicc 2>/dev/null | grep -q PRIVILEGED || die "package no longer privileged after update"
fi

echo "== step 6: frida-server =="
FRIDA_VERSION="${FRIDA_VERSION:-$(frida --version)}"
if ! $ADB shell "su -c 'ls /data/local/tmp/frida-server'" >/dev/null 2>&1; then
  mkdir -p "$REPO/.temp"
  URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-arm64.xz"
  curl -fL "$URL" -o "$REPO/.temp/frida-server.xz" || die "download failed: $URL"
  unxz -f "$REPO/.temp/frida-server.xz" || die "unxz failed"
  $ADB push "$REPO/.temp/frida-server" /data/local/tmp/frida-server || die "push frida-server failed"
  $ADB shell su -c 'chmod 755 /data/local/tmp/frida-server' || die "chmod frida-server failed"
else
  echo "frida-server already present on device, skipping download"
fi
bash "$REPO/scripts/frida/ensure_frida.sh" || die "frida-server not healthy"

echo "== step 7: datastore prefs =="
python3 - "$REPO" <<'PYEOF'
import struct, sys, pathlib

def varint(n):
    out = b""
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            out += bytes([b])
            return out

def tag(field, wire):
    return varint((field << 3) | wire)

def bool_value_message(b: bool) -> bytes:
    # Value message: bool field 1
    inner = tag(1, 0) + varint(1 if b else 0)
    return inner

def map_entry(key: str, val_bytes: bytes) -> bytes:
    key_bytes = tag(1, 2) + varint(len(key)) + key.encode()
    val_field = tag(2, 2) + varint(len(val_bytes)) + val_bytes
    entry = key_bytes + val_field
    return tag(1, 2) + varint(len(entry)) + entry

out = b""
out += map_entry("developer_options_enabled", bool_value_message(True))
out += map_entry("verbose_logging", bool_value_message(True))

repo = pathlib.Path(sys.argv[1])
dest = repo / ".temp" / "prefs.preferences_pb"
dest.parent.mkdir(parents=True, exist_ok=True)
dest.write_bytes(out)
print(f"wrote {dest} ({len(out)} bytes)")
PYEOF
$ADB push "$REPO/.temp/prefs.preferences_pb" /data/local/tmp/prefs.preferences_pb || die "push prefs failed"
$ADB shell su -c 'mkdir -p /data/data/im.angry.openeuicc/files/datastore' || die "mkdir datastore failed"
$ADB shell su -c 'cp /data/local/tmp/prefs.preferences_pb /data/data/im.angry.openeuicc/files/datastore/prefs.preferences_pb' || die "cp prefs failed"
APP_UID=$($ADB shell su -c 'stat -c %u /data/data/im.angry.openeuicc' | tr -d '\r\n')
[ -n "$APP_UID" ] || die "could not determine app uid"
$ADB shell su -c "chown $APP_UID:$APP_UID /data/data/im.angry.openeuicc/files/datastore/prefs.preferences_pb" || die "chown prefs failed"
$ADB shell su -c 'restorecon -R /data/data/im.angry.openeuicc/files/datastore' 2>/dev/null
$ADB shell su -c 'am force-stop im.angry.openeuicc' || die "force-stop failed"

echo "== step 8: relax hidden-API policy (card backend reflects EuiccCardManager) =="
# lets OpenEUICC's priv-app reflect @hide android.telephony.euicc.EuiccCardManager;
# the per-command card path is still authz-gated to the active LPA (returns
# RESULT_CALLER_NOT_ALLOWED), but this makes the reflection reach the framework.
$ADB shell "su -c 'settings put global hidden_api_policy 1'" || die "hidden_api_policy set failed"
$ADB shell am force-stop im.angry.openeuicc

echo "== step 9: keep awake + verify =="
bash "$REPO/scripts/device/keep_phone_awake.sh" || die "keep_phone_awake failed"
bash "$REPO/testbed/selftest.sh" || die "selftest failed"

echo "TESTBED READY"
