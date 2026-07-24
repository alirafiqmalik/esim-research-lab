#!/usr/bin/env bash
# Build the lpac parser fuzz targets (libFuzzer + ASan + UBSan).
# Offline, device-free. Skills: libfuzzer, address-sanitizer.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LPAC="${LPAC:-$HERE/../../../OpenEUICC/libs/lpac-jni/src/main/jni/lpac}"
CC="${CC:-clang}"

if [[ ! -d "$LPAC/euicc" ]]; then
    echo "lpac source not found at: $LPAC" >&2
    echo "Set LPAC=/path/to/lpac and re-run." >&2
    exit 1
fi

EUICC="$LPAC/euicc"
# cJSON is a sibling of the lpac tree (jni/cjson), not under it.
CJSON_ROOT="$LPAC/../cjson"
CJSON="$CJSON_ROOT/cjson"
CJSONEXT="$LPAC/cjson-ext"

# -I$CJSON_ROOT so cjson-ext's `#include <cjson/cJSON.h>` resolves.
INC=(-I"$EUICC" -I"$LPAC" -I"$CJSON_ROOT" -I"$CJSONEXT")
# -fsanitize=fuzzer,address,undefined per task; -O1 keeps parsers debuggable.
# -U_FORTIFY_SOURCE avoids fortify/ASan interference (address-sanitizer skill).
FLAGS=(-g -O1 -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer
       -U_FORTIFY_SOURCE -Wno-unused-parameter)

OUT="$HERE/build"
mkdir -p "$OUT"

# lpac translation units per target family. euicc.c and interface.c are
# deliberately EXCLUDED (they hold the real transport es10x_command /
# euicc_apdu_transmit, which each harness stubs).
DER="$EUICC/derutil.c"
CORE_TU=("$EUICC/derutil.c" "$EUICC/base64.c" "$EUICC/hexutil.c" "$EUICC/logger.c"
         "$EUICC/sha256.c" "$EUICC/tostr.c")
ES10_TU=("${CORE_TU[@]}" "$EUICC/es10a.c" "$EUICC/es10b.c" "$EUICC/es10c.c"
         "$EUICC/es10c_ex.c" "$EUICC/es8p.c")
ES8_TU=("$EUICC/es8p.c" "$EUICC/base64.c" "$EUICC/hexutil.c" "$EUICC/derutil.c"
        "$EUICC/logger.c")
ES9_TU=("$EUICC/es9p.c" "$EUICC/es9p_errors.c" "$EUICC/base64.c" "$EUICC/hexutil.c"
        "$EUICC/logger.c" "$EUICC/derutil.c" "$CJSON/cJSON.c"
        "$CJSONEXT/cjson-ext/cJSON_ex.c")

echo "[*] building fuzz_derutil"
"$CC" "${FLAGS[@]}" "${INC[@]}" "$HERE/harness_derutil.c" "$DER" -o "$OUT/fuzz_derutil"

echo "[*] building fuzz_es8p"
"$CC" "${FLAGS[@]}" "${INC[@]}" "$HERE/harness_es8p.c" "${ES8_TU[@]}" -o "$OUT/fuzz_es8p"

echo "[*] building fuzz_es10"
"$CC" "${FLAGS[@]}" "${INC[@]}" "$HERE/harness_es10.c" "${ES10_TU[@]}" -o "$OUT/fuzz_es10"

echo "[*] building fuzz_es9p"
"$CC" "${FLAGS[@]}" "${INC[@]}" "$HERE/harness_es9p.c" "${ES9_TU[@]}" -o "$OUT/fuzz_es9p"

echo "[+] done -> $OUT/{fuzz_derutil,fuzz_es8p,fuzz_es10,fuzz_es9p}"
