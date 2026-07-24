/*
 * Fuzz target: ES8+ profile-metadata parser (euicc/es8p.c :: es8p_metadata_parse).
 *
 * Threat model: rogue SM-DP+. profileMetadata arrives base64-encoded inside the
 * ES9+ authenticateClient JSON, is base64-decoded, then BER-TLV parsed here
 * (iccid gsmbcd, SPN/profileName memcpy, icon base64-encode, class/iconType).
 *
 * Input shaping: the fuzzer controls the DECODED metadata bytes directly. We
 * base64-encode the raw fuzz bytes with lpac's own encoder, then hand the
 * resulting C string to es8p_metadata_parse. That exercises the real
 * base64_decode_len/decode path AND lets mutations drive the DER structure
 * without wasting the budget guessing valid base64.
 *
 * Skills applied: harness-writing (input shaping to hit the deep parser),
 * fuzzing-dictionary (BF25 / tag bytes), address-sanitizer.
 */
#include "es8p.h"
#include "base64.h"

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 65535) {
        return 0;
    }

    char *b64 = malloc(euicc_base64_encode_len((int)size) + 1);
    if (!b64) {
        return 0;
    }
    euicc_base64_encode(b64, data, (int)size);

    struct es8p_metadata *meta = NULL;
    if (es8p_metadata_parse(&meta, b64) == 0) {
        es8p_metadata_free(&meta);
    }

    free(b64);
    return 0;
}
