/*
 * Fuzz target: lpac BER-TLV/DER decoder (euicc/derutil.c).
 *
 * This is the shared decoder underneath every ES10 APDU-response parser and
 * the ES8+ metadata parser. Attacker-controlled bytes (rogue eUICC APDU
 * responses, or the decoded serverSigned1/profileMetadata blobs from a rogue
 * SM-DP+) flow straight into these functions, so a memory-safety bug here is
 * reachable from both threat models.
 *
 * Input shaping: the raw fuzz bytes ARE the DER buffer. First two bytes double
 * as a search tag so unpack_find_tag exercises the tag-walk path.
 *
 * Skills applied: harness-writing (narrow target, size guard, iteration cap
 * to keep exec/s high), address-sanitizer + libfuzzer (build flags).
 */
#include "derutil.h"

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

static const char *cap_desc[] = {"a", "b", "c", "d", "e", "f", "g", "h", NULL};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > 65535) {
        return 0;
    }

    const uint16_t search_tag = (uint16_t)((data[0] << 8) | data[1]);

    struct euicc_derutil_node n;
    euicc_derutil_unpack_first(&n, data, (uint32_t)size);

    /* Walk the whole buffer node by node, touching every value span. */
    struct euicc_derutil_node it;
    it.self.ptr = data;
    it.self.length = 0;
    unsigned guard = 0;
    while (euicc_derutil_unpack_next(&it, &it, data, (uint32_t)size) == 0) {
        (void)euicc_derutil_convert_bin2long(it.value, it.length);
        if (++guard > 100000) {
            break;
        }
    }

    /* Tag search (single + alias-list forms). */
    struct euicc_derutil_node found;
    if (euicc_derutil_unpack_find_tag(&found, search_tag, data, (uint32_t)size) == 0) {
        /* Recurse one level into the found node's value, like real parsers do. */
        struct euicc_derutil_node child;
        (void)euicc_derutil_unpack_find_tag(&child, 0x80, found.value, found.length);
    }
    const uint16_t alias[] = {search_tag, 0xBF2F, 0xA0};
    (void)euicc_derutil_unpack_find_alias_tags(&found, alias, 3, data, (uint32_t)size);

    /* Bit-string capability decoder (allocates; free the result). */
    const char **caps = NULL;
    if (euicc_derutil_convert_bin2bits_str(&caps, data, (int)size, cap_desc) == 0) {
        free(caps);
    }

    return 0;
}
