/*
 * Fuzz target: ES10 APDU-response parsers (euicc/es10a.c, es10b.c, es10c.c,
 * es10c_ex.c) + the BER-TLV decoder they share.
 *
 * Threat model: rogue eUICC (a malicious/emulated card, or an OMAPI/APDU MITM)
 * returns attacker-controlled bytes as the eUICC response. Every es10*_r parser
 * feeds that response straight into euicc_derutil_unpack_* and then does
 * malloc+memcpy / gsmbcd / base64 on the extracted spans.
 *
 * Input shaping: we DO NOT emulate APDU framing. Instead we replace the
 * transport seam es10x_command() (normally in euicc.c, which we deliberately do
 * NOT compile) with a stub that returns the fuzz bytes verbatim as the eUICC
 * response buffer. That hands the fuzzer direct control of every parsed
 * response while running the genuine parser + decoder code.
 *
 * data[0] selects the parser family (interleaved fuzzing, shared corpus);
 * data[1..] is the response body.
 *
 * Stubs: es10x_command (transport). Everything else is real lpac code.
 *
 * Skills applied: harness-writing (transport-seam stubbing, interleaved
 * targets, resource cleanup), libfuzzer + address-sanitizer, coverage-analysis
 * (family selector keeps one corpus exercising all parsers).
 */
#include "euicc.h"
#include "es10a.h"
#include "es10b.h"
#include "es10c.h"
#include "es10c_ex.h"
#include "base64.h"

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Per-iteration response bytes handed to the stubbed transport. */
static const uint8_t *g_resp;
static uint32_t g_resp_len;

/* Replacement for euicc.c's es10x_command: return the fuzz bytes as the eUICC
 * response. Parsers free() this buffer, so hand out a fresh malloc each call. */
int es10x_command(struct euicc_ctx *ctx, uint8_t **resp, unsigned *resp_len, const uint8_t *der_req,
                  unsigned req_len) {
    (void)ctx;
    (void)der_req;
    (void)req_len;
    uint8_t *buf = malloc(g_resp_len ? g_resp_len : 1);
    if (!buf) {
        return -1;
    }
    if (g_resp_len) {
        memcpy(buf, g_resp, g_resp_len);
    }
    *resp = buf;
    *resp_len = g_resp_len;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > 65535) {
        return 0;
    }

    const uint8_t mode = data[0];
    g_resp = data + 1;
    g_resp_len = (uint32_t)(size - 1);

    struct euicc_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.es10x_mss = 120;

    switch (mode % 12) {
    case 0: {
        struct es10a_euicc_configured_addresses a;
        if (es10a_get_euicc_configured_addresses(&ctx, &a) == 0) {
            es10a_euicc_configured_addresses_free(&a);
        }
        break;
    }
    case 1: {
        char *b64 = NULL;
        if (es10b_get_euicc_challenge_r(&ctx, &b64) == 0) {
            free(b64);
        }
        break;
    }
    case 2: {
        char *b64 = NULL;
        if (es10b_get_euicc_info_r(&ctx, &b64) == 0) {
            free(b64);
        }
        break;
    }
    case 3: {
        struct es10b_notification_metadata_list *l = NULL;
        if (es10b_list_notification(&ctx, &l) == 0) {
            es10b_notification_metadata_list_free_all(l);
        }
        break;
    }
    case 4: {
        struct es10b_pending_notification pn;
        if (es10b_retrieve_notifications_list(&ctx, &pn, 1) == 0) {
            es10b_pending_notification_free(&pn);
        }
        break;
    }
    case 5: {
        struct es10b_rat *r = NULL;
        if (es10b_get_rat(&ctx, &r) == 0) {
            es10b_rat_list_free_all(r);
        }
        break;
    }
    case 6: {
        struct es10c_profile_info_list *l = NULL;
        if (es10c_get_profiles_info(&ctx, &l) == 0) {
            /* free the linked list */
            while (l) {
                struct es10c_profile_info_list *n = l->next;
                free(l->profileNickname);
                free(l->serviceProviderName);
                free(l->profileName);
                free(l->icon);
                free(l);
                l = n;
            }
        }
        break;
    }
    case 7: {
        char *eid = NULL;
        if (es10c_get_eid(&ctx, &eid) == 0) {
            free(eid);
        }
        break;
    }
    case 8: {
        struct es10c_ex_euiccinfo2 info2;
        if (es10c_ex_get_euiccinfo2(&ctx, &info2) == 0) {
            es10c_ex_euiccinfo2_free(&info2);
        }
        break;
    }
    case 9: {
        /* BoundProfilePackage structural parse (rogue SM-DP+ getBoundProfilePackage).
         * b64 is the fuzz-controlled decoded BPP; the segment responses are the
         * same fuzz bytes via the stub. */
        char *b64 = malloc(euicc_base64_encode_len((int)g_resp_len) + 1);
        if (b64) {
            euicc_base64_encode(b64, g_resp, (int)g_resp_len);
            struct es10b_load_bound_profile_package_result res;
            memset(&res, 0, sizeof(res));
            es10b_load_bound_profile_package_r(&ctx, &res, b64);
            free(b64);
        }
        break;
    }
    case 10: {
        /* prepare_download response re-encode path. */
        struct es10b_prepare_download_param p;
        memset(&p, 0, sizeof(p));
        p.b64_profileMetadata = strdup("");
        p.b64_smdpSigned2 = strdup("");
        p.b64_smdpSignature2 = strdup("");
        p.b64_smdpCertificate = strdup("");
        struct es10b_prepare_download_param_user u = {.confirmationCode = NULL};
        char *b64resp = NULL;
        if (es10b_prepare_download_r(&ctx, &b64resp, &p, &u) == 0) {
            free(b64resp);
        }
        free(p.b64_profileMetadata);
        free(p.b64_smdpSigned2);
        free(p.b64_smdpSignature2);
        free(p.b64_smdpCertificate);
        break;
    }
    case 11: {
        /* authenticate_server: transactionId extraction from response. */
        struct es10b_authenticate_server_param p;
        memset(&p, 0, sizeof(p));
        p.b64_serverSigned1 = strdup("");
        p.b64_serverSignature1 = strdup("");
        p.b64_euiccCiPKIdToBeUsed = strdup("");
        p.b64_serverCertificate = strdup("");
        struct es10b_authenticate_server_param_user u = {.matchingId = "", .imei = NULL};
        uint8_t *tid = NULL;
        uint32_t tid_len = 0;
        char *b64resp = NULL;
        if (es10b_authenticate_server_r(&ctx, &tid, &tid_len, &b64resp, &p, &u) == 0) {
            free(tid);
            free(b64resp);
        }
        free(p.b64_serverSigned1);
        free(p.b64_serverSignature1);
        free(p.b64_euiccCiPKIdToBeUsed);
        free(p.b64_serverCertificate);
        break;
    }
    }

    return 0;
}
