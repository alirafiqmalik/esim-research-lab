/*
 * Fuzz target: ES9+ / ES11 response parsers (euicc/es9p.c) — the rogue
 * SM-DP+ / SM-DS surface (highest value).
 *
 * Threat model: a rogue SM-DP+ (or SM-DS) returns an attacker-controlled HTTPS
 * body. lpac runs it through cJSON, walks header/functionExecutionStatus, then
 * strncpy's status fields and strdup's the response objects
 * (serverSigned1/serverSignature1/serverCertificate/eventEntries/...), then
 * es9p_base64_trim() rewrites the base64 in place.
 *
 * Input shaping: we replace the HTTP transport (ctx->http.interface->transmit)
 * with a stub that returns the fuzz bytes verbatim as the response body with
 * HTTP 200. That hands the fuzzer direct control of the JSON the parser sees.
 * data[0] selects the ES9+/ES11 function; data[1..] is the JSON body.
 *
 * Stubs: http transmit only. cJSON, cJSON-ext, es9p, es9p_errors are real.
 *
 * Skills applied: harness-writing (transport stub, interleave, cleanup),
 * fuzzing-dictionary (JSON keys + status structure), libfuzzer + ASan/UBSan.
 */
#include "euicc.h"
#include "es9p.h"
#include "interface.h"

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int es11_authenticate_client_r(struct euicc_ctx *ctx, char ***smdp_list, const char *server_address,
                               const char *transaction_id, const char *b64_authenticate_server_response);
void es11_smdp_list_free_all(char **smdp_list);

static const uint8_t *g_body;
static uint32_t g_body_len;

static int stub_http_transmit(struct euicc_ctx *ctx, const char *url, uint32_t *rcode, uint8_t **rx, uint32_t *rx_len,
                              const uint8_t *tx, uint32_t tx_len, const char **headers) {
    (void)ctx;
    (void)url;
    (void)tx;
    (void)tx_len;
    (void)headers;
    uint8_t *buf = malloc(g_body_len ? g_body_len : 1);
    if (!buf) {
        return -1;
    }
    if (g_body_len) {
        memcpy(buf, g_body, g_body_len);
    }
    *rx = buf;
    *rx_len = g_body_len;
    *rcode = 200;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > 65535) {
        return 0;
    }

    const uint8_t mode = data[0];
    g_body = data + 1;
    g_body_len = (uint32_t)(size - 1);

    struct euicc_http_interface iface;
    memset(&iface, 0, sizeof(iface));
    iface.transmit = stub_http_transmit;

    struct euicc_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.http.interface = &iface;
    ctx.http.server_address = "smdp.example.com";

    const char *tx = "0000000000000000";

    switch (mode % 6) {
    case 0: {
        char *transaction_id = NULL;
        struct es10b_authenticate_server_param resp;
        memset(&resp, 0, sizeof(resp));
        if (es9p_initiate_authentication_r(&ctx, &transaction_id, &resp, ctx.http.server_address, "", "") == 0) {
            free(transaction_id);
            free(resp.b64_serverSigned1);
            free(resp.b64_serverSignature1);
            free(resp.b64_euiccCiPKIdToBeUsed);
            free(resp.b64_serverCertificate);
        }
        break;
    }
    case 1: {
        struct es10b_prepare_download_param resp;
        memset(&resp, 0, sizeof(resp));
        if (es9p_authenticate_client_r(&ctx, &resp, ctx.http.server_address, tx, "") == 0) {
            free(resp.b64_profileMetadata);
            free(resp.b64_smdpSigned2);
            free(resp.b64_smdpSignature2);
            free(resp.b64_smdpCertificate);
        }
        break;
    }
    case 2: {
        char **smdp_list = NULL;
        if (es11_authenticate_client_r(&ctx, &smdp_list, ctx.http.server_address, tx, "") == 0) {
            es11_smdp_list_free_all(smdp_list);
        }
        break;
    }
    case 3: {
        char *b64_bpp = NULL;
        if (es9p_get_bound_profile_package_r(&ctx, &b64_bpp, ctx.http.server_address, tx, "") == 0) {
            free(b64_bpp);
        }
        break;
    }
    case 4:
        es9p_cancel_session_r(&ctx, ctx.http.server_address, tx, "");
        break;
    case 5:
        es9p_handle_notification(&ctx, "");
        break;
    }

    return 0;
}
