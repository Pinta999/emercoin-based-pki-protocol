/*
 *  Certificate reading application
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_PLATFORM_C)

#include "mbedtls/platform.h"

#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_time            time
#define mbedtls_time_t          time_t
#define mbedtls_fprintf         fprintf
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_ENTROPY_C) || \
    !defined(MBEDTLS_SSL_TLS_C) || !defined(MBEDTLS_SSL_CLI_C) || \
    !defined(MBEDTLS_NET_C) || !defined(MBEDTLS_RSA_C) || \
    !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_FS_IO) || \
    !defined(MBEDTLS_CTR_DRBG_C) || defined(MBEDTLS_X509_REMOVE_INFO)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_ENTROPY_C and/or "
           "MBEDTLS_SSL_TLS_C and/or MBEDTLS_SSL_CLI_C and/or "
           "MBEDTLS_NET_C and/or MBEDTLS_RSA_C and/or "
           "MBEDTLS_X509_CRT_PARSE_C and/or MBEDTLS_FS_IO and/or "
           "MBEDTLS_CTR_DRBG_C not defined and/or MBEDTLS_X509_REMOVE_INFO defined.\n");
    mbedtls_exit( 0 );
}
#else

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "mbedtls/debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*************************
 * Emercoin modification *
 *************************/

#define EMC_CORE_URL "http://user:psw@127.0.0.1:9092"
#define EMC_ISSUER_STR "O=EmerCoin, OU=PKI, CN=EMCSSL/emailAddress=team@emercoin.com/UID=EMC"

#include <curl/curl.h>
#include "emercoin/jsmn.h"


#define MODE_NONE               0
#define MODE_FILE               1
#define MODE_SSL                2

#define DFL_MODE                MODE_NONE
#define DFL_FILENAME            "cert.crt"
#define DFL_CA_FILE             ""
#define DFL_CRL_FILE            ""
#define DFL_CA_PATH             ""
#define DFL_SERVER_NAME         "localhost"
#define DFL_SERVER_PORT         "4433"
#define DFL_DEBUG_LEVEL         0
#define DFL_PERMISSIVE          0

#define USAGE_IO \
    "    ca_file=%%s          The single file containing the top-level CA(s) you fully trust\n" \
    "                        default: \"\" (none)\n" \
    "    crl_file=%%s         The single CRL file you want to use\n" \
    "                        default: \"\" (none)\n" \
    "    ca_path=%%s          The path containing the top-level CA(s) you fully trust\n" \
    "                        default: \"\" (none) (overrides ca_file)\n"

#define USAGE \
    "\n usage: cert_app param=<>...\n"                  \
    "\n acceptable parameters:\n"                       \
    "    mode=file|ssl       default: none\n"           \
    "    filename=%%s         default: cert.crt\n"      \
    USAGE_IO                                            \
    "    server_name=%%s      default: localhost\n"     \
    "    server_port=%%d      default: 4433\n"          \
    "    debug_level=%%d      default: 0 (disabled)\n"  \
    "    permissive=%%d       default: 0 (disabled)\n"  \
    "\n"

/* Emercoin modification necessary functions/struct */

struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t
write_memory_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *) userp;

    mem->memory = realloc(mem->memory, mem->size + realsize + 1);
    if (mem->memory == NULL) {
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
    if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
        strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
        return 0;
    }
    return -1;
}

/* Emercoin addons: end */

/*
 * global options
 */
struct options {
    int mode;                   /* the mode to run the application in   */
    const char *filename;       /* filename of the certificate file     */
    const char *ca_file;        /* the file with the CA certificate(s)  */
    const char *crl_file;       /* the file with the CRL to use         */
    const char *ca_path;        /* the path with the CA certificate(s) reside */
    const char *server_name;    /* hostname of the server (client only) */
    const char *server_port;    /* port on which the ssl service runs   */
    int debug_level;            /* level of debugging                   */
    int permissive;             /* permissive parsing                   */
} opt;

static void my_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str) {
    ((void) level);

    mbedtls_fprintf((FILE *) ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *) ctx);
}

static int my_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
    char *issuer_dn_buf;
    char *cert_sn;
    ((void) data);
    size_t len = 1024;


    /* Emercoin modification */

    issuer_dn_buf = malloc(len);
    cert_sn = malloc(len);
    memset(issuer_dn_buf, '\0', len);
    memset(cert_sn, '\0', len);

    mbedtls_x509_dn_gets(issuer_dn_buf, len, &crt->issuer);


    mbedtls_printf("\nVerify requested for (Depth %d):\n", depth);
    mbedtls_printf("\nIssuer name:== %s\n", issuer_dn_buf);

    if (strcmp(issuer_dn_buf, EMC_ISSUER_STR) != 0) {
        /* TODO: error management */
        mbedtls_printf("!    Wrong issuer\n");
        /* Create some new flags and set them */
    }

    mbedtls_printf("---[ Check certificate validation time. ]--- ...");

    /* Check time-validity
    if (mbedtls_x509_time_is_past(&crt->valid_to))
        *flags |= MBEDTLS_X509_BADCERT_EXPIRED;

    if (mbedtls_x509_time_is_future(&crt->valid_from))
        *flags |= MBEDTLS_X509_BADCERT_FUTURE;
    mbedtls_printf("OK!\n");*/


    mbedtls_printf("\n---[Extract serial number. ]--- ...");

    mbedtls_x509_serial_gets(cert_sn, len, &crt->serial);

    /*
     * Change the serial number to lower case
     * Remove ':' from serial number
     */

    char modified_sn[1024];
    memset(modified_sn, '\0', 1024);
    int c = 0;
    int j = 0;
    while (cert_sn[c] != '\0') {
        if (cert_sn[c] >= 'A' && cert_sn[c] <= 'Z') {
            if (cert_sn[c] != ':') {
                modified_sn[j] = cert_sn[c] + 32;
                j++;
            }
        } else {
            if (cert_sn[c] != ':') {
                modified_sn[j] = cert_sn[c];
                j++;
            }
        }
        c++;
    }


    mbedtls_printf("OK!\nSerial number: %s\n", modified_sn);

    /* Send the serial number (key of the pair) to the Emercoin core for value retrieval */

    CURL *curl;
    CURLcode res;
    char json_request[1024];

    mbedtls_printf("\n---[ Construct a JSON format for a POST request. ]---\n");

    strcpy(json_request, "{\n\t\"params\": [\n");
    strcat(json_request, "\t\t\"");
    strcat(json_request, modified_sn);
    strcat(json_request, "\",\n\t\t\"hex");
    strcat(json_request, "\"\n");
    strcat(json_request, "\t\t],\n");
    strcat(json_request, "\t\"method\": \"name_show\",\n");
    strcat(json_request, "\t\"id\": 1\n");
    strcat(json_request, "}");
    /*
     *
     * Send a POST request using CURL and receive a response
     *
     */

    struct MemoryStruct chunk;
    curl = curl_easy_init();

    mbedtls_printf("\n---[ Send a POST request to the Emercoin core. ]--- ...\n");

    if (curl) {
        chunk.memory = malloc(1);
        chunk.size = 0;
        curl_easy_setopt(curl, CURLOPT_URL, EMC_CORE_URL);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(json_request));
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_request);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_memory_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &chunk);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            /* TODO: error management
            ctx->error = X509_V_ERR_FAILED_TO_CONNECT_EMC_CORE;
            return -1;
             */
        }
        curl_easy_cleanup(curl);
    } else {
        /* TODO: error management
        ctx->error = X509_V_ERR_FAILED_TO_CONNECT_EMC_CORE;
        return -1;
         */
    }

    mbedtls_printf("OK!\n");

    /* Parse the response and print the result */

    int r, i;
    jsmn_parser p;
    jsmntok_t t[128];
    jsmn_init(&p);

    char lookup_sha256_result[64];
    char lookup_success = -1;

    mbedtls_printf("\n---[ Parse the JSON response and print the result. ]---\n");

    r = jsmn_parse(&p, chunk.memory, strlen(chunk.memory), t, sizeof(t) / sizeof(t[0]));

    if (r < 0) {
        /* TODO: error management
        mbedtls_printf( "Failed to parse JSON: %d\n", r);
        ctx->error = X509_V_ERR_FAILED_TO_PARSE_JSON;
        return -1;
         */
    }

    if (r < 1 || t[0].type != JSMN_OBJECT) {
        /* TODO: error management
        mbedtls_printf("Object expected\n");
        ctx->error = X509_V_ERR_TOP_LEVEL_ELEMENT_IS_NOT_OBJECT;
        return -1;
         */
    }

    /* Loop over all keys of the root object */
    for (i = 1; i < r; i++) {
        if (jsoneq(chunk.memory, &t[i], "error") == 0) {
            mbedtls_printf("- error: %.*s\n", t[i + 1].end - t[i + 1].start, chunk.memory + t[i + 1].start);
            i++;
        } else if (jsoneq(chunk.memory, &t[i], "code") == 0) {
            mbedtls_printf("  - code: %.*s\n", t[i + 1].end - t[i + 1].start, chunk.memory + t[i + 1].start);
            i++;
        } else if (jsoneq(chunk.memory, &t[i], "message") == 0) {
            mbedtls_printf("  - message: %.*s\n", t[i + 1].end - t[i + 1].start, chunk.memory + t[i + 1].start);
            i++;
        } else if (jsoneq(chunk.memory, &t[i], "result") == 0) {
            mbedtls_printf("- result: %.*s\n", t[i + 1].end - t[i + 1].start, chunk.memory + t[i + 1].start);
            i++;
        } else if (jsoneq(chunk.memory, &t[i], "id") == 0) {
            mbedtls_printf("  - id: %.*s\n", t[i + 1].end - t[i + 1].start, chunk.memory + t[i + 1].start);
            i++;
        } else if (jsoneq(chunk.memory, &t[i], "name") == 0) {
            mbedtls_printf("  - name: %.*s\n", t[i + 1].end - t[i + 1].start, chunk.memory + t[i + 1].start);
            i++;
        } else if (jsoneq(chunk.memory, &t[i], "value") == 0) {
            mbedtls_printf("  - value: %.*s\n", t[i + 1].end - t[i + 1].start, chunk.memory + t[i + 1].start);
            lookup_success = 1;
            memcpy(lookup_sha256_result, chunk.memory + t[i + 1].start /*+ 7*/, 64);
            mbedtls_printf("lookup_sha256_result:%.*s, %d\n", 64, lookup_sha256_result, t[i + 1].end - t[i + 1].start);
            i++;
        } else if (jsoneq(chunk.memory, &t[i], "txid") == 0) {
            mbedtls_printf("  - txid: %.*s\n", t[i + 1].end - t[i + 1].start, chunk.memory + t[i + 1].start);
            i++;
        } else if (jsoneq(chunk.memory, &t[i], "address") == 0) {
            mbedtls_printf("  - address: %.*s\n", t[i + 1].end - t[i + 1].start, chunk.memory + t[i + 1].start);
            i++;
        } else if (jsoneq(chunk.memory, &t[i], "expires_in") == 0) {
            mbedtls_printf("  - expires_in: %.*s\n", t[i + 1].end - t[i + 1].start, chunk.memory + t[i + 1].start);
            i++;
        } else if (jsoneq(chunk.memory, &t[i], "expires_at") == 0) {
            mbedtls_printf("  - expires_at: %.*s\n", t[i + 1].end - t[i + 1].start, chunk.memory + t[i + 1].start);
            i++;
        } else if (jsoneq(chunk.memory, &t[i], "time") == 0) {
            mbedtls_printf("  - time: %.*s\n", t[i + 1].end - t[i + 1].start, chunk.memory + t[i + 1].start);
            i++;
        } else if (jsoneq(chunk.memory, &t[i], "expired") == 0) {
            mbedtls_printf("  - expired: %.*s\n", t[i + 1].end - t[i + 1].start, chunk.memory + t[i + 1].start);
            i++;
        } else {
            mbedtls_printf("Unexpected key: %.*s\n", t[i].end - t[i].start, chunk.memory + t[i].start);
        }
    }

    /* Compute the hash of the certificate; check if the hash value is equal to the returned value */

    if (lookup_success < 0) {
        /* TODO: error management
        ctx->error = X509_V_ERR_NO_NAME_IN_EMC_CORE;
        return -1;
         */
    }

    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *info;

    mbedtls_printf("\n---[ Compute the hash of the certificate.]--- ...\n");

    unsigned char md_buf[32];
    unsigned char md_buf_hex[64];
    mbedtls_md_init(&ctx);
    info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_setup(&ctx, info, 0);

    if (!&ctx) {
        /* TODO: error management
        mbedtls_printf("Unknown digest sha256\n");
        ctx->error = X509_V_ERR_INVALID_HASH_FUNC;
        return -1;
         */
    }

    mbedtls_md_starts(&ctx);

    if (!mbedtls_md_update(&ctx, crt->raw.p, crt->raw.len)) {
        /* TODO: Error management */
    }

    mbedtls_md_finish(&ctx, md_buf);

    int step = 0;
    for (i = 0; i < 32; i++) {
        step += sprintf(md_buf_hex + step, "%02x", md_buf[i]);
    }

    mbedtls_printf("OK!\nHash: %s\n", md_buf_hex);

    mbedtls_md_free(&ctx);

    /* Compare the computed hash with the value obtained from the Emercoin Core*/

    for (i = 0; i < 64; i++) {
        if (md_buf_hex[i] != lookup_sha256_result[i]) {
            /* TODO: error management */
            mbedtls_printf("\n!     Error: non-matching SHA256");
        }
    }

    return (0);
}

int main(int argc, char *argv[]) {
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_net_context server_fd;
    unsigned char buf[1024];
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crl cacrl;
    int i, j;
    uint32_t flags;
    int verify = 0;
    char *p, *q;
    const char *pers = "cert_app";

    /*
     * Set to sane values
     */
    mbedtls_net_init(&server_fd);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
#if defined(MBEDTLS_X509_CRL_PARSE_C)
    mbedtls_x509_crl_init(&cacrl);
#else
    /* Zeroize structure as CRL parsing is not supported and we have to pass
       it to the verify function */
    memset( &cacrl, 0, sizeof(mbedtls_x509_crl) );
#endif

    if (argc == 0) {
        usage:
        mbedtls_printf(USAGE);
        goto exit;
    }

    opt.mode = DFL_MODE;
    opt.filename = DFL_FILENAME;
    opt.ca_file = DFL_CA_FILE;
    opt.crl_file = DFL_CRL_FILE;
    opt.ca_path = DFL_CA_PATH;
    opt.server_name = DFL_SERVER_NAME;
    opt.server_port = DFL_SERVER_PORT;
    opt.debug_level = DFL_DEBUG_LEVEL;
    opt.permissive = DFL_PERMISSIVE;

    for (i = 1; i < argc; i++) {
        p = argv[i];
        if ((q = strchr(p, '=')) == NULL)
            goto usage;
        *q++ = '\0';

        for (j = 0; p + j < q; j++) {
            if (argv[i][j] >= 'A' && argv[i][j] <= 'Z')
                argv[i][j] |= 0x20;
        }

        if (strcmp(p, "mode") == 0) {
            if (strcmp(q, "file") == 0)
                opt.mode = MODE_FILE;
            else if (strcmp(q, "ssl") == 0)
                opt.mode = MODE_SSL;
            else
                goto usage;
        } else if (strcmp(p, "filename") == 0)
            opt.filename = q;
        else if (strcmp(p, "ca_file") == 0)
            opt.ca_file = q;
        else if (strcmp(p, "crl_file") == 0)
            opt.crl_file = q;
        else if (strcmp(p, "ca_path") == 0)
            opt.ca_path = q;
        else if (strcmp(p, "server_name") == 0)
            opt.server_name = q;
        else if (strcmp(p, "server_port") == 0)
            opt.server_port = q;
        else if (strcmp(p, "debug_level") == 0) {
            opt.debug_level = atoi(q);
            if (opt.debug_level < 0 || opt.debug_level > 65535)
                goto usage;
        } else if (strcmp(p, "permissive") == 0) {
            opt.permissive = atoi(q);
            if (opt.permissive < 0 || opt.permissive > 1)
                goto usage;
        } else
            goto usage;
    }

    /*
     * 1.1. Load the trusted CA
     */
    mbedtls_printf("  . Loading the CA root certificate ...");
    fflush(stdout);

    if (strlen(opt.ca_path)) {
        if ((ret = mbedtls_x509_crt_parse_path(&cacert, opt.ca_path)) < 0) {
            mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse_path returned -0x%x\n\n", (unsigned int) -ret);
            goto exit;
        }

        verify = 1;
    } else if (strlen(opt.ca_file)) {
        if ((ret = mbedtls_x509_crt_parse_file(&cacert, opt.ca_file)) < 0) {
            mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse_file returned -0x%x\n\n", (unsigned int) -ret);
            goto exit;
        }

        verify = 1;
    }

    mbedtls_printf(" ok (%d skipped)\n", ret);

#if defined(MBEDTLS_X509_CRL_PARSE_C)
    if (strlen(opt.crl_file)) {
        if ((ret = mbedtls_x509_crl_parse_file(&cacrl, opt.crl_file)) != 0) {
            mbedtls_printf(" failed\n  !  mbedtls_x509_crl_parse returned -0x%x\n\n", (unsigned int) -ret);
            goto exit;
        }

        verify = 1;
    }
#endif

    if (opt.mode == MODE_FILE) {
        mbedtls_x509_crt crt;
        mbedtls_x509_crt *cur = &crt;
        mbedtls_x509_crt_init(&crt);

        /*
         * 1.1. Load the certificate(s)
         */
        mbedtls_printf("\n  . Loading the certificate(s) ...");
        fflush(stdout);

        ret = mbedtls_x509_crt_parse_file(&crt, opt.filename);

        if (ret < 0) {
            mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse_file returned %d\n\n", ret);
            mbedtls_x509_crt_free(&crt);
            goto exit;
        }

        if (opt.permissive == 0 && ret > 0) {
            mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse failed to parse %d certificates\n\n", ret);
            mbedtls_x509_crt_free(&crt);
            goto exit;
        }

        mbedtls_printf(" ok\n");

        /*
         * 1.2 Print the certificate(s)
         */
        while (cur != NULL) {
            mbedtls_printf("  . Peer certificate information    ...\n");
            ret = mbedtls_x509_crt_info((char *) buf, sizeof(buf) - 1, "      ",
                                        cur);
            if (ret == -1) {
                mbedtls_printf(" failed\n  !  mbedtls_x509_crt_info returned %d\n\n", ret);
                mbedtls_x509_crt_free(&crt);
                goto exit;
            }

            mbedtls_printf("%s\n", buf);

            cur = cur->next;
        }

        /*
         * 1.3 Verify the certificate
         */
        if (verify) {
            mbedtls_printf("  . Verifying X.509 certificate...");

            if ((ret = mbedtls_x509_crt_verify(&crt, &cacert, &cacrl, NULL, &flags,
                                               my_verify, NULL)) != 0) {
                char vrfy_buf[512];

                mbedtls_printf(" failed\n");

                mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

                mbedtls_printf("%s\n", vrfy_buf);
            } else
                mbedtls_printf(" ok\n");
        }

        mbedtls_x509_crt_free(&crt);
    } else if (opt.mode == MODE_SSL) {
        /*
         * 1. Initialize the RNG and the session data
         */
        mbedtls_printf("\n  . Seeding the random number generator...");
        fflush(stdout);

        mbedtls_entropy_init(&entropy);
        if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                         (const unsigned char *) pers,
                                         strlen(pers))) != 0) {
            mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
            goto ssl_exit;
        }

        mbedtls_printf(" ok\n");

#if defined(MBEDTLS_DEBUG_C)
        mbedtls_debug_set_threshold(opt.debug_level);
#endif

        /*
         * 2. Start the connection
         */
        mbedtls_printf("  . SSL connection to tcp/%s/%s...", opt.server_name,
                       opt.server_port);
        fflush(stdout);

        if ((ret = mbedtls_net_connect(&server_fd, opt.server_name,
                                       opt.server_port, MBEDTLS_NET_PROTO_TCP)) != 0) {
            mbedtls_printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
            goto ssl_exit;
        }

        /*
         * 3. Setup stuff
         */
        if ((ret = mbedtls_ssl_config_defaults(&conf,
                                               MBEDTLS_SSL_IS_CLIENT,
                                               MBEDTLS_SSL_TRANSPORT_STREAM,
                                               MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
            goto exit;
        }

        if (verify) {
            mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
            mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
            mbedtls_ssl_conf_verify(&conf, my_verify, NULL);
        } else
            mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);

        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
        mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

        if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
            goto ssl_exit;
        }

        if ((ret = mbedtls_ssl_set_hostname(&ssl, opt.server_name)) != 0) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
            goto ssl_exit;
        }

        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

        /*
         * 4. Handshake
         */
        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret);
                goto ssl_exit;
            }
        }

        mbedtls_printf(" ok\n");

        /*
         * 5. Print the certificate
         */
#if !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
        mbedtls_printf( "  . Peer certificate information    ... skipped\n" );
#else
        mbedtls_printf("  . Peer certificate information    ...\n");
        ret = mbedtls_x509_crt_info((char *) buf, sizeof(buf) - 1, "      ",
                                    mbedtls_ssl_get_peer_cert(&ssl));
        if (ret == -1) {
            mbedtls_printf(" failed\n  !  mbedtls_x509_crt_info returned %d\n\n", ret);
            goto ssl_exit;
        }

        mbedtls_printf("%s\n", buf);
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */

        mbedtls_ssl_close_notify(&ssl);

        ssl_exit:
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
    } else
        goto usage;

    exit_code = MBEDTLS_EXIT_SUCCESS;

    exit:

    mbedtls_net_free(&server_fd);
    mbedtls_x509_crt_free(&cacert);
#if defined(MBEDTLS_X509_CRL_PARSE_C)
    mbedtls_x509_crl_free(&cacrl);
#endif
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    mbedtls_exit(exit_code);
}

#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C && MBEDTLS_SSL_TLS_C &&
          MBEDTLS_SSL_CLI_C && MBEDTLS_NET_C && MBEDTLS_RSA_C &&
          MBEDTLS_X509_CRT_PARSE_C && MBEDTLS_FS_IO && MBEDTLS_CTR_DRBG_C */
