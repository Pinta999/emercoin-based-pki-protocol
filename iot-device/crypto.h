//
// Created by nzazzo on 23/06/22.
//

#ifndef PROTOCOL_CLIENT_CRYPTO_H
#define PROTOCOL_CLIENT_CRYPTO_H

#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/rsa.h>
#include <mbedtls/pem.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/x509_crt.h>

#include "mbedtls/error.h"

#include <string.h>
#include <malloc.h>
#include <stdio.h>

static int write_key(mbedtls_pk_context *key, const char *output_file, int private);

int get_msg_digest(char *msg, unsigned char *digest);

int get_pubkey_from_bytestring(
        unsigned char *pubkey_buffer,
        unsigned char *pubkey_bytes,
        int pubkey_bytes_size,
        mbedtls_pk_context *pk_ctx
);

int verify_signature(
        unsigned char *signed_message,
        unsigned char *signature_bytes,
        int signature_bytes_size,
        mbedtls_pk_context *pk_ctx
);

int gen_rsa_privkey();

int gen_x509_cert(unsigned char *cert_SN, unsigned char *cert_digest);

int gen_device_identity(unsigned char *hex_buf);

int encrypt_message(unsigned char *message, unsigned char *output, mbedtls_pk_context *pk);

int sign_message(unsigned char *to_be_signed, unsigned char *output);

#endif //PROTOCOL_CLIENT_CRYPTO_H
