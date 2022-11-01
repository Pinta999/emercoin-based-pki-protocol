//
// Created by nzazzo on 14/07/22.
//

#include "update.h"


int verify_mUpdt(char *message, const int size, unsigned char *new_pubkey) {
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_pk_parse_public_keyfile(&pk, "keys/master_pubkey.pem");
    mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);


    jsmn_parser parser;
    jsmntok_t tokens[16];
    jsmn_init(&parser);
    int parseRead = jsmn_parse(&parser, message, 4096, tokens, 16);
    if (parseRead < 0) {
        printf("\n!   JSON parsing: failed.\n");
        return -1;
    }

    int valread = 0;
    char signed_message[1024] = {0};
    char tmpkey[16] = {0};
    char command[8] = {0};
    char new_pubkey_hex[1024 + 1] = {0};
    char signature_hex[MBEDTLS_PK_SIGNATURE_MAX_SIZE * 2] = {0};
    char signature_bytes[MBEDTLS_PK_SIGNATURE_MAX_SIZE] = {0};

    strncpy(tmpkey, message + tokens[1].start, tokens[1].end - tokens[1].start);
    strncpy(command, message + tokens[2].start, tokens[2].end - tokens[2].start);
    if (strcmp(tmpkey, "command") || strcmp(command, "UPDT")) {
        printf("! error - verify_mUpdt(): update command not found.\n");
        return -1;
    }

    char tmpkey2[16] = {0};
    strncpy(tmpkey2, message + tokens[3].start, tokens[3].end - tokens[3].start);
    strncpy(new_pubkey_hex, message + tokens[4].start, tokens[4].end - tokens[4].start);
    if (strcmp(tmpkey2, "new_pubkey")) {
        printf("\n! error - verify_mUpdt(): new pubkey not found!\n");
        return -1;
    }

    memset(tmpkey, 0, 16);
    strncpy(tmpkey, message + tokens[5].start, tokens[5].end - tokens[5].start);
    strncpy(signature_hex, message + tokens[6].start, tokens[6].end - tokens[6].start);
    if (strcmp(tmpkey, "signature")) {
        printf("! error - verify_mUpdt(): signature not found.\n");
        return -1;
    }

    valread = from_hex_to_bytes(signature_hex, signature_bytes);
    get_msg_without_signature(signed_message, message, tokens[4]);
    if (verify_signature(signed_message, signature_bytes, valread, &pk) < 0) {
        printf("! error - verify_mUpdt(): invalid signature.\n");
        return -1;
    }
    printf("! success - verify_mUpdt(): valid signature.\n");
    from_hex_to_bytes(new_pubkey_hex, new_pubkey);
    return 0;
}

int create_new_identity_message(unsigned char *dm_pubkey_bytes, char *output, unsigned char *id) {
    char *p = NULL;
    int i;


    mbedtls_pk_context pk_ctx, device_pk_ctx;
    mbedtls_pk_init(&pk_ctx);
    mbedtls_pk_init(&device_pk_ctx);

    /* Generate new keypair - stored on keys/ directory */
    gen_rsa_privkey();

    /* Generate new certificate */
    unsigned char cert_digest[32 + 1] = {0};
    char cert_digest_hex[32 * 2 + 1] = {0};
    gen_x509_cert(id, cert_digest);
    p = cert_digest_hex;
    for (i = 0; i < 32; i++)
        p += sprintf(p, "%02x", cert_digest[i]);


    /* Getting device RSA pubkey from file */
    int ret;
    unsigned char device_pubkey_buf[512 + 1] = {'\0'};
    char *device_pubkey_hex = NULL;
    if ((ret = mbedtls_pk_parse_public_keyfile(&device_pk_ctx, "keys/rsa_pubkey.pem")) != 0) {
        printf("! error - mbedtls_pk_parse_public_keyfile() -- retval: %d\n", ret);
        return ret;
    }
    if ((ret = mbedtls_pk_write_pubkey_pem(&device_pk_ctx, device_pubkey_buf, 512 + 1)) != 0) {
        printf("\nerror - mbedtls_pk_write_key_pem() -- retval: %d\n", ret);
        return ret;
    }
    int buflen = strlen(device_pubkey_buf);
    device_pubkey_hex = calloc(buflen * 2 + 1, sizeof(char));
    p = device_pubkey_hex;
    for (i = 0; device_pubkey_buf[i] != 0; i++)
        p += sprintf(p, "%02x", device_pubkey_buf[i]);

    /* Create JSON message */
    strcat(output, "{\"identity\": \"");
    strcat(output, id);
    strcat(output, "\", \"new_pubkey\": \"");
    strcat(output, device_pubkey_hex);
    strcat(output, "\", \"cert_digest\": \"");
    strcat(output, cert_digest_hex);
    strcat(output, "\"}");

    /* Compute message signature using TPM IAK */
    ESYS_CONTEXT *ectx;
    TSS2_RC rc;
    ESYS_TR iakHandle;
    ESYS_TR iakSession;
    unsigned char iakBuffer[512] = {0};
    rc = Esys_Initialize(&ectx, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Error in Esys_Initialize: %s\n", Tss2_RC_Decode(rc));
        return rc;
    }
    TPMT_SYM_DEF symmetric = {
            .algorithm = TPM2_ALG_AES,
            .keyBits = {.aes = 128},
            .mode = {.aes = TPM2_ALG_CFB}
    };
    rc = Esys_StartAuthSession(ectx, ESYS_TR_NONE, ESYS_TR_NONE,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               NULL,
                               TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA256,
                               &iakSession);
    if (rc != TSS2_RC_SUCCESS) {
        printf("AuthSession 1 error: %s\n", Tss2_RC_Decode(rc));
        return rc;
    }

    FILE *fp = fopen("keys/serializedIak", "rb");
    if (fp == NULL) {
        printf("fopen() error: the file/directory may not exist\n");
        return -1;
    }

    rc = Esys_TR_FromTPMPublic(ectx, TPM2_PERSISTENT_FIRST,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &iakHandle);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_TR_FromTPMPublic() failure: %s\n", Tss2_RC_Decode(rc));
        return rc;
    }

    /** Compute digest for signature **/
    ESYS_TR sequenceHandle;
    rc = Esys_HashSequenceStart(ectx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_ALG_SHA256, &sequenceHandle);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Error in Esys_HashSequenceStart: %s\n", Tss2_RC_Decode(rc));
        return -1;
    }
    TPM2B_MAX_BUFFER buff;
    TPM2B_DIGEST *digest;
    TPMT_TK_HASHCHECK *validation;
    int tmpSize = strlen(output);
    unsigned char *msgPointer = output;

    while (tmpSize > 1024) {
        memcpy(buff.buffer, msgPointer, 1024);
        buff.size = 1024;
        rc = Esys_SequenceUpdate(ectx, sequenceHandle, iakSession, ESYS_TR_NONE, ESYS_TR_NONE, &buff);
        if (rc != TSS2_RC_SUCCESS) {
            printf("Error in Esys_SequenceUpdate: %s\n", Tss2_RC_Decode(rc));
            return -1;
        }
        tmpSize = tmpSize - 1024;
        msgPointer += 1024;
    }

    memset(buff.buffer, 0, 1024);
    memcpy(buff.buffer, msgPointer, tmpSize);
    buff.size = tmpSize;
    rc = Esys_SequenceComplete(ectx, sequenceHandle, iakSession, ESYS_TR_NONE, ESYS_TR_NONE, &buff, TPM2_RH_ENDORSEMENT,
                               &digest, &validation);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Error in Esys_SequenceComplete: %s\n", Tss2_RC_Decode(rc));
        return -1;
    }


    /** Signature **/
    TPMT_SIGNATURE *signature = NULL;
    TPMT_SIG_SCHEME inScheme = {
            .scheme = TPM2_ALG_RSASSA,
            .details.rsassa.hashAlg = TPM2_ALG_SHA256
    };

    rc = Esys_Sign(ectx, iakHandle, iakSession, ESYS_TR_NONE, ESYS_TR_NONE, digest, &inScheme, validation, &signature);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Error in Esys_Sign: %s\n", Tss2_RC_Decode(rc));
        return -1;
    }

    unsigned char tmpSig[1024] = {0};
    memcpy(tmpSig, signature->signature.rsassa.sig.buffer, signature->signature.rsapss.sig.size);
    size_t sigSize = signature->signature.rsassa.sig.size;
    char msg_signature_hex[MBEDTLS_PK_SIGNATURE_MAX_SIZE * 2 + 1] = {0};
    p = msg_signature_hex;
    for (i = 0; i < sigSize; i++) {
        p += sprintf(p, "%02x", tmpSig[i]);
    }

    int json_message_len = strlen(output);
    output[json_message_len - 2] = '"';
    output[json_message_len - 1] = ',';
    strcat(output, " \"signature\": \"");
    strcat(output, msg_signature_hex);
    strcat(output, "\"}");

    free(device_pubkey_hex);
    return ret;
}

int verify_updtAck(char *cReg_message, const int size, unsigned char *dm_pubkey_bytes) {
    int ret = 0;
    jsmn_parser parser;
    jsmntok_t tokens[16];
    jsmn_init(&parser);
    char signed_message[1024] = {0};
    char tmpkey[16] = {0};
    char command[8] = {0};
    char signature[MBEDTLS_PK_SIGNATURE_MAX_SIZE * 2] = {0};
    int signature_size;
    unsigned char signature_bytes[MBEDTLS_PK_SIGNATURE_MAX_SIZE] = {0};
    char nonce[32 + 1] = {0};
    int old_nonce, new_nonce;

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    if ( (ret = mbedtls_pk_parse_public_key(&pk, dm_pubkey_bytes, strlen(dm_pubkey_bytes) + 1) ) != 0) {
        printf("\nPubkey parsing error\n");
        return ret;
    }

    FILE *fp = fopen("nonce", "r");
    fscanf(fp, "%d", &old_nonce);
    fclose(fp);

    int valread = 0;
    valread = jsmn_parse(&parser, cReg_message, size, tokens, 16);
    if (valread < 0) {
        printf("\n!   JSON parsing: failed.\n");
        return -1;
    }

    strncpy(tmpkey, cReg_message + tokens[1].start, tokens[1].end - tokens[1].start);
    strncpy(command, cReg_message + tokens[2].start, tokens[2].end - tokens[2].start);
    if (strcmp(tmpkey, "command") || strcmp(command, "REGACK")) {
        printf("\n!     Initialization command not found!\n");
        return -1;
    }

    memset(tmpkey, 0, 16);
    strncpy(tmpkey, cReg_message + tokens[3].start, tokens[3].end - tokens[3].start);
    strncpy(nonce, cReg_message + tokens[4].start, tokens[4].end - tokens[4].start);
    if (strcmp(tmpkey, "nonce")) {
        printf("\n!     Nonce not found!\n");
        return -1;
    }

    sscanf(nonce, "%d", &new_nonce);
    if (old_nonce >= new_nonce) {
        printf("! error - verify_updtAck(), update.c : old nonce received.\n");
        return -1;
    }

    memset(tmpkey, 0, 16);
    strncpy(tmpkey, cReg_message + tokens[5].start, tokens[5].end - tokens[5].start);
    strncpy(signature, cReg_message + tokens[6].start, tokens[6].end - tokens[6].start);
    if (strcmp(tmpkey, "signature")) {
        printf("\n      Signature not found!\n");
        return -1;
    }
    get_msg_without_signature(signed_message, cReg_message, tokens[4]);
    signature_size = from_hex_to_bytes(signature, signature_bytes);
    if (verify_signature(signed_message, signature_bytes, signature_size, &pk) != 0) {
        return -1;
    }

    fp = fopen("nonce", "w");
    fprintf(fp, "%s", nonce);
    fclose(fp);
    printf("! success - verify_updtAck(): valid signature.\n ");
    return 0;
}

int update(char *message, const int size, int sock) {
    printf("M_updt received from DM.\n");
    char buffer[4096] = {0};
    unsigned char id[64 + 1] = {0};
    int ret = 0;
    int valread = 0;
    FILE *fp = NULL;
    unsigned char *new_pubkey = calloc(512 + 1, sizeof(unsigned char));
    if ( (ret = verify_mUpdt(message, size, new_pubkey) ) != 0 ) {
        return ret;
    }
    get_conf_device_id(id);
    create_new_identity_message(new_pubkey, buffer, id);
    printf("\n\nGenerated message:\n%s\n", buffer);
    send(sock, buffer, strlen(buffer), 0);
    memset(buffer, 0, 4096);
    valread = read(sock, buffer, 2048);
    verify_updtAck(buffer, valread, new_pubkey);

    fp = fopen("keys/master_pubkey.pem", "wb");
    fwrite(new_pubkey, 1, strlen(new_pubkey), fp);
    fclose(fp);

    send(sock, "", 1, 0);
    return 0;

}