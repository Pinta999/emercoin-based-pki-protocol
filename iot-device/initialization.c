//
// Created by nzazzo on 20/06/22.
//

#include "initialization.h"

#define BUFF_SIZE 1024



/******** Internal functions ********/

int serializeCsrContent(char *jsonOutput, const TCG_CSR_IDEVID_CONTENT content, size_t serializedEkSz) {
    char tpmNumber[16] = {0};
    strcat(jsonOutput, "{\"hashAlgoId\": \"0000b\", ");
    strcat(jsonOutput, "\"hashSz\": \"");
    sprintf(tpmNumber, "%d", content.hashSz);
    strcat(jsonOutput, tpmNumber);
    memset(tpmNumber, 0, 16);

    strcat(jsonOutput, "\", \"prodModelSz\": \"");
    sprintf(tpmNumber, "%d", content.prodModelSz);
    strcat(jsonOutput, tpmNumber);
    memset(tpmNumber, 0, 16);

    strcat(jsonOutput, "\", \"prodSerialSz\": \"");
    sprintf(tpmNumber, "%d", content.prodSerialSz);
    strcat(jsonOutput, tpmNumber);
    memset(tpmNumber, 0, 16);

    strcat(jsonOutput, "\", \"ekCertSz\": \"");
    sprintf(tpmNumber, "%d", content.ekCertSz);
    strcat(jsonOutput, tpmNumber);
    memset(tpmNumber, 0, 16);

    strcat(jsonOutput, "\", \"attestPubSz\": \"");
    sprintf(tpmNumber, "%d", content.attestPubSz);
    strcat(jsonOutput, tpmNumber);
    memset(tpmNumber, 0, 16);

    strcat(jsonOutput, "\", \"padSz\": \"");
    sprintf(tpmNumber, "%d", content.padSz);
    strcat(jsonOutput, tpmNumber);
    memset(tpmNumber, 0, 16);

    strcat(jsonOutput, "\", \"serializedEk\": \"");
    unsigned char hex_buf_ek[2048] = {0};
    int step = 0;
    int i;
    for (i = 0; i < serializedEkSz; i++) {
        step += sprintf(hex_buf_ek + step, "%02x", content.serializedEk[i]);
    }
    strcat(jsonOutput, hex_buf_ek);

    strcat(jsonOutput, "\", \"prodModel\": \"");
    strcat(jsonOutput, content.prodModel);

    strcat(jsonOutput, "\", \"prodSerial\": \"");
    sprintf(tpmNumber, "%04x", content.prodSerial);
    strcat(jsonOutput, tpmNumber);
    memset(tpmNumber, 0, 16);

    strcat(jsonOutput, "\", \"ekCert\": \"");
    strcat(jsonOutput, content.ekCert);

    strcat(jsonOutput, "\", \"attestPub\": \"");
    unsigned char hex_buf[2048] = {0};
    step = 0;
    for (i = 0; i < content.attestPubSz; i++) {
        step += sprintf(hex_buf + step, "%02x", content.attestPub[i]);
    }
    strcat(jsonOutput, hex_buf);

    strcat(jsonOutput, "\", \"attestAttributes\": \"");
    sprintf(tpmNumber, "%04x", content.attestAttributes);
    strcat(jsonOutput, tpmNumber);

    strcat(jsonOutput, "\", \"pad\": \"");
    strcat(jsonOutput, content.pad);
    strcat(jsonOutput, "\"}");
}

int serializeCsr(char *jsonOutput, const TCG_CSR_IDEVID idevid, size_t serializedEkSz) {
    char tpmNumber[16] = {0};

    strcpy(jsonOutput, "{\"contentSz\": \"");
    sprintf(tpmNumber, "%d", idevid.contentSz);
    strcat(jsonOutput, tpmNumber);
    memset(tpmNumber, 0, 16);

    strcat(jsonOutput, "\", \"sigSz\": \"");
    sprintf(tpmNumber, "%d", idevid.sigSz);
    strcat(jsonOutput, tpmNumber);
    memset(tpmNumber, 0, 16);

    strcat(jsonOutput, "\", \"csrContents\": {");
    strcat(jsonOutput, "\"hashAlgoId\": \"0000b\", ");
    strcat(jsonOutput, "\"hashSz\": \"");
    sprintf(tpmNumber, "%d", idevid.csrContents.hashSz);
    strcat(jsonOutput, tpmNumber);
    memset(tpmNumber, 0, 16);

    strcat(jsonOutput, "\", \"prodModelSz\": \"");
    sprintf(tpmNumber, "%d", idevid.csrContents.prodModelSz);
    strcat(jsonOutput, tpmNumber);
    memset(tpmNumber, 0, 16);

    strcat(jsonOutput, "\", \"prodSerialSz\": \"");
    sprintf(tpmNumber, "%d", idevid.csrContents.prodSerialSz);
    strcat(jsonOutput, tpmNumber);
    memset(tpmNumber, 0, 16);

    strcat(jsonOutput, "\", \"ekCertSz\": \"");
    sprintf(tpmNumber, "%d", idevid.csrContents.ekCertSz);
    strcat(jsonOutput, tpmNumber);
    memset(tpmNumber, 0, 16);

    strcat(jsonOutput, "\", \"attestPubSz\": \"");
    sprintf(tpmNumber, "%d", idevid.csrContents.attestPubSz);
    strcat(jsonOutput, tpmNumber);
    memset(tpmNumber, 0, 16);

    strcat(jsonOutput, "\", \"padSz\": \"");
    sprintf(tpmNumber, "%d", idevid.csrContents.padSz);
    strcat(jsonOutput, tpmNumber);
    memset(tpmNumber, 0, 16);

    strcat(jsonOutput, "\", \"serializedEk\": \"");
    unsigned char hex_buf_ek[2048] = {0};
    int step = 0;
    int i;
    for (i = 0; i < serializedEkSz; i++) {
        step += sprintf(hex_buf_ek + step, "%02x", idevid.csrContents.serializedEk[i]);
    }
    strcat(jsonOutput, hex_buf_ek);

    strcat(jsonOutput, "\", \"prodModel\": \"");
    strcat(jsonOutput, idevid.csrContents.prodModel);

    strcat(jsonOutput, "\", \"prodSerial\": \"");
    sprintf(tpmNumber, "%04x", idevid.csrContents.prodSerial);
    strcat(jsonOutput, tpmNumber);
    memset(tpmNumber, 0, 16);

    strcat(jsonOutput, "\", \"ekCert\": \"");
    strcat(jsonOutput, idevid.csrContents.ekCert);

    strcat(jsonOutput, "\", \"attestPub\": \"");
    unsigned char hex_buf[2048] = {0};
    step = 0;
    for (i = 0; i < idevid.csrContents.attestPubSz; i++) {
        step += sprintf(hex_buf + step, "%02x", idevid.csrContents.attestPub[i]);
    }
    strcat(jsonOutput, hex_buf);

    strcat(jsonOutput, "\", \"attestAttributes\": \"");
    sprintf(tpmNumber, "%04x", idevid.csrContents.attestAttributes);
    strcat(jsonOutput, tpmNumber);

    strcat(jsonOutput, "\", \"pad\": \"");
    strcat(jsonOutput, idevid.csrContents.pad);

    strcat(jsonOutput, "\"}, \"signature\": \"");
    // Transform signature in hex string
    strcat(jsonOutput, idevid.signature);
    strcat(jsonOutput, "\"}");
    return 0;
}



int verify_minit(char *m_init, const int size, unsigned char **dm_pubkey_bytes) {
    jsmn_parser parser;
    jsmntok_t tokens[16];
    jsmn_init(&parser);
    int ret = 0;
    int valread = 0;
    char tmpkey[32] = {0};

    char command[8] = {0};

    char pubkey_hex[1024] = {0};
    unsigned char pubkey_buffer[1024] = {0};

    char signature_hex[1024] = {0};
    unsigned char signature_buffer[1024] = {0};
    
    valread = jsmn_parse(&parser, m_init, 4096, tokens, 16);
    if (valread < 0) {
        printf("\n!   JSON parsing: failed.\n");
        return -1;
    }

    strncpy(tmpkey, m_init + tokens[1].start, tokens[1].end - tokens[1].start);
    strncpy(command, m_init + tokens[2].start, tokens[2].end - tokens[2].start);

    if (strcmp(tmpkey, "command") || strcmp(command, "INIT")) {
        printf("\n!     Initialization command not found!\n");
        return -1;
    }

    memset(tmpkey, 0, 32);
    unsigned char *pubkey_bytes;
    int pubkey_bytes_size = 0;
    mbedtls_pk_context pk_ctx;
    mbedtls_pk_init(&pk_ctx);
    strncpy(tmpkey, m_init + tokens[3].start, tokens[3].end - tokens[3].start);
    mbedtls_pk_type_t type;

    if (!strcmp(tmpkey, "pubkey")) {
        strncpy(pubkey_hex, m_init + tokens[4].start/* + 54*/, tokens[4].end /*- 52*/ - tokens[4].start/* - 54*/);
        pubkey_bytes_size = from_hex_to_bytes(pubkey_hex, pubkey_buffer);
        pubkey_bytes = malloc(pubkey_bytes_size * sizeof(unsigned char) + 1);
        type = get_pubkey_from_bytestring(pubkey_buffer, pubkey_bytes, pubkey_bytes_size, &pk_ctx);
        memcpy(*dm_pubkey_bytes, pubkey_bytes, pubkey_bytes_size);
    }

    memset(tmpkey, 0, 32);
    strncpy(tmpkey, m_init + tokens[7].start, tokens[7].end - tokens[7].start);
    unsigned char *signature_bytes;
    int signature_bytes_size = 0;
    unsigned char signed_message[2 * BUFF_SIZE] = {0};

    mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk_ctx), MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);

    if (!strcmp(tmpkey, "signature")) {
        strncpy(signature_hex, m_init + tokens[8].start, tokens[8].end - tokens[8].start);
        signature_bytes_size = from_hex_to_bytes(signature_hex, signature_buffer);
        signature_bytes = malloc(signature_bytes_size * sizeof(unsigned char) + 1);
        memcpy(signature_bytes, signature_buffer, signature_bytes_size + 1);
        signature_bytes[signature_bytes_size] = '\0';
        get_msg_without_signature(signed_message, m_init, tokens[6]);
        ret = verify_signature(signed_message, signature_bytes, signature_bytes_size, &pk_ctx);
        if (ret != 0) {
            printf("! error - verify_minit(): invalid signature.\n");
            return ret;
        }
        printf("! success - verify_minit(): valid signature.\n");
    }

    mbedtls_pk_free(&pk_ctx);
    free(signature_bytes);
    return ret;
}

int create_tpm_idevid(ESYS_CONTEXT *ectx, char *jsonIdevid, int sock, ESYS_TR *iakHandle, ESYS_TR *iakSession) {
    printf("\n\n[   TCG Device Identification Procedure   ]\n\n");
    TSS2_RC rc;
    TPM2B_SENSITIVE_CREATE inSensitive = {0};

    TPM2B_PUBLIC inPublicRSA = {
            .size = 0,
            .publicArea = {
                    .type = TPM2_ALG_RSA,
                    .nameAlg = TPM2_ALG_SHA256,
                    .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                         TPMA_OBJECT_SIGN_ENCRYPT |
                                         TPMA_OBJECT_RESTRICTED |
                                         TPMA_OBJECT_FIXEDTPM |
                                         TPMA_OBJECT_FIXEDPARENT |
                                         TPMA_OBJECT_SENSITIVEDATAORIGIN),
                    .authPolicy = {
                            .size = 0,
                    },
                    .parameters.rsaDetail = {
                            .symmetric = {
                                    .algorithm = TPM2_ALG_NULL,
                                    .keyBits.aes = 128,
                                    .mode.aes = TPM2_ALG_CFB,
                            },
                            .scheme = {
                                    .scheme =
                                    TPM2_ALG_RSASSA,
                                    .details.rsassa.hashAlg = TPM2_ALG_SHA256
                            },
                            .keyBits = 2048,
                            .exponent = 0,
                    },
                    .unique.rsa = {
                            .size = 0,
                            .buffer = {},
                    }
            }
    };

    TPM2B_PUBLIC inPublicRSA_ek = {
            .publicArea = {
                    .type = TPM2_ALG_RSA,
                    .nameAlg = TPM2_ALG_SHA256,
                    .objectAttributes = (TPMA_OBJECT_DECRYPT |
                                         TPMA_OBJECT_RESTRICTED |
                                         TPMA_OBJECT_FIXEDTPM |
                                         TPMA_OBJECT_FIXEDPARENT |
                                         TPMA_OBJECT_ADMINWITHPOLICY |
                                         TPMA_OBJECT_SENSITIVEDATAORIGIN),
                    .authPolicy = {
                            .size = 32,
                            .buffer = {0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
                                       0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
                                       0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
                                       0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
                                       0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
                                       0x69, 0xAA}
                    },
                    .parameters.rsaDetail = {
                            .symmetric = {
                                    .algorithm = TPM2_ALG_AES,
                                    .keyBits.aes = 128,
                                    .mode.aes = TPM2_ALG_CFB,
                            },
                            .scheme = {
                                    .scheme =
                                    TPM2_ALG_NULL
                            },
                            .keyBits = 2048,
                            .exponent = 0,
                    },
                    .unique.rsa = {
                            .size = 256,
                            .buffer = {0},
                    }
            }
    };

    TPM2B_DATA outsideInfo = {
            .size = 0,
            .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR = {
            .count = 0,
    };

    ESYS_TR objectHandle;
    ESYS_TR ekHandle;

    TPM2B_PUBLIC *outPublic;
    TPM2B_PUBLIC *outPublicEk;

    ESYS_TR session = ESYS_TR_NONE;
    ESYS_TR session2 = ESYS_TR_NONE;
    TPMT_SYM_DEF symmetric = {
            .algorithm = TPM2_ALG_AES,
            .keyBits = {.aes = 128},
            .mode = {.aes = TPM2_ALG_CFB}
    };

    rc = Esys_StartAuthSession(ectx, ESYS_TR_NONE, ESYS_TR_NONE,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               NULL,
                               TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA256,
                               &session);
    if (rc != TSS2_RC_SUCCESS) {
        printf("AuthSession 1 error: %s\n", Tss2_RC_Decode(rc));
        return rc;
    }
    *iakSession = session;

    rc = Esys_StartAuthSession(ectx, ESYS_TR_NONE, ESYS_TR_NONE,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               NULL,
                               TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA256,
                               &session2);
    if (rc != TSS2_RC_SUCCESS) {
        printf("AuthSession 2 error: %s\n", Tss2_RC_Decode(rc));
        return rc;
    }

    TPM2B_NONCE *nonceTPM;
    Esys_TRSess_GetNonceTPM(ectx, session2, &nonceTPM);
    TPM2B_DIGEST cpHashA = {0};
    TPM2B_NONCE policyRef = {0};
    INT32 expiration = -(10*365*24*60*60); /* Expiration ten years */

    rc = Esys_PolicySecret(ectx, ESYS_TR_RH_ENDORSEMENT, session2, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, nonceTPM, &cpHashA, &policyRef, expiration, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Error PolicySecret: %s\n", Tss2_RC_Decode(rc));
        return rc;
    }
    
    printf("Retrieving Endorsement Key...");
    rc = Esys_CreatePrimary(ectx, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            &inSensitive, &inPublicRSA_ek, &outsideInfo, &creationPCR,
                            &ekHandle, &outPublicEk, NULL, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Error in Esys_CreatePrimary 1: %s\n", Tss2_RC_Decode(rc));
        return -1;
    }
    printf("[OK]\nGenerating Attestation Key...");

    rc = Esys_CreatePrimary(ectx, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_PASSWORD,ESYS_TR_NONE, ESYS_TR_NONE,
                            &inSensitive, &inPublicRSA, &outsideInfo, &creationPCR,
                            &objectHandle, &outPublic, NULL, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Error in Esys_CreatePrimary: %s\n", Tss2_RC_Decode(rc));
        return -1;
    }
    printf("[OK]\n");

    *iakHandle = objectHandle;

    rc = Esys_EvictControl(ectx, ESYS_TR_RH_OWNER, objectHandle,
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           TPM2_PERSISTENT_FIRST, &objectHandle);
    if (rc != TSS2_RC_SUCCESS) {
        Esys_TR_FromTPMPublic(ectx, TPM2_PERSISTENT_FIRST,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &objectHandle);
    }

    printf("Retrieving Endorsement Key certificate...");
    TPM2B_PUBLIC *publicArea;
    TPM2B_NAME *name;
    unsigned char *ekCertificate = NULL;
    TPM2B_MAX_NV_BUFFER *ekCertNV = NULL;
    FAPI_CONTEXT *fapiContext;
    Fapi_Initialize(&fapiContext, NULL);
    rc = Fapi_GetCertificate(fapiContext, "/HE/EK", &ekCertificate);
    if (rc != TSS2_RC_SUCCESS) {
        if (ekCertificate != NULL)
            free(ekCertificate);
        ekCertificate = calloc(1078 + 1, 1);
        int tpmSize = 0;

        ESYS_TR ekCertEsapiHandle;
        rc = Esys_TR_FromTPMPublic(ectx, 0x01c00002, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &ekCertEsapiHandle);
        if (rc != TSS2_RC_SUCCESS) {
            printf("\n\nError in Esys_TR_FromTPMPublic(): %s\n\n", Tss2_RC_Decode(rc));
            return -1;
        }
        rc = Esys_NV_Read(ectx, ekCertEsapiHandle, ekCertEsapiHandle, session, ESYS_TR_NONE, ESYS_TR_NONE, 1000 /*1078*/, 0, &ekCertNV);
        if (rc != TSS2_RC_SUCCESS) {
            printf("\n\nError in Esys_NV_Read(): %s\n\n", Tss2_RC_Decode(rc));
            return -1;
        }
        tpmSize = ekCertNV->size;
        memcpy(ekCertificate, ekCertNV->buffer, tpmSize);
        free(ekCertNV);
        rc = Esys_NV_Read(ectx, ekCertEsapiHandle, ekCertEsapiHandle, session, ESYS_TR_NONE, ESYS_TR_NONE, 1078 - tpmSize /*1078*/, tpmSize, &ekCertNV);
        if (rc != TSS2_RC_SUCCESS) {
            printf("\n\nError in Esys_NV_Read(): %s\n\n", Tss2_RC_Decode(rc));
            return -1;
        }
        memcpy(ekCertificate + tpmSize, ekCertNV->buffer, ekCertNV->size);
        free(ekCertNV);
    }

    printf("[OK]\n");

    int i = 0, step = 0;
    rc = Esys_ReadPublic(ectx, objectHandle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &publicArea, &name, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Error in Esys_ReadPublic: %s\n", Tss2_RC_Decode(rc));
        publicArea = outPublic;
    }

    printf("Computing TCG_CSR_IDEVID structure...");

    TCG_CSR_IDEVID idevid = {
            .signature = {0},
            .sigSz = 0,
            .csrContents.serializedEk = {0},
            .csrContents.prodModel = {0},
            .csrContents.attestPub = {0},
            .csrContents.ekCert = {0},
            .csrContents.pad = {0},
    };

    /* Retrieve model name and serial number */
    FILE *fp = NULL;
    char modelName[16] = {0};
    int serialNumber;
    fp = fopen("../device-identity", "r");
    if (fp == NULL) {
        printf("File not found: device-identity\n");
        return -1;
    }
    fscanf(fp, "%s %d", modelName, &serialNumber);
    fclose(fp);

    size_t serializedEkSize = 0;
    Tss2_MU_TPM2B_PUBLIC_Marshal(outPublicEk, idevid.csrContents.serializedEk, 4096, &serializedEkSize);
    Tss2_MU_TPM2B_PUBLIC_Marshal(publicArea, idevid.csrContents.attestPub, 4096, &(idevid.csrContents.attestPubSz));
    idevid.csrContents.attestAttributes = publicArea->publicArea.objectAttributes;
    strcpy(idevid.csrContents.prodModel, modelName);
    idevid.csrContents.prodModelSz = sizeof(idevid.csrContents.prodModel);
    idevid.csrContents.prodSerial = serialNumber;
    idevid.csrContents.prodSerialSz = sizeof(int);
    strcpy(idevid.csrContents.ekCert, ekCertificate);
    idevid.csrContents.ekCertSz = strlen(ekCertificate);
    idevid.csrContents.hashAlgoId = 0x000b;
    idevid.csrContents.hashSz = 256;
    idevid.csrContents.padSz = idevid.contentSz % 16;
    idevid.contentSz = sizeof(idevid.csrContents);

    ESYS_TR sequenceHandle;
    rc = Esys_HashSequenceStart(ectx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_ALG_SHA256, &sequenceHandle);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Error in Esys_HashSequenceStart: %s\n", Tss2_RC_Decode(rc));
        return -1;
    }

    char jsonCsrContent[10*1024] = {0};
    serializeCsrContent(jsonCsrContent, idevid.csrContents, serializedEkSize);

    TPM2B_MAX_BUFFER buff;
    TPM2B_DIGEST *digest;
    TPMT_TK_HASHCHECK *validation;
    int tmpSize = strlen(jsonCsrContent);
    unsigned char *csrPointer = jsonCsrContent;
    while (tmpSize > 1024) {
        memcpy(buff.buffer, csrPointer, 1024);
        buff.size = 1024;
        rc = Esys_SequenceUpdate(ectx, sequenceHandle, session, ESYS_TR_NONE, ESYS_TR_NONE, &buff);
        if (rc != TSS2_RC_SUCCESS) {
            printf("Error in Esys_SequenceUpdate: %s\n", Tss2_RC_Decode(rc));
            return -1;
        }
        tmpSize = tmpSize - 1024;
        csrPointer += 1024;
    }
    memcpy(buff.buffer, csrPointer, tmpSize); //memset to 0?
    buff.size = tmpSize;
    rc = Esys_SequenceComplete(ectx, sequenceHandle, session, ESYS_TR_NONE, ESYS_TR_NONE, &buff, TPM2_RH_ENDORSEMENT,
                               &digest, &validation);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Error in Esys_SequenceComplete: %s\n", Tss2_RC_Decode(rc));
        return -1;
    }

    TPMT_SIGNATURE *signature = NULL;
    TPMT_SIG_SCHEME inScheme = {
            .scheme = TPM2_ALG_RSASSA,
            .details.rsassa.hashAlg = TPM2_ALG_SHA256
    };

    rc = Esys_Sign(ectx, objectHandle, session, ESYS_TR_NONE, ESYS_TR_NONE, digest, &inScheme, validation, &signature);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Error in Esys_Sign: %s\n", Tss2_RC_Decode(rc));
        return -1;
    }

    unsigned char tmpSig[1024] = {0};
    int ret;
    memcpy(tmpSig, signature->signature.rsassa.sig.buffer, signature->signature.rsapss.sig.size);
    idevid.sigSz = signature->signature.rsassa.sig.size;
    step = 0;
    for (i = 0; i < idevid.sigSz; i++) {
        step += sprintf(idevid.signature + step, "%02x", tmpSig[i]);
    }

    serializeCsr(jsonIdevid, idevid, serializedEkSize);
    printf("[OK]\n");
    int sent;
    sent = send(sock, jsonIdevid, strlen(jsonIdevid), 0);
    printf("TCG_CSR_IDEVID struct sent to the DM. Waiting for a challenge to solve...\n");

    unsigned char credentialBuffer[1024] = {0};
    int size;
    if ( (size = read(sock, credentialBuffer, 1024) ) <= 0) {
        printf("error - read() from initialization(), line 21: no credential message received.\n");
        return -1;
    }
    printf("Received encrypted credential blob. Solving the challenge using Endorsement Key...\n");
    jsmn_parser parser;
    jsmntok_t tokens[5];
    jsmn_init(&parser);
    int valread = 0;

    valread = jsmn_parse(&parser, credentialBuffer, size, tokens, 5);
    if (valread < 0) {
        printf("\n!   JSON parsing: failed.\n");
        return -1;
    }

    char credentialBlobHex[256] = {0}, secretHex[1024] = {0};
    strncpy(credentialBlobHex, credentialBuffer + tokens[2].start, tokens[2].end - tokens[2].start);
    strncpy(secretHex, credentialBuffer + tokens[4].start, tokens[4].end - tokens[4].start);
    unsigned char credentialBlobBytes[512] = {0}, secretBytes[512] = {0};
    int credSize = from_hex_to_bytes(credentialBlobHex, credentialBlobBytes);
    int secretSize = from_hex_to_bytes(secretHex, secretBytes);
    TPM2B_ID_OBJECT credentialBlob;
    TPM2B_ENCRYPTED_SECRET secret;
    size_t offset = 0;
    Tss2_MU_TPM2B_ID_OBJECT_Unmarshal(credentialBlobBytes, 512, &offset, &credentialBlob);
    offset = 0;
    Tss2_MU_TPM2B_ENCRYPTED_SECRET_Unmarshal(secretBytes, 512, &offset, &secret);

    TPM2B_DIGEST *certInfo;
    rc = Esys_ActivateCredential(ectx, objectHandle, ekHandle, session, session2, ESYS_TR_NONE, &credentialBlob, &secret, &certInfo);
    if (rc != TSS2_RC_SUCCESS) {
        printf("ActivateCredential error: %s\n", Tss2_RC_Decode(rc));
    }
    printf("[OK]\nReleased nonce: 0x");
    for (i = 0; i < certInfo->size; i++)
        printf("%02x", certInfo->buffer[i]);
    printf("\nSending back challenge solution to the DM...\n");
    size = send(sock, certInfo->buffer, certInfo->size, 0);
    return 0;

}

int create_encrypted_identity_message(unsigned char *dm_pubkey_bytes, ESYS_CONTEXT *ectx, ESYS_TR iakHandle, ESYS_TR iakSession, char *output, unsigned char *id) {
    printf("\n[   Encrypted identity message creation   ]");

    int ret = 1;
    int i;
    char *p;
    unsigned char cert_digest[32 + 1] = {0};
    unsigned char encrypted_sn[256 + 1] = {0};
    unsigned char sn_signature[MBEDTLS_PK_SIGNATURE_MAX_SIZE] = {0};
    mbedtls_pk_context pk_ctx, device_pk_ctx;
    mbedtls_pk_init(&pk_ctx);
    mbedtls_pk_init(&device_pk_ctx);
   
    printf("\n\nGenerating new keypair...");
    /* Generate private key */
    gen_rsa_privkey();

    printf("[OK]\nGenerating self-signed certificate...");
    /* Generate certificate */
    char cert_digest_hex[32 * 2 + 1] = {0};
    gen_x509_cert(id, cert_digest);
    p = cert_digest_hex;
    for (i = 0; i < 32; i++)
        p += sprintf(p, "%02x", cert_digest[i]);
    printf("[OK]\n");

    printf("Encrypting generated ID...");
    /* Encrypt SN */
    char encrypted_sn_hex[256 * 2 + 1] = {0};
    ret = mbedtls_pk_parse_public_key(&pk_ctx, dm_pubkey_bytes, 512);
    if (ret != 0)
        printf("Error parsing pubkey from bytes\n");
    ret = encrypt_message(id, encrypted_sn, &pk_ctx);
    if (ret != 0)
        printf("Error encrypting\n");
    sign_message(encrypted_sn, sn_signature);
    p = encrypted_sn_hex;
    for (i = 0; i < 256; i++)
        p += sprintf(p, "%02x", encrypted_sn[i]);
    printf("[OK]\n");


    /* Getting device RSA pubkey from file */
    unsigned char device_pubkey_buf[512 + 1] = {'\0'};
    unsigned char *device_pubkey = NULL;
    char *device_pubkey_hex = NULL;
    if ((ret = mbedtls_pk_parse_public_keyfile(&device_pk_ctx, "keys/rsa_pubkey.pem")) != 0) {
        printf("\nerror in mbedtls_pk_parse_public_keyfile -- retval: %d\n", ret);
        return ret;
    }
    if ((ret = mbedtls_pk_write_pubkey_pem(&device_pk_ctx, device_pubkey_buf, 512 + 1)) != 0) {
        printf("\nerror in mbedtls_pk_write_key_pem -- retval: %d\n", ret);
        return ret;
    }

    /* Moving pubkey bytes from the buffer to another array with right allocation size */
    int buflen = strlen(device_pubkey_buf);
    device_pubkey = malloc(sizeof(unsigned char) * (buflen + 1));
    memset(device_pubkey, 0, sizeof(unsigned char) * (buflen + 1));
    memcpy(device_pubkey, device_pubkey_buf, buflen);
    device_pubkey_hex = malloc(sizeof(char) * (buflen * 2 + 1));
    memset(device_pubkey_hex, 0, sizeof(char) * (buflen * 2 + 1));
    p = device_pubkey_hex;
    for (i = 0; device_pubkey[i] != 0; i++)
        p += sprintf(p, "%02x", device_pubkey[i]);


    printf("Creating encrypted identity message that will be sent to the DM...");
    /* Create JSON message */
    strcat(output, "{\"encrypted_SN\": \"");
    strcat(output, encrypted_sn_hex);
    strcat(output, "\", \"cert_digest\": \"");
    strcat(output, cert_digest_hex);
    strcat(output, "\", \"device_pubkey\": \"");
    strcat(output, device_pubkey_hex);
    strcat(output, "\"}");
    printf("[OK]\n");
    /* Compute message signature with attestation key */
    char msg_signature_hex[MBEDTLS_PK_SIGNATURE_MAX_SIZE * 2 + 1] = {0};

    printf("Computing signature using Attestation Key...");
    TSS2_RC rc;
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
    unsigned char *csrPointer = output;
    while (tmpSize > 1024) {
        memcpy(buff.buffer, csrPointer, 1024);
        buff.size = 1024;
        rc = Esys_SequenceUpdate(ectx, sequenceHandle, iakSession, ESYS_TR_NONE, ESYS_TR_NONE, &buff);
        if (rc != TSS2_RC_SUCCESS) {
            printf("Error in Esys_SequenceUpdate: %s\n", Tss2_RC_Decode(rc));
            return -1;
        }
        tmpSize = tmpSize - 1024;
        csrPointer += 1024;
    }
    memcpy(buff.buffer, csrPointer, tmpSize); //memset to 0?
    buff.size = tmpSize;
    rc = Esys_SequenceComplete(ectx, sequenceHandle, iakSession, ESYS_TR_NONE, ESYS_TR_NONE, &buff, TPM2_RH_ENDORSEMENT,
                               &digest, &validation);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Error in Esys_SequenceComplete: %s\n", Tss2_RC_Decode(rc));
        return -1;
    }

    TPMT_SIGNATURE *signature = NULL;
    TPMT_SIG_SCHEME inScheme = {
            .scheme = TPM2_ALG_RSASSA,
            .details.rsassa.hashAlg = TPM2_ALG_SHA256
    };

    rc = Esys_Sign(ectx, iakHandle, iakSession, ESYS_TR_NONE, ESYS_TR_NONE, digest, &inScheme, validation, &signature);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Error in Esys_Sign in create_encrypted_identity(): %s\n", Tss2_RC_Decode(rc));
        return -1;
    }
    printf("[OK]\n");

    p = msg_signature_hex;
    for (i = 0; i < signature->signature.rsassa.sig.size; i++)
        p += sprintf(p, "%02x", signature->signature.rsassa.sig.buffer[i]);

    /* Append message signature to the message */
    int json_message_len = strlen(output);
    output[json_message_len - 2] = '"';
    output[json_message_len - 1] = ',';
    strcat(output, " \"signature\": \"");
    strcat(output, msg_signature_hex);
    strcat(output, "\"}");

    free(device_pubkey);
    free(device_pubkey_hex);
    return ret;
}

int verify_cReg(char *cReg_message, const int size, unsigned char *dm_pubkey_bytes) {
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

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    if ( (ret = mbedtls_pk_parse_public_key(&pk, dm_pubkey_bytes, strlen(dm_pubkey_bytes) + 1) ) != 0) {
        printf("\nPubkey parsing error\n");
        return ret;
    }

    FILE *fp = NULL;

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
    printf("! success - verify_cReg(): valid signature.\n ");
    return 0;
}

int save_configuration(char *m_init, const int size, unsigned char *id) {
    jsmn_parser parser;
    jsmntok_t tokens[16];
    jsmn_init(&parser);

    jsmn_parse(&parser, m_init, size, tokens, 16);

    char tmpkey[16] = {0};
    char status[32] = "STATUS RUNNING\n";
    char id_str[128] = "ID ";
    strcat(id_str, id);
    strcat(id_str, "\n");
    char exp_date[32] = "EXP_DATE ";

    strncpy(tmpkey, m_init + tokens[5].start, tokens[5].end - tokens[5].start);
    if (strcmp(tmpkey, "exp_date")) {
        printf("\n! error - save_configuration(): Expiration date not found.\n");
        return -1;
    }
    strncat(exp_date, m_init + tokens[6].start, tokens[6].end - tokens[6].start);
    strcat(exp_date, "\n");


    FILE *fp = fopen("configuration", "wb");
    fprintf(fp, "%s", status);
    fprintf(fp, "%s", id_str);
    fprintf(fp, "%s", exp_date);
    fclose(fp);
    return 0;
}

/************************************/

int initializazion(char *m_init, const int size, int sock) {
    clock_t start, end;
    double cpu_time_used;
    start = clock();

    printf("M_init received from DM.\n");
    FILE *fp = NULL;
    int ret = 0;
    unsigned char buffer[2048] = {0};
    unsigned char *dm_pubkey_bytes = malloc(512 * sizeof(unsigned char));
    memset(dm_pubkey_bytes, 0, 512);
    unsigned char enc_identity_msg[4096] = {0};
    char jsonIdevid[20*1024] = {0};
    unsigned char id[64 + 1] = {0};

    ESYS_CONTEXT *ectx;
    TSS2_RC rc;
    ESYS_TR iakHandle;
    ESYS_TR iakSession;
    rc = Esys_Initialize(&ectx, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Error in Esys_Initialize: %s\n", Tss2_RC_Decode(rc));
        return rc;
    }

    if (verify_minit(m_init, size, &dm_pubkey_bytes) != 0) {
        printf("! error - verify_minit() : invalid signature.\n");
        return ret;
    } else {
        create_tpm_idevid(ectx, jsonIdevid, sock, &iakHandle, &iakSession);
        create_encrypted_identity_message(dm_pubkey_bytes, ectx, iakHandle, iakSession, enc_identity_msg, id);

        printf("Sending encrypted identity message to the DM...");
        send(sock, enc_identity_msg, strlen(enc_identity_msg), 0);
        printf("[OK]\nWaiting for registration acknowledgement...\n");
        if (read(sock, buffer, 2048) <= 0) {
            printf("error - read() from initialization(), line 21: no cReg message received.\n");
            return -1;
        }
       
        if ((ret = verify_cReg(buffer, strlen(buffer), dm_pubkey_bytes)) != 0) {
            printf("! error - verify_cReg() : invalid signature.\n");
            return ret;
        }
        /* TODO: Save DM pubkey */
        fp = fopen("keys/master_pubkey.pem", "wb");
        fwrite(dm_pubkey_bytes, 1, strlen(dm_pubkey_bytes), fp);
        fclose(fp);

        /* Save configuration */
        save_configuration(m_init, size, id);
    }
    end = clock();
    cpu_time_used = ( (double) (end - start) / CLOCKS_PER_SEC);
    printf("\n\nInitialization process time: %f\n\n", cpu_time_used);
    free(dm_pubkey_bytes);
    return ret;
}
