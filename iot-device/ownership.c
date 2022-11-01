//
// Created by nzazzo on 11/07/22.
//

#include "ownership.h"

/******** Internal functions ********/

int verify_mOwnr(char *message, const int size, unsigned char *new_pubkey) {
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_pk_parse_public_keyfile(&pk, "keys/master_pubkey.pem");

    jsmn_parser parser;
    jsmntok_t tokens[16];
    jsmn_init(&parser);
    int valread = jsmn_parse(&parser, message, size, tokens, 16);
    char signed_message[1024] = {0};

    char tmpkey[16] = {0};
    char command[8] = {0};
    char new_pubkey_hex[512 + 1] = {0};
    char signature_hex[MBEDTLS_PK_SIGNATURE_MAX_SIZE * 2] = {0};
    char signature_bytes[MBEDTLS_PK_SIGNATURE_MAX_SIZE] = {0};

    strncpy(tmpkey, message + tokens[1].start, tokens[1].end - tokens[1].start);
    strncpy(command, message + tokens[2].start, tokens[2].end - tokens[2].start);
    if (strcmp(tmpkey, "command") || strcmp(command, "OWNR")) {
        printf("\n!     Ownership transfer command not found!\n");
        return -1;
    }

    memset(tmpkey, 0, 16);
    strncpy(tmpkey, message + tokens[3].start, tokens[3].end - tokens[3].start);
    strncpy(new_pubkey_hex, message + tokens[4].start, tokens[4].end - tokens[4].start);
    if (strcmp(tmpkey, "new_pubkey")) {
        printf("\n!     New pubkey not found!\n");
        return -1;
    }

    memset(tmpkey, 0, 16);
    strncpy(tmpkey, message + tokens[5].start, tokens[5].end - tokens[5].start);
    strncpy(signature_hex, message + tokens[6].start, tokens[6].end - tokens[6].start);
    if (strcmp(tmpkey, "signature")) {
        printf("\n!     Signature not found!\n");
        return -1;
    }
    from_hex_to_bytes(signature_hex, signature_bytes);
    get_msg_without_signature(signed_message, message, tokens[4]);
    if (verify_signature(signed_message, signature_bytes, strlen(signature_bytes), &pk) < 0) {
        printf("! error - verify_mOwnr(): invalid signature.\n");
        return -1;
    }
    printf("! success - verify_mOwnr(): valid signature.\n");
    from_hex_to_bytes(new_pubkey_hex, new_pubkey);
    return 0;
}

int create_ack_message(char *output) {
    int end = 0;
    char key[16] = {0};
    char value[64 + 1] = {0};
    int nonce;
    char nonce_string[16] = {0};

    /* Get identity from configuration file */
    FILE *fp = fopen("configuration", "r");
    while (!end && fscanf(fp, "%s %s", key, value) != EOF) {
        end = strcmp(key, "ID") ? 0 : 1;
        if (!end) {
            memset(value, 0, 64 + 1);
            memset(key, 0, 16);
        }
    }

    /* Get last nonce from nonce file and increment it*/
    fp = fopen("nonce", "rb");
    fscanf(fp, "%d", &nonce);
    fclose(fp);
    nonce++;

    fp = fopen("nonce", "w");
    fprintf(fp, "%d", nonce);
    fclose(fp);

    /* Generate JSON ack message */
    sprintf(nonce_string, "%d", nonce);
    strcat(output, "{\"id\": \"");
    strcat(output, value);
    strcat(output, "\", \"nonce\": \"");
    strcat(output, nonce_string);
    strcat(output, "\"}");

    /* Compute message signature */
    int siglen, i;
    char *p;
    unsigned char msg_signature[MBEDTLS_PK_SIGNATURE_MAX_SIZE + 1] = {0};
    char msg_signature_hex[MBEDTLS_PK_SIGNATURE_MAX_SIZE * 2 + 1] = {0};
    siglen = sign_message((unsigned char *) output, (unsigned char *) msg_signature);
    if (siglen <= 0) {
        printf("! error - create_ack_message(): signature process failed.\n");
        return -1;
    }
    p = msg_signature_hex;
    for (i = 0; i < siglen; i++)
        p += sprintf(p, "%02x", msg_signature[i]);

    /* Append message signature to the message */
    int json_message_len = strlen(output);
    output[json_message_len - 2] = '"';
    output[json_message_len - 1] = ',';
    strcat(output, " \"signature\": \"");
    strcat(output, msg_signature_hex);
    strcat(output, "\"}");

    return 0;
}

int verify_transaction_acknowledge(unsigned char *message, const int size) {
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_pk_parse_public_keyfile(&pk, "keys/master_pubkey.pem");

    FILE *fp;

    jsmn_parser parser;
    jsmntok_t tokens[16];
    jsmn_init(&parser);
    jsmn_parse(&parser, message, size, tokens, 16);

    int valread;
    char signed_message[1024] = {0};
    char tmpkey[16] = {0};
    char command[8] = {0};
    char nonce_str[16] = {0};
    int stored_nonce;
    int nonce;
    char signature_hex[MBEDTLS_PK_SIGNATURE_MAX_SIZE * 2] = {0};
    char signature_bytes[MBEDTLS_PK_SIGNATURE_MAX_SIZE] = {0};

    strncpy(tmpkey, message + tokens[1].start, tokens[1].end - tokens[1].start);
    strncpy(command, message + tokens[2].start, tokens[2].end - tokens[2].start);
    if (strcmp(tmpkey, "command") || strcmp(command, "REGACK")) {
        printf("\n! error: - ownership: Registraction acknowledge command not found!\n");
        return -1;
    }

    memset(tmpkey, 0, 16);
    strncpy(tmpkey, message + tokens[3].start, tokens[3].end - tokens[3].start);
    strncpy(nonce_str, message + tokens[4].start, tokens[4].end - tokens[4].start);
    if (strcmp(tmpkey, "nonce")) {
        printf("\n! error: - ownership, verify_transaction_acknowledge(): Nonce not found!\n");
        return -1;
    }

    sscanf(nonce_str, "%d", &nonce);
    fp = fopen("nonce", "rb");
    fscanf(fp, "%d", &stored_nonce);
    fclose(fp);

    if (stored_nonce >= nonce) {
        printf("! error: verify_transaction_acknowledge(): old nonce.\n");
        return -1;
    }

    memset(tmpkey, 0, 16);
    strncpy(tmpkey, message + tokens[5].start, tokens[5].end - tokens[5].start);
    strncpy(signature_hex, message + tokens[6].start, tokens[6].end - tokens[6].start);
    if (strcmp(tmpkey, "signature")) {
        printf("\n!     Signature not found!\n");
        return -1;
    }
    valread = from_hex_to_bytes(signature_hex, signature_bytes);
    get_msg_without_signature(signed_message, message, tokens[4]);
    if (verify_signature(signed_message, signature_bytes, valread, &pk) < 0) {
        printf("! error - verify_transaction_acknowledge(): invalid signature.\n");
        return -1;
    }

    fp = fopen("nonce", "w");
    fprintf(fp, "%d", nonce);
    fclose(fp);

    printf("! success - verify_transaction_acknowledge(): valid signature.\n");
    return 0;
}

/************************************/

int ownership(char *message, const int size, int sock) {
    printf("M_ownr received from DM.\n");
    char buffer[4096] = {0};
    int ret = 0;
    int valread = 0;
    unsigned char *new_pubkey = malloc( (256 + 1) * sizeof(unsigned char));
    if ( (ret = verify_mOwnr(message, size, new_pubkey) ) != 0) {
        printf("! error - verify_mOwnr() : invalid signature.\n");
        return ret;
    }
    /* TODO: send back a signed ACK message; after the verification, the DM will create the transaction */
    create_ack_message(buffer);
    send(sock, buffer, strlen(buffer), 0);

    /* Block the client until the DM verifies acknowledge */
    memset(buffer, 0, 4096);
    valread = read(sock, buffer, 4096);
    if ( (ret = verify_transaction_acknowledge(buffer, valread) ) != 0) {
        printf("! error - verify_transaction_acknowledge(): invalid signature or possible errors.\n");
        close(sock);
        return ret;
    }
    close(sock);
    return ret;
}