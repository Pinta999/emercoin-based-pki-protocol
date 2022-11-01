//
// Created by lorep on 06/09/2022.
//

#ifndef PROTOCOL_CLIENT_IDEVID_H
#define PROTOCOL_CLIENT_IDEVID_H

#include <tss2/tss2_tpm2_types.h>

typedef struct TCG_IDEVID_CONTENT_t {
    uint32_t hashAlgoId; // TCG algorithm identifier for CSR hash
    size_t hashSz; // Size, in bytes, of hash used
    size_t prodModelSz; // Size of unterminated product model string
    size_t prodSerialSz;// Size of unterminated product serial number string
    size_t ekCertSz; // TPM EK cert size
    size_t attestPubSz; // Attestation key public size
    size_t padSz;

    unsigned char serializedEk[4096];
    char prodModel[16];
    int prodSerial;
    unsigned char ekCert[4096]; //PEM encoded EK certificate
    uint8_t attestPub[4096]; //IAK public
    TPMA_OBJECT attestAttributes; //IAK attributes
    unsigned char pad[16];
} TCG_CSR_IDEVID_CONTENT;

typedef struct TCG_CSR_t {
    size_t contentSz; // Size of csrContents
    size_t sigSz; // Size, in bytes, of signature
    TCG_CSR_IDEVID_CONTENT csrContents;
    unsigned char signature[1024]; // DER encoded signature, including algorithm ID
} TCG_CSR_IDEVID;


#endif //PROTOCOL_CLIENT_IDEVID_H
