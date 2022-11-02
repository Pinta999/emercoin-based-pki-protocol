//
// Created by nzazzo on 23/06/22.
//

#include <stdlib.h>
#include "crypto.h"


/*** Global option for key generation ***/

#define KEY_SIZE 2048
#define EXPONENT 65537
#define FORMAT_PEM 0
#define FORMAT_DER 1

struct options_key {
    int type;
    int rsa_keysize;
    int ec_curve;
    const char *filename_priv;
    const char *filename_pub;
    int format;
    int use_dev_random;
} opt_key;

/***************************************/

/*** Options for certificate generation ***/

#define DFL_SUBJECT_KEY         "keys/rsa_privkey.pem"
#define DFL_OUTPUT_FILENAME     "certs/cert.pem"
#define DFL_SUBJECT_NAME        "CN=Test-device, O=thesis, C=IT"
#define DFL_ISSUER_NAME         "O=EmerCoin, OU=PKI, CN=EMCSSL/emailAddress=team@emercoin.com/UID=EMC"
#define DFL_NOT_BEFORE          "20010101000000"
#define DFL_NOT_AFTER           "20301231235959"
#define DFL_VERSION             2 //3
#define DFL_DIGEST              MBEDTLS_MD_SHA256

/******************************************/


/*** Internal functions ***/

static int write_key(mbedtls_pk_context *key, const char *output_file, int private) {
    int ret;
    FILE *f;
    unsigned char output_buf[16000];
    unsigned char *c = output_buf;
    size_t len = 0;

    memset(output_buf, 0, 16000);

    if (private == 1) {
        if ((ret = mbedtls_pk_write_key_pem(key, output_buf, 16000)) != 0)
            return (ret);
    }
    else {
        if ((ret = mbedtls_pk_write_pubkey_pem(key, output_buf, 16000)) != 0)
            return (ret);
    }

    len = strlen((char *) output_buf);

    if ((f = fopen(output_file, "wb")) == NULL)
        return (-1);

    if (fwrite(c, 1, len, f) != len) {
        fclose(f);
        return (-1);
    }

    fclose(f);

    return (0);
}

int write_certificate( mbedtls_x509write_cert *crt, const char *output_file,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng, unsigned char *cert_hash )
{
    int ret;
    FILE *f;
    unsigned char output_buf_pem[4096];
    unsigned char output_buf_der[4096];
    unsigned char err_buf[1024];
    size_t len = 0;

    memset(err_buf, 0, 1024);
    memset( output_buf_pem, 0, 4096 );
    memset( output_buf_der, 0, 4096 );

    if( ( ret = mbedtls_x509write_crt_der( crt, output_buf_der, 4096,
                                           f_rng, p_rng ) ) < 0 ) {
        mbedtls_strerror( ret, err_buf, 1024 );
        return (ret);
    }

    if( ( ret = mbedtls_x509write_crt_pem( crt, output_buf_pem, 4096,
                                           f_rng, p_rng ) ) < 0 ) {
        mbedtls_strerror( ret, err_buf, 1024 );
        return (ret);
    }

    get_msg_digest(output_buf_der, cert_hash);

    len = strlen( (char *) output_buf_pem);

    if( ( f = fopen( output_file, "w" ) ) == NULL )
        return( -1 );

    if( fwrite( output_buf_pem, 1, len, f ) != len )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );

    return( 0 );
}

/**************************/

int get_msg_digest(char *msg, unsigned char *digest) {
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *info;
    mbedtls_md_init(&ctx);
    info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_setup(&ctx, info, 0);
    /* TODO: error check during initialization */

    mbedtls_md_starts(&ctx);
    if (mbedtls_md_update(&ctx, msg, strlen(msg)) != 0) {
        return -1;
    }
    mbedtls_md_finish(&ctx, digest);
    return mbedtls_md_get_size(info);
}

int get_pubkey_from_bytestring(unsigned char *pubkey_buffer, unsigned char *pubkey_bytes, int pubkey_bytes_size, mbedtls_pk_context *pk_ctx) {
    mbedtls_pk_type_t type;

    memcpy(pubkey_bytes, pubkey_buffer, pubkey_bytes_size + 1);
    pubkey_bytes[pubkey_bytes_size] = '\0';
    mbedtls_pk_parse_public_key(pk_ctx, pubkey_bytes, pubkey_bytes_size + 1);
    type = mbedtls_pk_get_type(pk_ctx);
    return type;
}

int verify_signature(unsigned char *signed_message, unsigned char *signature_bytes, int signature_bytes_size, mbedtls_pk_context *pk_ctx) {
    unsigned char digest[32];
    int ret = 0;

    get_msg_digest(signed_message, digest);
    ret = mbedtls_pk_verify(pk_ctx, MBEDTLS_MD_SHA256, digest, 0, signature_bytes, signature_bytes_size);
    return ret;
}

int gen_rsa_privkey() {
    int ret = 1;
    mbedtls_pk_context key;
    char buf[1024];
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&E);
    mbedtls_mpi_init(&DP);
    mbedtls_mpi_init(&DQ);
    mbedtls_mpi_init(&QP);

    mbedtls_pk_init(&key);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    memset(buf, 0, sizeof(buf));

    opt_key.type = MBEDTLS_PK_RSA;
    opt_key.rsa_keysize = 2048;
    opt_key.filename_priv = "keys/rsa_privkey.pem";
    opt_key.filename_pub = "keys/rsa_pubkey.pem";
    opt_key.format = FORMAT_PEM;
    opt_key.ec_curve = 0;
    opt_key.use_dev_random = 0;

    mbedtls_entropy_init(&entropy);


    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     NULL,
                                     0)) != 0) {
        printf(" failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n", (unsigned int) -ret);
        goto exit;
    }


    /*
     *  Generate the key
     */

    if ((ret = mbedtls_pk_setup(&key,
                                mbedtls_pk_info_from_type((mbedtls_pk_type_t) opt_key.type))) != 0) {
        printf(" failed\n  !  mbedtls_pk_setup returned -0x%04x", (unsigned int) -ret);
        goto exit;
    }

    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr_drbg, opt_key.rsa_keysize, 65537);
    if (ret != 0) {
        printf(" failed\n  !  mbedtls_rsa_gen_key returned -0x%04x", (unsigned int) -ret);
        goto exit;
    }

    /* Store in a PEM file both public and secret key */

    ret = write_key(&key, opt_key.filename_priv, 1);
    ret |= write_key(&key, opt_key.filename_pub, 0);
    if (ret != 0) {
        printf("\n  ! failed\n");
        goto exit;
    }

    exit:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&DP);
    mbedtls_mpi_free(&DQ);
    mbedtls_mpi_free(&QP);

    mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}

int gen_x509_cert(unsigned char *cert_SN, unsigned char *cert_digest) {
    int ret = 1;
    mbedtls_x509_crt issuer_crt;
    mbedtls_pk_context loaded_subject_key;
    mbedtls_pk_context *subject_key = &loaded_subject_key;
    char buf[1024];
    mbedtls_x509write_cert crt;
    mbedtls_mpi serial;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_x509write_crt_init( &crt );
    mbedtls_pk_init( &loaded_subject_key );
    mbedtls_mpi_init( &serial );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    mbedtls_x509_crt_init(&issuer_crt);

    memset(buf, 0, 1024);


    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                       NULL,
                                       0 ) ) != 0 )
    {
        printf( " failed\n  !  mbedtls_ctr_drbg_seed returned %d - %s\n",
                        ret, buf );
        goto exit;
    }

    /* In this case, certificate is created with a new SN, otherwise the SN has been provided as input */
    if (cert_SN[0] == 0)
        gen_device_identity(cert_SN);

    if( ( ret = mbedtls_mpi_read_string( &serial, 16, cert_SN ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        printf( " failed\n  !  mbedtls_mpi_read_string "
                        "returned -0x%04x - %s\n\n", (unsigned int) -ret, buf );
        goto exit;
    }
    ret = mbedtls_pk_parse_keyfile( &loaded_subject_key, DFL_SUBJECT_KEY,
                                    NULL, mbedtls_ctr_drbg_random, &ctr_drbg );


    if( ret != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        printf( " failed\n  !  mbedtls_pk_parse_keyfile "
                        "returned -x%02x - %s\n\n", (unsigned int) -ret, buf );
        goto exit;
    }

    mbedtls_x509write_crt_set_subject_key(&crt, subject_key);
    mbedtls_x509write_crt_set_issuer_key(&crt, subject_key);

    if ( (mbedtls_x509write_crt_set_subject_name( &crt, DFL_SUBJECT_NAME ) ) != 0) {
        mbedtls_strerror( ret, buf, 1024 );
        printf( " failed\n  !  mbedtls_x509write_crt_set_subject_name "
                        "returned -0x%04x - %s\n\n", (unsigned int) -ret, buf );
        goto exit;
    }

    if ( (mbedtls_x509write_crt_set_issuer_name( &crt, DFL_ISSUER_NAME ) ) != 0) {
        mbedtls_strerror( ret, buf, 1024 );
        printf( " failed\n  !  mbedtls_x509write_crt_set_issuer_name "
                        "returned -0x%04x - %s\n\n", (unsigned int) -ret, buf );
        goto exit;
    }

    mbedtls_x509write_crt_set_version( &crt, DFL_VERSION );
    mbedtls_x509write_crt_set_md_alg( &crt, DFL_DIGEST );

    if ( (mbedtls_x509write_crt_set_serial( &crt, &serial ) ) != 0) {
        mbedtls_strerror( ret, buf, 1024 );
        printf( " failed\n  !  mbedtls_x509write_crt_set_serial "
                        "returned -0x%04x - %s\n\n", (unsigned int) -ret, buf );
        goto exit;
    }

    if ( (mbedtls_x509write_crt_set_validity( &crt, DFL_NOT_BEFORE, DFL_NOT_AFTER ) ) != 0) {
        mbedtls_strerror( ret, buf, 1024 );
        printf( " failed\n  !  mbedtls_x509write_crt_set_validity "
                        "returned -0x%04x - %s\n\n", (unsigned int) -ret, buf );
        goto exit;
    }

    if( ( ret = write_certificate( &crt, DFL_OUTPUT_FILENAME,
                                   mbedtls_ctr_drbg_random, &ctr_drbg, cert_digest ) ) != 0 )
    {
        printf( " failed\n  !  write_certificate -0x%04x - %s\n\n",
                        (unsigned int) -ret, buf );
        goto exit;
    }

exit:
    mbedtls_x509_crt_free( &issuer_crt );
    mbedtls_x509write_crt_free( &crt );
    mbedtls_pk_free( &loaded_subject_key );
    mbedtls_mpi_free( &serial );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return ret;
}

int gen_device_identity(unsigned char *hex_buf) {
    int i, k, ret = 1;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    unsigned char buf[32];

    memset(buf, 0, 32);

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) "RANDOM_GEN", 10 );
    if( ret != 0 )
    {
        printf( "failed in mbedtls_ctr_drbg_seed: %d\n", ret );
        goto cleanup;
    }
    mbedtls_ctr_drbg_set_prediction_resistance( &ctr_drbg, MBEDTLS_CTR_DRBG_PR_OFF );
    ret = mbedtls_ctr_drbg_write_seed_file( &ctr_drbg, "rand/seedfile" );
    if( ret != 0 )
    {
        printf( "failed in mbedtls_ctr_drbg_write_seed_file: %d\n", ret );
        goto cleanup;
    }

    for(i = 0, k = 768; i < k; i++) {
        ret = mbedtls_ctr_drbg_random( &ctr_drbg, buf, sizeof( buf ) );
        if( ret != 0 )
        {
            goto cleanup;
        }
    }

    char *p = hex_buf;
    for (i = 0; i < 32; i++)
    {
        p += sprintf(p, "%02x", buf[i]);
    }

cleanup:
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    return ret;
}

int encrypt_message(unsigned char *message, unsigned char *output, mbedtls_pk_context *pk) {
    int ret = 1;
    size_t olen = 0;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                       &entropy, NULL,
                                       0 ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n",
                        (unsigned int) -ret );
        goto exit;
    }

    if( ( ret = mbedtls_pk_encrypt( pk, message, strlen( message ),
                                    output, &olen, 256+1,
                                    mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n",
                        (unsigned int) -ret );
        goto exit;
    }

exit:
    mbedtls_entropy_free( &entropy );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    return ret;

}

int sign_message(unsigned char *to_be_signed, unsigned char *output) {
    int ret = 0;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    size_t olen = 0;
    unsigned char hash[32 + 1] = {0};

    mbedtls_pk_init( &pk );
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                       NULL,
                                       0 ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n", (unsigned int) -ret );
        goto exit;
    }

    if( ( ret = mbedtls_pk_parse_keyfile( &pk, "keys/rsa_privkey.pem", "",
                                          mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( " failed\n  ! Could not parse 'keys/rsa_privkey.pem'\n" );
        goto exit;
    }

    get_msg_digest(to_be_signed, hash);
    if( ( ret = mbedtls_pk_sign( &pk, MBEDTLS_MD_SHA256, hash, 0,
                                 output, MBEDTLS_PK_SIGNATURE_MAX_SIZE , &olen,
                                 mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_pk_sign returned -0x%04x\n", (unsigned int) -ret );
        goto exit;
    }

exit:
    mbedtls_pk_free( &pk );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    if (ret != 0)
        return ret;
    return olen;
}










