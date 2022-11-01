#line 2 "suites/main_test.function"
/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script:
 * generate_test_code.py
 *
 * Test file      : ./test_suite_mpi.c
 *
 * The following files were used to create this file.
 *
 *      Main code file      : /home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/main_test.function
 *      Platform code file  : /home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/host_test.function
 *      Helper file         : /home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/helpers.function
 *      Test suite file     : /home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function
 *      Test suite data     : /home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.data
 *
 */

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L // for fileno() from <stdio.h>
#endif
#endif

#include "mbedtls/build_info.h"

/* Test code may use deprecated identifiers only if the preprocessor symbol
 * MBEDTLS_TEST_DEPRECATED is defined. When building tests, set
 * MBEDTLS_TEST_DEPRECATED explicitly if MBEDTLS_DEPRECATED_WARNING is
 * enabled but the corresponding warnings are not treated as errors.
 */
#if !defined(MBEDTLS_DEPRECATED_REMOVED) && !defined(MBEDTLS_DEPRECATED_WARNING)
#define MBEDTLS_TEST_DEPRECATED
#endif

/*----------------------------------------------------------------------------*/
/* Common helper code */

#line 2 "suites/helpers.function"
/*----------------------------------------------------------------------------*/
/* Headers */

#include <test/helpers.h>
#include <test/macros.h>
#include <test/random.h>
#include <test/psa_crypto_helpers.h>

#include <stdlib.h>

#if defined (MBEDTLS_ERROR_C)
#include "mbedtls/error.h"
#endif
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_snprintf   snprintf
#define mbedtls_calloc     calloc
#define mbedtls_free       free
#define mbedtls_exit       exit
#define mbedtls_time       time
#define mbedtls_time_t     time_t
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#ifdef _MSC_VER
#include <basetsd.h>
typedef UINT8 uint8_t;
typedef INT32 int32_t;
typedef UINT32 uint32_t;
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#else
#include <stdint.h>
#endif

#include <string.h>

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__)) || defined(__MINGW32__)
#include <strings.h>
#endif

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#endif

/* Type for Hex parameters */
typedef struct data_tag
{
    uint8_t *   x;
    uint32_t    len;
} data_t;

/*----------------------------------------------------------------------------*/
/* Status and error constants */

#define DEPENDENCY_SUPPORTED            0   /* Dependency supported by build */
#define KEY_VALUE_MAPPING_FOUND         0   /* Integer expression found */
#define DISPATCH_TEST_SUCCESS           0   /* Test dispatch successful */

#define KEY_VALUE_MAPPING_NOT_FOUND     -1  /* Integer expression not found */
#define DEPENDENCY_NOT_SUPPORTED        -2  /* Dependency not supported */
#define DISPATCH_TEST_FN_NOT_FOUND      -3  /* Test function not found */
#define DISPATCH_INVALID_TEST_DATA      -4  /* Invalid test parameter type.
                                               Only int, string, binary data
                                               and integer expressions are
                                               allowed */
#define DISPATCH_UNSUPPORTED_SUITE      -5  /* Test suite not supported by the
                                               build */

/*----------------------------------------------------------------------------*/
/* Global variables */

/*----------------------------------------------------------------------------*/
/* Helper flags for complex dependencies */

/* Indicates whether we expect mbedtls_entropy_init
 * to initialize some strong entropy source. */
#if !defined(MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES) && \
    ( !defined(MBEDTLS_NO_PLATFORM_ENTROPY) ||      \
        defined(MBEDTLS_ENTROPY_HARDWARE_ALT) ||    \
        defined(ENTROPY_NV_SEED) )
#define ENTROPY_HAVE_STRONG
#endif


/*----------------------------------------------------------------------------*/
/* Helper Functions */

#if defined(MBEDTLS_PSA_CRYPTO_C)
/** Check that no PSA Crypto key slots are in use.
 *
 * If any slots are in use, mark the current test as failed.
 *
 * \return 0 if the key store is empty, 1 otherwise.
 */
int test_fail_if_psa_leaking( int line_no, const char *filename )
{
    const char *msg = mbedtls_test_helper_is_psa_leaking( );
    if( msg == NULL )
        return 0;
    else
    {
        mbedtls_test_fail( msg, line_no, filename );
        return 1;
    }
}
#endif /* defined(MBEDTLS_PSA_CRYPTO_C) */

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
static int redirect_output( FILE* out_stream, const char* path )
{
    int out_fd, dup_fd;
    FILE* path_stream;

    out_fd = fileno( out_stream );
    dup_fd = dup( out_fd );

    if( dup_fd == -1 )
    {
        return( -1 );
    }

    path_stream = fopen( path, "w" );
    if( path_stream == NULL )
    {
        close( dup_fd );
        return( -1 );
    }

    fflush( out_stream );
    if( dup2( fileno( path_stream ), out_fd ) == -1 )
    {
        close( dup_fd );
        fclose( path_stream );
        return( -1 );
    }

    fclose( path_stream );
    return( dup_fd );
}

static int restore_output( FILE* out_stream, int dup_fd )
{
    int out_fd = fileno( out_stream );

    fflush( out_stream );
    if( dup2( dup_fd, out_fd ) == -1 )
    {
        close( out_fd );
        close( dup_fd );
        return( -1 );
    }

    close( dup_fd );
    return( 0 );
}
#endif /* __unix__ || __APPLE__ __MACH__ */


#line 43 "suites/main_test.function"


/*----------------------------------------------------------------------------*/
/* Test Suite Code */


#define TEST_SUITE_ACTIVE

#if defined(MBEDTLS_BIGNUM_C)
#line 2 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
#include "mbedtls/bignum.h"
#include "mbedtls/entropy.h"

#if MBEDTLS_MPI_MAX_BITS > 792
#define MPI_MAX_BITS_LARGER_THAN_792
#endif

/* Check the validity of the sign bit in an MPI object. Reject representations
 * that are not supported by the rest of the library and indicate a bug when
 * constructing the value. */
static int sign_is_valid( const mbedtls_mpi *X )
{
    if( X->s != 1 && X->s != -1 )
        return( 0 ); // invalid sign bit, e.g. 0
    if( mbedtls_mpi_bitlen( X ) == 0 && X->s != 1 )
        return( 0 ); // negative zero
    return( 1 );
}

typedef struct mbedtls_test_mpi_random
{
    data_t *data;
    size_t  pos;
    size_t  chunk_len;
} mbedtls_test_mpi_random;

/*
 * This function is called by the Miller-Rabin primality test each time it
 * chooses a random witness. The witnesses (or non-witnesses as provided by the
 * test) are stored in the data member of the state structure. Each number is in
 * the format that mbedtls_mpi_read_string understands and is chunk_len long.
 */
int mbedtls_test_mpi_miller_rabin_determinizer( void* state,
                                                unsigned char* buf,
                                                size_t len )
{
    mbedtls_test_mpi_random *random = (mbedtls_test_mpi_random*) state;

    if( random == NULL || random->data->x == NULL || buf == NULL )
        return( -1 );

    if( random->pos + random->chunk_len > random->data->len
            || random->chunk_len > len )
    {
        return( -1 );
    }

    memset( buf, 0, len );

    /* The witness is written to the end of the buffer, since the buffer is
     * used as big endian, unsigned binary data in mbedtls_mpi_read_binary.
     * Writing the witness to the start of the buffer would result in the
     * buffer being 'witness 000...000', which would be treated as
     * witness * 2^n for some n. */
    memcpy( buf + len - random->chunk_len, &random->data->x[random->pos],
            random->chunk_len );

    random->pos += random->chunk_len;

    return( 0 );
}

/* Random generator that is told how many bytes to return. */
static int f_rng_bytes_left( void *state, unsigned char *buf, size_t len )
{
    size_t *bytes_left = state;
    size_t i;
    for( i = 0; i < len; i++ )
    {
        if( *bytes_left == 0 )
            return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
        buf[i] = *bytes_left & 0xff;
        --( *bytes_left );
    }
    return( 0 );
}

/* Test whether bytes represents (in big-endian base 256) a number b that
 * is significantly above a power of 2. That is, b must not have a long run
 * of unset bits after the most significant bit.
 *
 * Let n be the bit-size of b, i.e. the integer such that 2^n <= b < 2^{n+1}.
 * This function returns 1 if, when drawing a number between 0 and b,
 * the probability that this number is at least 2^n is not negligible.
 * This probability is (b - 2^n) / b and this function checks that this
 * number is above some threshold A. The threshold value is heuristic and
 * based on the needs of mpi_random_many().
 */
static int is_significantly_above_a_power_of_2( data_t *bytes )
{
    const uint8_t *p = bytes->x;
    size_t len = bytes->len;
    unsigned x;

    /* Skip leading null bytes */
    while( len > 0 && p[0] == 0 )
    {
        ++p;
        --len;
    }
    /* 0 is not significantly above a power of 2 */
    if( len == 0 )
        return( 0 );
    /* Extract the (up to) 2 most significant bytes */
    if( len == 1 )
        x = p[0];
    else
        x = ( p[0] << 8 ) | p[1];

    /* Shift the most significant bit of x to position 8 and mask it out */
    while( ( x & 0xfe00 ) != 0 )
        x >>= 1;
    x &= 0x00ff;

    /* At this point, x = floor((b - 2^n) / 2^(n-8)). b is significantly above
     * a power of 2 iff x is significantly above 0 compared to 2^8.
     * Testing x >= 2^4 amounts to picking A = 1/16 in the function
     * description above. */
    return( x >= 0x10 );
}

#line 131 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mpi_null(  )
{
    mbedtls_mpi X, Y, Z;

    mbedtls_mpi_init( &X );
    mbedtls_mpi_init( &Y );
    mbedtls_mpi_init( &Z );

    TEST_ASSERT( mbedtls_mpi_get_bit( &X, 42 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_lsb( &X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_bitlen( &X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_size( &X ) == 0 );

exit:
    mbedtls_mpi_free( &X );
}

void test_mpi_null_wrapper( void ** params )
{
    (void)params;

    test_mpi_null(  );
}
#line 150 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mpi_read_write_string( int radix_X, char * input_X, int radix_A,
                            char * input_A, int output_size, int result_read,
                            int result_write )
{
    mbedtls_mpi X;
    char str[1000];
    size_t len;

    mbedtls_mpi_init( &X );

    memset( str, '!', sizeof( str ) );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, radix_X, input_X ) == result_read );
    if( result_read == 0 )
    {
        TEST_ASSERT( sign_is_valid( &X ) );
        TEST_ASSERT( mbedtls_mpi_write_string( &X, radix_A, str, output_size, &len ) == result_write );
        if( result_write == 0 )
        {
            TEST_ASSERT( strcasecmp( str, input_A ) == 0 );
            TEST_ASSERT( str[len] == '!' );
        }
    }

exit:
    mbedtls_mpi_free( &X );
}

void test_mpi_read_write_string_wrapper( void ** params )
{

    test_mpi_read_write_string( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), (char *) params[3], *( (int *) params[4] ), *( (int *) params[5] ), *( (int *) params[6] ) );
}
#line 180 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_read_binary( data_t * buf, int radix_A, char * input_A )
{
    mbedtls_mpi X;
    char str[1000];
    size_t len;

    mbedtls_mpi_init( &X );


    TEST_ASSERT( mbedtls_mpi_read_binary( &X, buf->x, buf->len ) == 0 );
    TEST_ASSERT( sign_is_valid( &X ) );
    TEST_ASSERT( mbedtls_mpi_write_string( &X, radix_A, str, sizeof( str ), &len ) == 0 );
    TEST_ASSERT( strcmp( (char *) str, input_A ) == 0 );

exit:
    mbedtls_mpi_free( &X );
}

void test_mbedtls_mpi_read_binary_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};

    test_mbedtls_mpi_read_binary( &data0, *( (int *) params[2] ), (char *) params[3] );
}
#line 200 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_read_binary_le( data_t * buf, int radix_A, char * input_A )
{
    mbedtls_mpi X;
    char str[1000];
    size_t len;

    mbedtls_mpi_init( &X );


    TEST_ASSERT( mbedtls_mpi_read_binary_le( &X, buf->x, buf->len ) == 0 );
    TEST_ASSERT( sign_is_valid( &X ) );
    TEST_ASSERT( mbedtls_mpi_write_string( &X, radix_A, str, sizeof( str ), &len ) == 0 );
    TEST_ASSERT( strcmp( (char *) str, input_A ) == 0 );

exit:
    mbedtls_mpi_free( &X );
}

void test_mbedtls_mpi_read_binary_le_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};

    test_mbedtls_mpi_read_binary_le( &data0, *( (int *) params[2] ), (char *) params[3] );
}
#line 220 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_write_binary( int radix_X, char * input_X,
                               data_t * input_A, int output_size,
                               int result )
{
    mbedtls_mpi X;
    unsigned char buf[1000];
    size_t buflen;

    memset( buf, 0x00, 1000 );

    mbedtls_mpi_init( &X );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );

    buflen = mbedtls_mpi_size( &X );
    if( buflen > (size_t) output_size )
        buflen = (size_t) output_size;

    TEST_ASSERT( mbedtls_mpi_write_binary( &X, buf, buflen ) == result );
    if( result == 0)
    {

        TEST_ASSERT( mbedtls_test_hexcmp( buf, input_A->x,
                                          buflen, input_A->len ) == 0 );
    }

exit:
    mbedtls_mpi_free( &X );
}

void test_mbedtls_mpi_write_binary_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};

    test_mbedtls_mpi_write_binary( *( (int *) params[0] ), (char *) params[1], &data2, *( (int *) params[4] ), *( (int *) params[5] ) );
}
#line 252 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_write_binary_le( int radix_X, char * input_X,
                                  data_t * input_A, int output_size,
                                  int result )
{
    mbedtls_mpi X;
    unsigned char buf[1000];
    size_t buflen;

    memset( buf, 0x00, 1000 );

    mbedtls_mpi_init( &X );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );

    buflen = mbedtls_mpi_size( &X );
    if( buflen > (size_t) output_size )
        buflen = (size_t) output_size;

    TEST_ASSERT( mbedtls_mpi_write_binary_le( &X, buf, buflen ) == result );
    if( result == 0)
    {

        TEST_ASSERT( mbedtls_test_hexcmp( buf, input_A->x,
                                          buflen, input_A->len ) == 0 );
    }

exit:
    mbedtls_mpi_free( &X );
}

void test_mbedtls_mpi_write_binary_le_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};

    test_mbedtls_mpi_write_binary_le( *( (int *) params[0] ), (char *) params[1], &data2, *( (int *) params[4] ), *( (int *) params[5] ) );
}
#if defined(MBEDTLS_FS_IO)
#line 284 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_read_file( int radix_X, char * input_file,
                            data_t * input_A, int result )
{
    mbedtls_mpi X;
    unsigned char buf[1000];
    size_t buflen;
    FILE *file;
    int ret;

    memset( buf, 0x00, 1000 );

    mbedtls_mpi_init( &X );

    file = fopen( input_file, "r" );
    TEST_ASSERT( file != NULL );
    ret = mbedtls_mpi_read_file( &X, radix_X, file );
    fclose(file);
    TEST_ASSERT( ret == result );

    if( result == 0 )
    {
        TEST_ASSERT( sign_is_valid( &X ) );
        buflen = mbedtls_mpi_size( &X );
        TEST_ASSERT( mbedtls_mpi_write_binary( &X, buf, buflen ) == 0 );


        TEST_ASSERT( mbedtls_test_hexcmp( buf, input_A->x,
                                          buflen, input_A->len ) == 0 );
    }

exit:
    mbedtls_mpi_free( &X );
}

void test_mbedtls_mpi_read_file_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};

    test_mbedtls_mpi_read_file( *( (int *) params[0] ), (char *) params[1], &data2, *( (int *) params[4] ) );
}
#endif /* MBEDTLS_FS_IO */
#if defined(MBEDTLS_FS_IO)
#line 320 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_write_file( int radix_X, char * input_X, int output_radix,
                             char * output_file )
{
    mbedtls_mpi X, Y;
    FILE *file_out, *file_in;
    int ret;

    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );

    file_out = fopen( output_file, "w" );
    TEST_ASSERT( file_out != NULL );
    ret = mbedtls_mpi_write_file( NULL, &X, output_radix, file_out );
    fclose(file_out);
    TEST_ASSERT( ret == 0 );

    file_in = fopen( output_file, "r" );
    TEST_ASSERT( file_in != NULL );
    ret = mbedtls_mpi_read_file( &Y, output_radix, file_in );
    fclose(file_in);
    TEST_ASSERT( ret == 0 );

    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &Y ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y );
}

void test_mbedtls_mpi_write_file_wrapper( void ** params )
{

    test_mbedtls_mpi_write_file( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), (char *) params[3] );
}
#endif /* MBEDTLS_FS_IO */
#line 351 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_get_bit( int radix_X, char * input_X, int pos, int val )
{
    mbedtls_mpi X;
    mbedtls_mpi_init( &X );
    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_get_bit( &X, pos ) == val );

exit:
    mbedtls_mpi_free( &X );
}

void test_mbedtls_mpi_get_bit_wrapper( void ** params )
{

    test_mbedtls_mpi_get_bit( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), *( (int *) params[3] ) );
}
#line 364 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_set_bit( int radix_X, char * input_X, int pos, int val,
                          int radix_Y, char * output_Y, int result )
{
    mbedtls_mpi X, Y;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &Y, radix_Y, output_Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_set_bit( &X, pos, val ) == result );

    if( result == 0 )
    {
        TEST_ASSERT( sign_is_valid( &X ) );
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &Y ) == 0 );
    }

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y );
}

void test_mbedtls_mpi_set_bit_wrapper( void ** params )
{

    test_mbedtls_mpi_set_bit( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ), (char *) params[5], *( (int *) params[6] ) );
}
#line 386 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_lsb( int radix_X, char * input_X, int nr_bits )
{
    mbedtls_mpi X;
    mbedtls_mpi_init( &X );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_lsb( &X ) == (size_t) nr_bits );

exit:
    mbedtls_mpi_free( &X );
}

void test_mbedtls_mpi_lsb_wrapper( void ** params )
{

    test_mbedtls_mpi_lsb( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ) );
}
#line 400 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_bitlen( int radix_X, char * input_X, int nr_bits )
{
    mbedtls_mpi X;
    mbedtls_mpi_init( &X );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_bitlen( &X ) == (size_t) nr_bits );

exit:
    mbedtls_mpi_free( &X );
}

void test_mbedtls_mpi_bitlen_wrapper( void ** params )
{

    test_mbedtls_mpi_bitlen( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ) );
}
#line 414 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_gcd( int radix_X, char * input_X, int radix_Y,
                      char * input_Y, int radix_A, char * input_A )
{
    mbedtls_mpi A, X, Y, Z;
    mbedtls_mpi_init( &A ); mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &Z );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_gcd( &Z, &X, &Y ) == 0 );
    TEST_ASSERT( sign_is_valid( &Z ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &A ) == 0 );

exit:
    mbedtls_mpi_free( &A ); mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &Z );
}

void test_mbedtls_mpi_gcd_wrapper( void ** params )
{

    test_mbedtls_mpi_gcd( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), (char *) params[3], *( (int *) params[4] ), (char *) params[5] );
}
#line 433 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_cmp_int( int input_X, int input_A, int result_CMP )
{
    mbedtls_mpi X;
    mbedtls_mpi_init( &X  );

    TEST_ASSERT( mbedtls_mpi_lset( &X, input_X ) == 0);
    TEST_ASSERT( mbedtls_mpi_cmp_int( &X, input_A ) == result_CMP);

exit:
    mbedtls_mpi_free( &X );
}

void test_mbedtls_mpi_cmp_int_wrapper( void ** params )
{

    test_mbedtls_mpi_cmp_int( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ) );
}
#line 447 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_cmp_mpi( int radix_X, char * input_X, int radix_Y,
                          char * input_Y, int input_A )
{
    mbedtls_mpi X, Y;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &Y ) == input_A );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y );
}

void test_mbedtls_mpi_cmp_mpi_wrapper( void ** params )
{

    test_mbedtls_mpi_cmp_mpi( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), (char *) params[3], *( (int *) params[4] ) );
}
#line 463 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_lt_mpi_ct( int size_X, char * input_X,
                            int size_Y, char * input_Y,
                            int input_ret, int input_err )
{
    unsigned ret = -1;
    unsigned input_uret = input_ret;
    mbedtls_mpi X, Y;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, 16, input_X ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &Y, 16, input_Y ) == 0 );

    TEST_ASSERT( mbedtls_mpi_grow( &X, size_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_grow( &Y, size_Y ) == 0 );

    TEST_ASSERT( mbedtls_mpi_lt_mpi_ct( &X, &Y, &ret ) == input_err );
    if( input_err == 0 )
        TEST_ASSERT( ret == input_uret );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y );
}

void test_mbedtls_mpi_lt_mpi_ct_wrapper( void ** params )
{

    test_mbedtls_mpi_lt_mpi_ct( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), (char *) params[3], *( (int *) params[4] ), *( (int *) params[5] ) );
}
#line 488 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_cmp_abs( int radix_X, char * input_X, int radix_Y,
                          char * input_Y, int input_A )
{
    mbedtls_mpi X, Y;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_abs( &X, &Y ) == input_A );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y );
}

void test_mbedtls_mpi_cmp_abs_wrapper( void ** params )
{

    test_mbedtls_mpi_cmp_abs( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), (char *) params[3], *( (int *) params[4] ) );
}
#line 504 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_copy( char *src_hex, char *dst_hex )
{
    mbedtls_mpi src, dst, ref;
    mbedtls_mpi_init( &src );
    mbedtls_mpi_init( &dst );
    mbedtls_mpi_init( &ref );

    TEST_ASSERT( mbedtls_test_read_mpi( &src, 16, src_hex ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &ref, 16, dst_hex ) == 0 );

    /* mbedtls_mpi_copy() */
    TEST_ASSERT( mbedtls_test_read_mpi( &dst, 16, dst_hex ) == 0 );
    TEST_ASSERT( mbedtls_mpi_copy( &dst, &src ) == 0 );
    TEST_ASSERT( sign_is_valid( &dst ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &dst, &src ) == 0 );

    /* mbedtls_mpi_safe_cond_assign(), assignment done */
    mbedtls_mpi_free( &dst );
    TEST_ASSERT( mbedtls_test_read_mpi( &dst, 16, dst_hex ) == 0 );
    TEST_ASSERT( mbedtls_mpi_safe_cond_assign( &dst, &src, 1 ) == 0 );
    TEST_ASSERT( sign_is_valid( &dst ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &dst, &src ) == 0 );

    /* mbedtls_mpi_safe_cond_assign(), assignment not done */
    mbedtls_mpi_free( &dst );
    TEST_ASSERT( mbedtls_test_read_mpi( &dst, 16, dst_hex ) == 0 );
    TEST_ASSERT( mbedtls_mpi_safe_cond_assign( &dst, &src, 0 ) == 0 );
    TEST_ASSERT( sign_is_valid( &dst ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &dst, &ref ) == 0 );

exit:
    mbedtls_mpi_free( &src );
    mbedtls_mpi_free( &dst );
    mbedtls_mpi_free( &ref );
}

void test_mbedtls_mpi_copy_wrapper( void ** params )
{

    test_mbedtls_mpi_copy( (char *) params[0], (char *) params[1] );
}
#line 542 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mpi_copy_self( char *input_X )
{
    mbedtls_mpi X, A;
    mbedtls_mpi_init( &A );
    mbedtls_mpi_init( &X );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, 16, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_copy( &X, &X ) == 0 );

    TEST_ASSERT( mbedtls_test_read_mpi( &A, 16, input_X ) == 0 );
    TEST_ASSERT( sign_is_valid( &X ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &A ) == 0 );

exit:
    mbedtls_mpi_free( &A );
    mbedtls_mpi_free( &X );
}

void test_mpi_copy_self_wrapper( void ** params )
{

    test_mpi_copy_self( (char *) params[0] );
}
#line 562 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_swap( char *X_hex, char *Y_hex )
{
    mbedtls_mpi X, Y, X0, Y0;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y );
    mbedtls_mpi_init( &X0 ); mbedtls_mpi_init( &Y0 );

    TEST_ASSERT( mbedtls_test_read_mpi( &X0, 16, X_hex ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &Y0, 16, Y_hex ) == 0 );

    /* mbedtls_mpi_swap() */
    TEST_ASSERT( mbedtls_test_read_mpi( &X,  16, X_hex ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &Y,  16, Y_hex ) == 0 );
    mbedtls_mpi_swap( &X, &Y );
    TEST_ASSERT( sign_is_valid( &X ) );
    TEST_ASSERT( sign_is_valid( &Y ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &Y0 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Y, &X0 ) == 0 );

    /* mbedtls_mpi_safe_cond_swap(), swap done */
    mbedtls_mpi_free( &X );
    mbedtls_mpi_free( &Y );
    TEST_ASSERT( mbedtls_test_read_mpi( &X,  16, X_hex ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &Y,  16, Y_hex ) == 0 );
    TEST_ASSERT( mbedtls_mpi_safe_cond_swap( &X, &Y, 1 ) == 0 );
    TEST_ASSERT( sign_is_valid( &X ) );
    TEST_ASSERT( sign_is_valid( &Y ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &Y0 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Y, &X0 ) == 0 );

    /* mbedtls_mpi_safe_cond_swap(), swap not done */
    mbedtls_mpi_free( &X );
    mbedtls_mpi_free( &Y );
    TEST_ASSERT( mbedtls_test_read_mpi( &X,  16, X_hex ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &Y,  16, Y_hex ) == 0 );
    TEST_ASSERT( mbedtls_mpi_safe_cond_swap( &X, &Y, 0 ) == 0 );
    TEST_ASSERT( sign_is_valid( &X ) );
    TEST_ASSERT( sign_is_valid( &Y ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &X0 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Y, &Y0 ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y );
    mbedtls_mpi_free( &X0 ); mbedtls_mpi_free( &Y0 );
}

void test_mbedtls_mpi_swap_wrapper( void ** params )
{

    test_mbedtls_mpi_swap( (char *) params[0], (char *) params[1] );
}
#line 609 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mpi_swap_self( char *X_hex )
{
    mbedtls_mpi X, X0;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &X0 );

    TEST_ASSERT( mbedtls_test_read_mpi( &X,  16, X_hex ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &X0, 16, X_hex ) == 0 );

    mbedtls_mpi_swap( &X, &X );
    TEST_ASSERT( sign_is_valid( &X ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &X0 ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &X0 );
}

void test_mpi_swap_self_wrapper( void ** params )
{

    test_mpi_swap_self( (char *) params[0] );
}
#line 627 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_shrink( int before, int used, int min, int after )
{
    mbedtls_mpi X;
    mbedtls_mpi_init( &X );

    TEST_ASSERT( mbedtls_mpi_grow( &X, before ) == 0 );
    if( used > 0 )
    {
        size_t used_bit_count = used * 8 * sizeof( mbedtls_mpi_uint );
        TEST_ASSERT( mbedtls_mpi_set_bit( &X, used_bit_count - 1, 1 ) == 0 );
    }
    TEST_EQUAL( X.n, (size_t) before );
    TEST_ASSERT( mbedtls_mpi_shrink( &X, min ) == 0 );
    TEST_EQUAL( X.n, (size_t) after );

exit:
    mbedtls_mpi_free( &X );
}

void test_mbedtls_mpi_shrink_wrapper( void ** params )
{

    test_mbedtls_mpi_shrink( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ) );
}
#line 648 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_add_mpi( int radix_X, char * input_X, int radix_Y,
                          char * input_Y, int radix_A, char * input_A )
{
    mbedtls_mpi X, Y, Z, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &Z ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_add_mpi( &Z, &X, &Y ) == 0 );
    TEST_ASSERT( sign_is_valid( &Z ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &A ) == 0 );

    /* result == first operand */
    TEST_ASSERT( mbedtls_mpi_add_mpi( &X, &X, &Y ) == 0 );
    TEST_ASSERT( sign_is_valid( &X ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &A ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );

    /* result == second operand */
    TEST_ASSERT( mbedtls_mpi_add_mpi( &Y, &X, &Y ) == 0 );
    TEST_ASSERT( sign_is_valid( &Y ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Y, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &Z ); mbedtls_mpi_free( &A );
}

void test_mbedtls_mpi_add_mpi_wrapper( void ** params )
{

    test_mbedtls_mpi_add_mpi( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), (char *) params[3], *( (int *) params[4] ), (char *) params[5] );
}
#line 678 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_add_mpi_inplace( int radix_X, char * input_X, int radix_A,
                                  char * input_A )
{
    mbedtls_mpi X, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_test_read_mpi( &A, radix_A, input_A ) == 0 );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_sub_abs( &X, &X, &X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_int( &X, 0 ) == 0 );
    TEST_ASSERT( sign_is_valid( &X ) );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_add_abs( &X, &X, &X ) == 0 );
    TEST_ASSERT( sign_is_valid( &X ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &A ) == 0 );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_add_mpi( &X, &X, &X ) == 0 );
    TEST_ASSERT( sign_is_valid( &X ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &A );
}

void test_mbedtls_mpi_add_mpi_inplace_wrapper( void ** params )
{

    test_mbedtls_mpi_add_mpi_inplace( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), (char *) params[3] );
}
#line 708 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_add_abs( int radix_X, char * input_X, int radix_Y,
                          char * input_Y, int radix_A, char * input_A )
{
    mbedtls_mpi X, Y, Z, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &Z ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_add_abs( &Z, &X, &Y ) == 0 );
    TEST_ASSERT( sign_is_valid( &Z ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &A ) == 0 );

    /* result == first operand */
    TEST_ASSERT( mbedtls_mpi_add_abs( &X, &X, &Y ) == 0 );
    TEST_ASSERT( sign_is_valid( &X ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &A ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );

    /* result == second operand */
    TEST_ASSERT( mbedtls_mpi_add_abs( &Y, &X, &Y ) == 0 );
    TEST_ASSERT( sign_is_valid( &Y ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Y, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &Z ); mbedtls_mpi_free( &A );
}

void test_mbedtls_mpi_add_abs_wrapper( void ** params )
{

    test_mbedtls_mpi_add_abs( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), (char *) params[3], *( (int *) params[4] ), (char *) params[5] );
}
#line 738 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_add_int( int radix_X, char * input_X, int input_Y,
                          int radix_A, char * input_A )
{
    mbedtls_mpi X, Z, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Z ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_add_int( &Z, &X, input_Y ) == 0 );
    TEST_ASSERT( sign_is_valid( &Z ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Z ); mbedtls_mpi_free( &A );
}

void test_mbedtls_mpi_add_int_wrapper( void ** params )
{

    test_mbedtls_mpi_add_int( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), *( (int *) params[3] ), (char *) params[4] );
}
#line 756 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_sub_mpi( int radix_X, char * input_X, int radix_Y,
                          char * input_Y, int radix_A, char * input_A )
{
    mbedtls_mpi X, Y, Z, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &Z ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_sub_mpi( &Z, &X, &Y ) == 0 );
    TEST_ASSERT( sign_is_valid( &Z ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &A ) == 0 );

    /* result == first operand */
    TEST_ASSERT( mbedtls_mpi_sub_mpi( &X, &X, &Y ) == 0 );
    TEST_ASSERT( sign_is_valid( &X ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &A ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );

    /* result == second operand */
    TEST_ASSERT( mbedtls_mpi_sub_mpi( &Y, &X, &Y ) == 0 );
    TEST_ASSERT( sign_is_valid( &Y ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Y, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &Z ); mbedtls_mpi_free( &A );
}

void test_mbedtls_mpi_sub_mpi_wrapper( void ** params )
{

    test_mbedtls_mpi_sub_mpi( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), (char *) params[3], *( (int *) params[4] ), (char *) params[5] );
}
#line 786 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_sub_abs( int radix_X, char * input_X, int radix_Y,
                          char * input_Y, int radix_A, char * input_A,
                          int sub_result )
{
    mbedtls_mpi X, Y, Z, A;
    int res;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &Z ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &A, radix_A, input_A ) == 0 );

    res = mbedtls_mpi_sub_abs( &Z, &X, &Y );
    TEST_ASSERT( res == sub_result );
    TEST_ASSERT( sign_is_valid( &Z ) );
    if( res == 0 )
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &A ) == 0 );

    /* result == first operand */
    TEST_ASSERT( mbedtls_mpi_sub_abs( &X, &X, &Y ) == sub_result );
    TEST_ASSERT( sign_is_valid( &X ) );
    if( sub_result == 0 )
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &A ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );

    /* result == second operand */
    TEST_ASSERT( mbedtls_mpi_sub_abs( &Y, &X, &Y ) == sub_result );
    TEST_ASSERT( sign_is_valid( &Y ) );
    if( sub_result == 0 )
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Y, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &Z ); mbedtls_mpi_free( &A );
}

void test_mbedtls_mpi_sub_abs_wrapper( void ** params )
{

    test_mbedtls_mpi_sub_abs( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), (char *) params[3], *( (int *) params[4] ), (char *) params[5], *( (int *) params[6] ) );
}
#line 823 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_sub_int( int radix_X, char * input_X, int input_Y,
                          int radix_A, char * input_A )
{
    mbedtls_mpi X, Z, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Z ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_sub_int( &Z, &X, input_Y ) == 0 );
    TEST_ASSERT( sign_is_valid( &Z ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Z ); mbedtls_mpi_free( &A );
}

void test_mbedtls_mpi_sub_int_wrapper( void ** params )
{

    test_mbedtls_mpi_sub_int( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), *( (int *) params[3] ), (char *) params[4] );
}
#line 841 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_mul_mpi( int radix_X, char * input_X, int radix_Y,
                          char * input_Y, int radix_A, char * input_A )
{
    mbedtls_mpi X, Y, Z, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &Z ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_mul_mpi( &Z, &X, &Y ) == 0 );
    TEST_ASSERT( sign_is_valid( &Z ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &Z ); mbedtls_mpi_free( &A );
}

void test_mbedtls_mpi_mul_mpi_wrapper( void ** params )
{

    test_mbedtls_mpi_mul_mpi( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), (char *) params[3], *( (int *) params[4] ), (char *) params[5] );
}
#line 860 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_mul_int( int radix_X, char * input_X, int input_Y,
                          int radix_A, char * input_A,
                          char * result_comparison )
{
    mbedtls_mpi X, Z, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Z ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_mul_int( &Z, &X, input_Y ) == 0 );
    TEST_ASSERT( sign_is_valid( &Z ) );
    if( strcmp( result_comparison, "==" ) == 0 )
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &A ) == 0 );
    else if( strcmp( result_comparison, "!=" ) == 0 )
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &A ) != 0 );
    else
        TEST_ASSERT( "unknown operator" == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Z ); mbedtls_mpi_free( &A );
}

void test_mbedtls_mpi_mul_int_wrapper( void ** params )
{

    test_mbedtls_mpi_mul_int( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), *( (int *) params[3] ), (char *) params[4], (char *) params[5] );
}
#line 884 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_div_mpi( int radix_X, char * input_X, int radix_Y,
                          char * input_Y, int radix_A, char * input_A,
                          int radix_B, char * input_B, int div_result )
{
    mbedtls_mpi X, Y, Q, R, A, B;
    int res;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &Q ); mbedtls_mpi_init( &R );
    mbedtls_mpi_init( &A ); mbedtls_mpi_init( &B );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &B, radix_B, input_B ) == 0 );
    res = mbedtls_mpi_div_mpi( &Q, &R, &X, &Y );
    TEST_ASSERT( res == div_result );
    if( res == 0 )
    {
        TEST_ASSERT( sign_is_valid( &Q ) );
        TEST_ASSERT( sign_is_valid( &R ) );
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Q, &A ) == 0 );
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R, &B ) == 0 );
    }

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &Q ); mbedtls_mpi_free( &R );
    mbedtls_mpi_free( &A ); mbedtls_mpi_free( &B );
}

void test_mbedtls_mpi_div_mpi_wrapper( void ** params )
{

    test_mbedtls_mpi_div_mpi( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), (char *) params[3], *( (int *) params[4] ), (char *) params[5], *( (int *) params[6] ), (char *) params[7], *( (int *) params[8] ) );
}
#line 914 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_div_int( int radix_X, char * input_X, int input_Y,
                          int radix_A, char * input_A, int radix_B,
                          char * input_B, int div_result )
{
    mbedtls_mpi X, Q, R, A, B;
    int res;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Q ); mbedtls_mpi_init( &R ); mbedtls_mpi_init( &A );
    mbedtls_mpi_init( &B );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &B, radix_B, input_B ) == 0 );
    res = mbedtls_mpi_div_int( &Q, &R, &X, input_Y );
    TEST_ASSERT( res == div_result );
    if( res == 0 )
    {
        TEST_ASSERT( sign_is_valid( &Q ) );
        TEST_ASSERT( sign_is_valid( &R ) );
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Q, &A ) == 0 );
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R, &B ) == 0 );
    }

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Q ); mbedtls_mpi_free( &R ); mbedtls_mpi_free( &A );
    mbedtls_mpi_free( &B );
}

void test_mbedtls_mpi_div_int_wrapper( void ** params )
{

    test_mbedtls_mpi_div_int( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), *( (int *) params[3] ), (char *) params[4], *( (int *) params[5] ), (char *) params[6], *( (int *) params[7] ) );
}
#line 943 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_mod_mpi( int radix_X, char * input_X, int radix_Y,
                          char * input_Y, int radix_A, char * input_A,
                          int div_result )
{
    mbedtls_mpi X, Y, A;
    int res;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &A, radix_A, input_A ) == 0 );
    res = mbedtls_mpi_mod_mpi( &X, &X, &Y );
    TEST_ASSERT( res == div_result );
    if( res == 0 )
    {
        TEST_ASSERT( sign_is_valid( &X ) );
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &A ) == 0 );
    }

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &A );
}

void test_mbedtls_mpi_mod_mpi_wrapper( void ** params )
{

    test_mbedtls_mpi_mod_mpi( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), (char *) params[3], *( (int *) params[4] ), (char *) params[5], *( (int *) params[6] ) );
}
#line 968 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_mod_int( int radix_X, char * input_X, int input_Y,
                          int input_A, int div_result )
{
    mbedtls_mpi X;
    int res;
    mbedtls_mpi_uint r;
    mbedtls_mpi_init( &X );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    res = mbedtls_mpi_mod_int( &r, &X, input_Y );
    TEST_ASSERT( res == div_result );
    if( res == 0 )
    {
        TEST_ASSERT( r == (mbedtls_mpi_uint) input_A );
    }

exit:
    mbedtls_mpi_free( &X );
}

void test_mbedtls_mpi_mod_int_wrapper( void ** params )
{

    test_mbedtls_mpi_mod_int( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ) );
}
#line 990 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_exp_mod( int radix_A, char * input_A, int radix_E,
                          char * input_E, int radix_N, char * input_N,
                          int radix_X, char * input_X, int exp_result )
{
    mbedtls_mpi A, E, N, RR, Z, X;
    int res;
    mbedtls_mpi_init( &A  ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &N );
    mbedtls_mpi_init( &RR ); mbedtls_mpi_init( &Z ); mbedtls_mpi_init( &X );

    TEST_ASSERT( mbedtls_test_read_mpi( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &E, radix_E, input_E ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );

    res = mbedtls_mpi_exp_mod( &Z, &A, &E, &N, NULL );
    TEST_ASSERT( res == exp_result );
    if( res == 0 )
    {
        TEST_ASSERT( sign_is_valid( &Z ) );
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &X ) == 0 );
    }

    /* Now test again with the speed-up parameter supplied as an output. */
    res = mbedtls_mpi_exp_mod( &Z, &A, &E, &N, &RR );
    TEST_ASSERT( res == exp_result );
    if( res == 0 )
    {
        TEST_ASSERT( sign_is_valid( &Z ) );
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &X ) == 0 );
    }

    /* Now test again with the speed-up parameter supplied in calculated form. */
    res = mbedtls_mpi_exp_mod( &Z, &A, &E, &N, &RR );
    TEST_ASSERT( res == exp_result );
    if( res == 0 )
    {
        TEST_ASSERT( sign_is_valid( &Z ) );
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &X ) == 0 );
    }

exit:
    mbedtls_mpi_free( &A  ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &N );
    mbedtls_mpi_free( &RR ); mbedtls_mpi_free( &Z ); mbedtls_mpi_free( &X );
}

void test_mbedtls_mpi_exp_mod_wrapper( void ** params )
{

    test_mbedtls_mpi_exp_mod( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), (char *) params[3], *( (int *) params[4] ), (char *) params[5], *( (int *) params[6] ), (char *) params[7], *( (int *) params[8] ) );
}
#line 1037 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_exp_mod_size( int A_bytes, int E_bytes, int N_bytes,
                               int radix_RR, char * input_RR, int exp_result )
{
    mbedtls_mpi A, E, N, RR, Z;
    mbedtls_mpi_init( &A  ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &N );
    mbedtls_mpi_init( &RR ); mbedtls_mpi_init( &Z );

    /* Set A to 2^(A_bytes - 1) + 1 */
    TEST_ASSERT( mbedtls_mpi_lset( &A, 1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_shift_l( &A, ( A_bytes * 8 ) - 1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_set_bit( &A, 0, 1 ) == 0 );

    /* Set E to 2^(E_bytes - 1) + 1 */
    TEST_ASSERT( mbedtls_mpi_lset( &E, 1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_shift_l( &E, ( E_bytes * 8 ) - 1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_set_bit( &E, 0, 1 ) == 0 );

    /* Set N to 2^(N_bytes - 1) + 1 */
    TEST_ASSERT( mbedtls_mpi_lset( &N, 1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_shift_l( &N, ( N_bytes * 8 ) - 1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_set_bit( &N, 0, 1 ) == 0 );

    if( strlen( input_RR ) )
        TEST_ASSERT( mbedtls_test_read_mpi( &RR, radix_RR, input_RR ) == 0 );

    TEST_ASSERT( mbedtls_mpi_exp_mod( &Z, &A, &E, &N, &RR ) == exp_result );

exit:
    mbedtls_mpi_free( &A  ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &N );
    mbedtls_mpi_free( &RR ); mbedtls_mpi_free( &Z );
}

void test_mbedtls_mpi_exp_mod_size_wrapper( void ** params )
{

    test_mbedtls_mpi_exp_mod_size( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ), (char *) params[4], *( (int *) params[5] ) );
}
#line 1071 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_inv_mod( int radix_X, char * input_X, int radix_Y,
                          char * input_Y, int radix_A, char * input_A,
                          int div_result )
{
    mbedtls_mpi X, Y, Z, A;
    int res;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &Z ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &A, radix_A, input_A ) == 0 );
    res = mbedtls_mpi_inv_mod( &Z, &X, &Y );
    TEST_ASSERT( res == div_result );
    if( res == 0 )
    {
        TEST_ASSERT( sign_is_valid( &Z ) );
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Z, &A ) == 0 );
    }

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &Z ); mbedtls_mpi_free( &A );
}

void test_mbedtls_mpi_inv_mod_wrapper( void ** params )
{

    test_mbedtls_mpi_inv_mod( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), (char *) params[3], *( (int *) params[4] ), (char *) params[5], *( (int *) params[6] ) );
}
#if defined(MBEDTLS_GENPRIME)
#line 1096 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_is_prime( int radix_X, char * input_X, int div_result )
{
    mbedtls_mpi X;
    int res;
    mbedtls_mpi_init( &X );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    res = mbedtls_mpi_is_prime_ext( &X, 40, mbedtls_test_rnd_std_rand, NULL );
    TEST_ASSERT( res == div_result );

exit:
    mbedtls_mpi_free( &X );
}

void test_mbedtls_mpi_is_prime_wrapper( void ** params )
{

    test_mbedtls_mpi_is_prime( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ) );
}
#endif /* MBEDTLS_GENPRIME */
#if defined(MBEDTLS_GENPRIME)
#line 1112 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_is_prime_det( data_t * input_X, data_t * witnesses,
                               int chunk_len, int rounds )
{
    mbedtls_mpi X;
    int res;
    mbedtls_test_mpi_random rand;

    mbedtls_mpi_init( &X );
    rand.data = witnesses;
    rand.pos = 0;
    rand.chunk_len = chunk_len;

    TEST_ASSERT( mbedtls_mpi_read_binary( &X, input_X->x, input_X->len ) == 0 );
    res = mbedtls_mpi_is_prime_ext( &X, rounds - 1,
                                    mbedtls_test_mpi_miller_rabin_determinizer,
                                    &rand );
    TEST_ASSERT( res == 0 );

    rand.data = witnesses;
    rand.pos = 0;
    rand.chunk_len = chunk_len;

    res = mbedtls_mpi_is_prime_ext( &X, rounds,
                                    mbedtls_test_mpi_miller_rabin_determinizer,
                                    &rand );
    TEST_ASSERT( res == MBEDTLS_ERR_MPI_NOT_ACCEPTABLE );

exit:
    mbedtls_mpi_free( &X );
}

void test_mbedtls_mpi_is_prime_det_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};

    test_mbedtls_mpi_is_prime_det( &data0, &data2, *( (int *) params[4] ), *( (int *) params[5] ) );
}
#endif /* MBEDTLS_GENPRIME */
#if defined(MBEDTLS_GENPRIME)
#line 1145 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_gen_prime( int bits, int flags, int ref_ret )
{
    mbedtls_mpi X;
    int my_ret;

    mbedtls_mpi_init( &X );

    my_ret = mbedtls_mpi_gen_prime( &X, bits, flags,
                                    mbedtls_test_rnd_std_rand, NULL );
    TEST_ASSERT( my_ret == ref_ret );

    if( ref_ret == 0 )
    {
        size_t actual_bits = mbedtls_mpi_bitlen( &X );

        TEST_ASSERT( actual_bits >= (size_t) bits );
        TEST_ASSERT( actual_bits <= (size_t) bits + 1 );
        TEST_ASSERT( sign_is_valid( &X ) );

        TEST_ASSERT( mbedtls_mpi_is_prime_ext( &X, 40,
                                               mbedtls_test_rnd_std_rand,
                                               NULL ) == 0 );
        if( flags & MBEDTLS_MPI_GEN_PRIME_FLAG_DH )
        {
            /* X = ( X - 1 ) / 2 */
            TEST_ASSERT( mbedtls_mpi_shift_r( &X, 1 ) == 0 );
            TEST_ASSERT( mbedtls_mpi_is_prime_ext( &X, 40,
                                                   mbedtls_test_rnd_std_rand,
                                                   NULL ) == 0 );
        }
    }

exit:
    mbedtls_mpi_free( &X );
}

void test_mbedtls_mpi_gen_prime_wrapper( void ** params )
{

    test_mbedtls_mpi_gen_prime( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ) );
}
#endif /* MBEDTLS_GENPRIME */
#line 1183 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_shift_l( int radix_X, char * input_X, int shift_X,
                          int radix_A, char * input_A )
{
    mbedtls_mpi X, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_shift_l( &X, shift_X ) == 0 );
    TEST_ASSERT( sign_is_valid( &X ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &A );
}

void test_mbedtls_mpi_shift_l_wrapper( void ** params )
{

    test_mbedtls_mpi_shift_l( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), *( (int *) params[3] ), (char *) params[4] );
}
#line 1201 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mbedtls_mpi_shift_r( int radix_X, char * input_X, int shift_X,
                          int radix_A, char * input_A )
{
    mbedtls_mpi X, A;
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &A );

    TEST_ASSERT( mbedtls_test_read_mpi( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mbedtls_test_read_mpi( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mbedtls_mpi_shift_r( &X, shift_X ) == 0 );
    TEST_ASSERT( sign_is_valid( &X ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &X, &A ) == 0 );

exit:
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &A );
}

void test_mbedtls_mpi_shift_r_wrapper( void ** params )
{

    test_mbedtls_mpi_shift_r( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), *( (int *) params[3] ), (char *) params[4] );
}
#line 1219 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mpi_fill_random( int wanted_bytes, int rng_bytes,
                      int before, int expected_ret )
{
    mbedtls_mpi X;
    int ret;
    size_t bytes_left = rng_bytes;
    mbedtls_mpi_init( &X );

    if( before != 0 )
    {
        /* Set X to sign(before) * 2^(|before|-1) */
        TEST_ASSERT( mbedtls_mpi_lset( &X, before > 0 ? 1 : -1 ) == 0 );
        if( before < 0 )
            before = - before;
        TEST_ASSERT( mbedtls_mpi_shift_l( &X, before - 1 ) == 0 );
    }

    ret = mbedtls_mpi_fill_random( &X, wanted_bytes,
                                   f_rng_bytes_left, &bytes_left );
    TEST_ASSERT( ret == expected_ret );

    if( expected_ret == 0 )
    {
        /* mbedtls_mpi_fill_random is documented to use bytes from the RNG
         * as a big-endian representation of the number. We know when
         * our RNG function returns null bytes, so we know how many
         * leading zero bytes the number has. */
        size_t leading_zeros = 0;
        if( wanted_bytes > 0 && rng_bytes % 256 == 0 )
            leading_zeros = 1;
        TEST_ASSERT( mbedtls_mpi_size( &X ) + leading_zeros ==
                     (size_t) wanted_bytes );
        TEST_ASSERT( (int) bytes_left == rng_bytes - wanted_bytes );
        TEST_ASSERT( sign_is_valid( &X ) );
    }

exit:
    mbedtls_mpi_free( &X );
}

void test_mpi_fill_random_wrapper( void ** params )
{

    test_mpi_fill_random( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ) );
}
#line 1261 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mpi_random_many( int min, data_t *bound_bytes, int iterations )
{
    /* Generate numbers in the range 1..bound-1. Do it iterations times.
     * This function assumes that the value of bound is at least 2 and
     * that iterations is large enough that a one-in-2^iterations chance
     * effectively never occurs.
     */

    mbedtls_mpi upper_bound;
    size_t n_bits;
    mbedtls_mpi result;
    size_t b;
    /* If upper_bound is small, stats[b] is the number of times the value b
     * has been generated. Otherwise stats[b] is the number of times a
     * value with bit b set has been generated. */
    size_t *stats = NULL;
    size_t stats_len;
    int full_stats;
    size_t i;

    mbedtls_mpi_init( &upper_bound );
    mbedtls_mpi_init( &result );

    TEST_EQUAL( 0, mbedtls_mpi_read_binary( &upper_bound,
                                            bound_bytes->x, bound_bytes->len ) );
    n_bits = mbedtls_mpi_bitlen( &upper_bound );
    /* Consider a bound "small" if it's less than 2^5. This value is chosen
     * to be small enough that the probability of missing one value is
     * negligible given the number of iterations. It must be less than
     * 256 because some of the code below assumes that "small" values
     * fit in a byte. */
    if( n_bits <= 5 )
    {
        full_stats = 1;
        stats_len = bound_bytes->x[bound_bytes->len - 1];
    }
    else
    {
        full_stats = 0;
        stats_len = n_bits;
    }
    ASSERT_ALLOC( stats, stats_len );

    for( i = 0; i < (size_t) iterations; i++ )
    {
        mbedtls_test_set_step( i );
        TEST_EQUAL( 0, mbedtls_mpi_random( &result, min, &upper_bound,
                                           mbedtls_test_rnd_std_rand, NULL ) );

        TEST_ASSERT( sign_is_valid( &result ) );
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &result, &upper_bound ) < 0 );
        TEST_ASSERT( mbedtls_mpi_cmp_int( &result, min ) >= 0 );
        if( full_stats )
        {
            uint8_t value;
            TEST_EQUAL( 0, mbedtls_mpi_write_binary( &result, &value, 1 ) );
            TEST_ASSERT( value < stats_len );
            ++stats[value];
        }
        else
        {
            for( b = 0; b < n_bits; b++ )
                stats[b] += mbedtls_mpi_get_bit( &result, b );
        }
    }

    if( full_stats )
    {
        for( b = min; b < stats_len; b++ )
        {
            mbedtls_test_set_step( 1000000 + b );
            /* Assert that each value has been reached at least once.
             * This is almost guaranteed if the iteration count is large
             * enough. This is a very crude way of checking the distribution.
             */
            TEST_ASSERT( stats[b] > 0 );
        }
    }
    else
    {
        int statistically_safe_all_the_way =
            is_significantly_above_a_power_of_2( bound_bytes );
        for( b = 0; b < n_bits; b++ )
        {
            mbedtls_test_set_step( 1000000 + b );
            /* Assert that each bit has been set in at least one result and
             * clear in at least one result. Provided that iterations is not
             * too small, it would be extremely unlikely for this not to be
             * the case if the results are uniformly distributed.
             *
             * As an exception, the top bit may legitimately never be set
             * if bound is a power of 2 or only slightly above.
             */
            if( statistically_safe_all_the_way || b != n_bits - 1 )
            {
                TEST_ASSERT( stats[b] > 0 );
            }
            TEST_ASSERT( stats[b] < (size_t) iterations );
        }
    }

exit:
    mbedtls_mpi_free( &upper_bound );
    mbedtls_mpi_free( &result );
    mbedtls_free( stats );
}

void test_mpi_random_many_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};

    test_mpi_random_many( *( (int *) params[0] ), &data1, *( (int *) params[3] ) );
}
#line 1370 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mpi_random_sizes( int min, data_t *bound_bytes, int nlimbs, int before )
{
    mbedtls_mpi upper_bound;
    mbedtls_mpi result;

    mbedtls_mpi_init( &upper_bound );
    mbedtls_mpi_init( &result );

    if( before != 0 )
    {
        /* Set result to sign(before) * 2^(|before|-1) */
        TEST_ASSERT( mbedtls_mpi_lset( &result, before > 0 ? 1 : -1 ) == 0 );
        if( before < 0 )
            before = - before;
        TEST_ASSERT( mbedtls_mpi_shift_l( &result, before - 1 ) == 0 );
    }

    TEST_EQUAL( 0, mbedtls_mpi_grow( &result, nlimbs ) );
    TEST_EQUAL( 0, mbedtls_mpi_read_binary( &upper_bound,
                                            bound_bytes->x, bound_bytes->len ) );
    TEST_EQUAL( 0, mbedtls_mpi_random( &result, min, &upper_bound,
                                       mbedtls_test_rnd_std_rand, NULL ) );
    TEST_ASSERT( sign_is_valid( &result ) );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &result, &upper_bound ) < 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_int( &result, min ) >= 0 );

exit:
    mbedtls_mpi_free( &upper_bound );
    mbedtls_mpi_free( &result );
}

void test_mpi_random_sizes_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};

    test_mpi_random_sizes( *( (int *) params[0] ), &data1, *( (int *) params[3] ), *( (int *) params[4] ) );
}
#line 1403 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mpi_random_fail( int min, data_t *bound_bytes, int expected_ret )
{
    mbedtls_mpi upper_bound;
    mbedtls_mpi result;
    int actual_ret;

    mbedtls_mpi_init( &upper_bound );
    mbedtls_mpi_init( &result );

    TEST_EQUAL( 0, mbedtls_mpi_read_binary( &upper_bound,
                                            bound_bytes->x, bound_bytes->len ) );
    actual_ret = mbedtls_mpi_random( &result, min, &upper_bound,
                                     mbedtls_test_rnd_std_rand, NULL );
    TEST_EQUAL( expected_ret, actual_ret );

exit:
    mbedtls_mpi_free( &upper_bound );
    mbedtls_mpi_free( &result );
}

void test_mpi_random_fail_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};

    test_mpi_random_fail( *( (int *) params[0] ), &data1, *( (int *) params[3] ) );
}
#if defined(MBEDTLS_SELF_TEST)
#line 1425 "/home/kali/Desktop/dpki-protocol/MBED-TLS/MBED-TLS/mbedtls/tests/suites/test_suite_mpi.function"
void test_mpi_selftest(  )
{
    TEST_ASSERT( mbedtls_mpi_self_test( 1 ) == 0 );
exit:
    ;
}

void test_mpi_selftest_wrapper( void ** params )
{
    (void)params;

    test_mpi_selftest(  );
}
#endif /* MBEDTLS_SELF_TEST */
#endif /* MBEDTLS_BIGNUM_C */


#line 54 "suites/main_test.function"


/*----------------------------------------------------------------------------*/
/* Test dispatch code */


/**
 * \brief       Evaluates an expression/macro into its literal integer value.
 *              For optimizing space for embedded targets each expression/macro
 *              is identified by a unique identifier instead of string literals.
 *              Identifiers and evaluation code is generated by script:
 *              generate_test_code.py
 *
 * \param exp_id    Expression identifier.
 * \param out_value Pointer to int to hold the integer.
 *
 * \return       0 if exp_id is found. 1 otherwise.
 */
int get_expression( int32_t exp_id, int32_t * out_value )
{
    int ret = KEY_VALUE_MAPPING_FOUND;

    (void) exp_id;
    (void) out_value;

    switch( exp_id )
    {

#if defined(MBEDTLS_BIGNUM_C)

        case 0:
            {
                *out_value = MBEDTLS_ERR_MPI_INVALID_CHARACTER;
            }
            break;
        case 1:
            {
                *out_value = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
            }
            break;
        case 2:
            {
                *out_value = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
            }
            break;
        case 3:
            {
                *out_value = MBEDTLS_ERR_MPI_FILE_IO_ERROR;
            }
            break;
        case 4:
            {
                *out_value = -1;
            }
            break;
        case 5:
            {
                *out_value = -2;
            }
            break;
        case 6:
            {
                *out_value = -3;
            }
            break;
        case 7:
            {
                *out_value = -9871232;
            }
            break;
        case 8:
            {
                *out_value = MBEDTLS_ERR_MPI_NEGATIVE_VALUE;
            }
            break;
        case 9:
            {
                *out_value = MBEDTLS_ERR_MPI_DIVISION_BY_ZERO;
            }
            break;
        case 10:
            {
                *out_value = -13;
            }
            break;
        case 11:
            {
                *out_value = -34;
            }
            break;
        case 12:
            {
                *out_value = MBEDTLS_MPI_MAX_SIZE;
            }
            break;
        case 13:
            {
                *out_value = MBEDTLS_MPI_MAX_SIZE + 1;
            }
            break;
        case 14:
            {
                *out_value = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
            }
            break;
        case 15:
            {
                *out_value = MBEDTLS_MPI_GEN_PRIME_FLAG_DH;
            }
            break;
        case 16:
            {
                *out_value = MBEDTLS_MPI_GEN_PRIME_FLAG_DH | MBEDTLS_MPI_GEN_PRIME_FLAG_LOW_ERR;
            }
            break;
        case 17:
            {
                *out_value = MBEDTLS_MPI_GEN_PRIME_FLAG_LOW_ERR;
            }
            break;
        case 18:
            {
                *out_value = MBEDTLS_MPI_MAX_SIZE - 7;
            }
            break;
        case 19:
            {
                *out_value = -65;
            }
            break;
        case 20:
            {
                *out_value = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
            }
            break;
        case 21:
            {
                *out_value = MBEDTLS_MPI_MAX_SIZE-1;
            }
            break;
#endif

#line 83 "suites/main_test.function"
        default:
           {
                ret = KEY_VALUE_MAPPING_NOT_FOUND;
           }
           break;
    }
    return( ret );
}


/**
 * \brief       Checks if the dependency i.e. the compile flag is set.
 *              For optimizing space for embedded targets each dependency
 *              is identified by a unique identifier instead of string literals.
 *              Identifiers and check code is generated by script:
 *              generate_test_code.py
 *
 * \param dep_id    Dependency identifier.
 *
 * \return       DEPENDENCY_SUPPORTED if set else DEPENDENCY_NOT_SUPPORTED
 */
int dep_check( int dep_id )
{
    int ret = DEPENDENCY_NOT_SUPPORTED;

    (void) dep_id;

    switch( dep_id )
    {

#if defined(MBEDTLS_BIGNUM_C)

        case 0:
            {
#if defined(MPI_MAX_BITS_LARGER_THAN_792)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 1:
            {
#if defined(MBEDTLS_GENPRIME)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 2:
            {
#if defined(MBEDTLS_SELF_TEST)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
#endif

#line 114 "suites/main_test.function"
        default:
            break;
    }
    return( ret );
}


/**
 * \brief       Function pointer type for test function wrappers.
 *
 * A test function wrapper decodes the parameters and passes them to the
 * underlying test function. Both the wrapper and the underlying function
 * return void. Test wrappers assume that they are passed a suitable
 * parameter array and do not perform any error detection.
 *
 * \param param_array   The array of parameters. Each element is a `void *`
 *                      which the wrapper casts to the correct type and
 *                      dereferences. Each wrapper function hard-codes the
 *                      number and types of the parameters.
 */
typedef void (*TestWrapper_t)( void **param_array );


/**
 * \brief       Table of test function wrappers. Used by dispatch_test().
 *              This table is populated by script:
 *              generate_test_code.py
 *
 */
TestWrapper_t test_funcs[] =
{
/* Function Id: 0 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mpi_null_wrapper,
#else
    NULL,
#endif
/* Function Id: 1 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mpi_read_write_string_wrapper,
#else
    NULL,
#endif
/* Function Id: 2 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_read_binary_wrapper,
#else
    NULL,
#endif
/* Function Id: 3 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_read_binary_le_wrapper,
#else
    NULL,
#endif
/* Function Id: 4 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_write_binary_wrapper,
#else
    NULL,
#endif
/* Function Id: 5 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_write_binary_le_wrapper,
#else
    NULL,
#endif
/* Function Id: 6 */

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_FS_IO)
    test_mbedtls_mpi_read_file_wrapper,
#else
    NULL,
#endif
/* Function Id: 7 */

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_FS_IO)
    test_mbedtls_mpi_write_file_wrapper,
#else
    NULL,
#endif
/* Function Id: 8 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_get_bit_wrapper,
#else
    NULL,
#endif
/* Function Id: 9 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_set_bit_wrapper,
#else
    NULL,
#endif
/* Function Id: 10 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_lsb_wrapper,
#else
    NULL,
#endif
/* Function Id: 11 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_bitlen_wrapper,
#else
    NULL,
#endif
/* Function Id: 12 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_gcd_wrapper,
#else
    NULL,
#endif
/* Function Id: 13 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_cmp_int_wrapper,
#else
    NULL,
#endif
/* Function Id: 14 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_cmp_mpi_wrapper,
#else
    NULL,
#endif
/* Function Id: 15 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_lt_mpi_ct_wrapper,
#else
    NULL,
#endif
/* Function Id: 16 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_cmp_abs_wrapper,
#else
    NULL,
#endif
/* Function Id: 17 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_copy_wrapper,
#else
    NULL,
#endif
/* Function Id: 18 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mpi_copy_self_wrapper,
#else
    NULL,
#endif
/* Function Id: 19 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_swap_wrapper,
#else
    NULL,
#endif
/* Function Id: 20 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mpi_swap_self_wrapper,
#else
    NULL,
#endif
/* Function Id: 21 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_shrink_wrapper,
#else
    NULL,
#endif
/* Function Id: 22 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_add_mpi_wrapper,
#else
    NULL,
#endif
/* Function Id: 23 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_add_mpi_inplace_wrapper,
#else
    NULL,
#endif
/* Function Id: 24 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_add_abs_wrapper,
#else
    NULL,
#endif
/* Function Id: 25 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_add_int_wrapper,
#else
    NULL,
#endif
/* Function Id: 26 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_sub_mpi_wrapper,
#else
    NULL,
#endif
/* Function Id: 27 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_sub_abs_wrapper,
#else
    NULL,
#endif
/* Function Id: 28 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_sub_int_wrapper,
#else
    NULL,
#endif
/* Function Id: 29 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_mul_mpi_wrapper,
#else
    NULL,
#endif
/* Function Id: 30 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_mul_int_wrapper,
#else
    NULL,
#endif
/* Function Id: 31 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_div_mpi_wrapper,
#else
    NULL,
#endif
/* Function Id: 32 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_div_int_wrapper,
#else
    NULL,
#endif
/* Function Id: 33 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_mod_mpi_wrapper,
#else
    NULL,
#endif
/* Function Id: 34 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_mod_int_wrapper,
#else
    NULL,
#endif
/* Function Id: 35 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_exp_mod_wrapper,
#else
    NULL,
#endif
/* Function Id: 36 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_exp_mod_size_wrapper,
#else
    NULL,
#endif
/* Function Id: 37 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_inv_mod_wrapper,
#else
    NULL,
#endif
/* Function Id: 38 */

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_GENPRIME)
    test_mbedtls_mpi_is_prime_wrapper,
#else
    NULL,
#endif
/* Function Id: 39 */

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_GENPRIME)
    test_mbedtls_mpi_is_prime_det_wrapper,
#else
    NULL,
#endif
/* Function Id: 40 */

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_GENPRIME)
    test_mbedtls_mpi_gen_prime_wrapper,
#else
    NULL,
#endif
/* Function Id: 41 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_shift_l_wrapper,
#else
    NULL,
#endif
/* Function Id: 42 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_mpi_shift_r_wrapper,
#else
    NULL,
#endif
/* Function Id: 43 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mpi_fill_random_wrapper,
#else
    NULL,
#endif
/* Function Id: 44 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mpi_random_many_wrapper,
#else
    NULL,
#endif
/* Function Id: 45 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mpi_random_sizes_wrapper,
#else
    NULL,
#endif
/* Function Id: 46 */

#if defined(MBEDTLS_BIGNUM_C)
    test_mpi_random_fail_wrapper,
#else
    NULL,
#endif
/* Function Id: 47 */

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_SELF_TEST)
    test_mpi_selftest_wrapper,
#else
    NULL,
#endif

#line 147 "suites/main_test.function"
};

/**
 * \brief        Dispatches test functions based on function index.
 *
 * \param func_idx    Test function index.
 * \param params      The array of parameters to pass to the test function.
 *                    It will be decoded by the #TestWrapper_t wrapper function.
 *
 * \return       DISPATCH_TEST_SUCCESS if found
 *               DISPATCH_TEST_FN_NOT_FOUND if not found
 *               DISPATCH_UNSUPPORTED_SUITE if not compile time enabled.
 */
int dispatch_test( size_t func_idx, void ** params )
{
    int ret = DISPATCH_TEST_SUCCESS;
    TestWrapper_t fp = NULL;

    if ( func_idx < (int)( sizeof( test_funcs ) / sizeof( TestWrapper_t ) ) )
    {
        fp = test_funcs[func_idx];
        if ( fp )
        {
            #if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
                mbedtls_test_enable_insecure_external_rng( );
            #endif

                fp( params );

            #if defined(MBEDTLS_TEST_MUTEX_USAGE)
                mbedtls_test_mutex_usage_check( );
            #endif /* MBEDTLS_TEST_MUTEX_USAGE */
        }
        else
            ret = DISPATCH_UNSUPPORTED_SUITE;
    }
    else
    {
        ret = DISPATCH_TEST_FN_NOT_FOUND;
    }

    return( ret );
}


/**
 * \brief       Checks if test function is supported in this build-time
 *              configuration.
 *
 * \param func_idx    Test function index.
 *
 * \return       DISPATCH_TEST_SUCCESS if found
 *               DISPATCH_TEST_FN_NOT_FOUND if not found
 *               DISPATCH_UNSUPPORTED_SUITE if not compile time enabled.
 */
int check_test( size_t func_idx )
{
    int ret = DISPATCH_TEST_SUCCESS;
    TestWrapper_t fp = NULL;

    if ( func_idx < (int)( sizeof(test_funcs)/sizeof( TestWrapper_t ) ) )
    {
        fp = test_funcs[func_idx];
        if ( fp == NULL )
            ret = DISPATCH_UNSUPPORTED_SUITE;
    }
    else
    {
        ret = DISPATCH_TEST_FN_NOT_FOUND;
    }

    return( ret );
}


#line 2 "suites/host_test.function"

/**
 * \brief       Verifies that string is in string parameter format i.e. "<str>"
 *              It also strips enclosing '"' from the input string.
 *
 * \param str   String parameter.
 *
 * \return      0 if success else 1
 */
int verify_string( char **str )
{
    if( ( *str )[0] != '"' ||
        ( *str )[strlen( *str ) - 1] != '"' )
    {
        mbedtls_fprintf( stderr,
            "Expected string (with \"\") for parameter and got: %s\n", *str );
        return( -1 );
    }

    ( *str )++;
    ( *str )[strlen( *str ) - 1] = '\0';

    return( 0 );
}

/**
 * \brief       Verifies that string is an integer. Also gives the converted
 *              integer value.
 *
 * \param str   Input string.
 * \param value Pointer to int for output value.
 *
 * \return      0 if success else 1
 */
int verify_int( char *str, int32_t *value )
{
    size_t i;
    int minus = 0;
    int digits = 1;
    int hex = 0;

    for( i = 0; i < strlen( str ); i++ )
    {
        if( i == 0 && str[i] == '-' )
        {
            minus = 1;
            continue;
        }

        if( ( ( minus && i == 2 ) || ( !minus && i == 1 ) ) &&
            str[i - 1] == '0' && ( str[i] == 'x' || str[i] == 'X' ) )
        {
            hex = 1;
            continue;
        }

        if( ! ( ( str[i] >= '0' && str[i] <= '9' ) ||
                ( hex && ( ( str[i] >= 'a' && str[i] <= 'f' ) ||
                           ( str[i] >= 'A' && str[i] <= 'F' ) ) ) ) )
        {
            digits = 0;
            break;
        }
    }

    if( digits )
    {
        if( hex )
            *value = strtol( str, NULL, 16 );
        else
            *value = strtol( str, NULL, 10 );

        return( 0 );
    }

    mbedtls_fprintf( stderr,
                    "Expected integer for parameter and got: %s\n", str );
    return( KEY_VALUE_MAPPING_NOT_FOUND );
}


/**
 * \brief       Usage string.
 *
 */
#define USAGE \
    "Usage: %s [OPTIONS] files...\n\n" \
    "   Command line arguments:\n" \
    "     files...          One or more test data files. If no file is\n" \
    "                       specified the following default test case\n" \
    "                       file is used:\n" \
    "                           %s\n\n" \
    "   Options:\n" \
    "     -v | --verbose    Display full information about each test\n" \
    "     -h | --help       Display this information\n\n", \
    argv[0], \
    "TESTCASE_FILENAME"


/**
 * \brief       Read a line from the passed file pointer.
 *
 * \param f     FILE pointer
 * \param buf   Pointer to memory to hold read line.
 * \param len   Length of the buf.
 *
 * \return      0 if success else -1
 */
int get_line( FILE *f, char *buf, size_t len )
{
    char *ret;
    int i = 0, str_len = 0, has_string = 0;

    /* Read until we get a valid line */
    do
    {
        ret = fgets( buf, len, f );
        if( ret == NULL )
            return( -1 );

        str_len = strlen( buf );

        /* Skip empty line and comment */
        if ( str_len == 0 || buf[0] == '#' )
            continue;
        has_string = 0;
        for ( i = 0; i < str_len; i++ )
        {
            char c = buf[i];
            if ( c != ' ' && c != '\t' && c != '\n' &&
                 c != '\v' && c != '\f' && c != '\r' )
            {
                has_string = 1;
                break;
            }
        }
    } while( !has_string );

    /* Strip new line and carriage return */
    ret = buf + strlen( buf );
    if( ret-- > buf && *ret == '\n' )
        *ret = '\0';
    if( ret-- > buf && *ret == '\r' )
        *ret = '\0';

    return( 0 );
}

/**
 * \brief       Splits string delimited by ':'. Ignores '\:'.
 *
 * \param buf           Input string
 * \param len           Input string length
 * \param params        Out params found
 * \param params_len    Out params array len
 *
 * \return      Count of strings found.
 */
static int parse_arguments( char *buf, size_t len, char **params,
                            size_t params_len )
{
    size_t cnt = 0, i;
    char *cur = buf;
    char *p = buf, *q;

    params[cnt++] = cur;

    while( *p != '\0' && p < ( buf + len ) )
    {
        if( *p == '\\' )
        {
            p++;
            p++;
            continue;
        }
        if( *p == ':' )
        {
            if( p + 1 < buf + len )
            {
                cur = p + 1;
                TEST_HELPER_ASSERT( cnt < params_len );
                params[cnt++] = cur;
            }
            *p = '\0';
        }

        p++;
    }

    /* Replace newlines, question marks and colons in strings */
    for( i = 0; i < cnt; i++ )
    {
        p = params[i];
        q = params[i];

        while( *p != '\0' )
        {
            if( *p == '\\' && *( p + 1 ) == 'n' )
            {
                p += 2;
                *( q++ ) = '\n';
            }
            else if( *p == '\\' && *( p + 1 ) == ':' )
            {
                p += 2;
                *( q++ ) = ':';
            }
            else if( *p == '\\' && *( p + 1 ) == '?' )
            {
                p += 2;
                *( q++ ) = '?';
            }
            else
                *( q++ ) = *( p++ );
        }
        *q = '\0';
    }

    return( cnt );
}

/**
 * \brief       Converts parameters into test function consumable parameters.
 *              Example: Input:  {"int", "0", "char*", "Hello",
 *                                "hex", "abef", "exp", "1"}
 *                      Output:  {
 *                                0,                // Verified int
 *                                "Hello",          // Verified string
 *                                2, { 0xab, 0xef },// Converted len,hex pair
 *                                9600              // Evaluated expression
 *                               }
 *
 *
 * \param cnt               Parameter array count.
 * \param params            Out array of found parameters.
 * \param int_params_store  Memory for storing processed integer parameters.
 *
 * \return      0 for success else 1
 */
static int convert_params( size_t cnt , char ** params , int32_t * int_params_store )
{
    char ** cur = params;
    char ** out = params;
    int ret = DISPATCH_TEST_SUCCESS;

    while ( cur < params + cnt )
    {
        char * type = *cur++;
        char * val = *cur++;

        if ( strcmp( type, "char*" ) == 0 )
        {
            if ( verify_string( &val ) == 0 )
            {
              *out++ = val;
            }
            else
            {
                ret = ( DISPATCH_INVALID_TEST_DATA );
                break;
            }
        }
        else if ( strcmp( type, "int" ) == 0 )
        {
            if ( verify_int( val, int_params_store ) == 0 )
            {
              *out++ = (char *) int_params_store++;
            }
            else
            {
                ret = ( DISPATCH_INVALID_TEST_DATA );
                break;
            }
        }
        else if ( strcmp( type, "hex" ) == 0 )
        {
            if ( verify_string( &val ) == 0 )
            {
                size_t len;

                TEST_HELPER_ASSERT(
                  mbedtls_test_unhexify( (unsigned char *) val, strlen( val ),
                                         val, &len ) == 0 );

                *int_params_store = len;
                *out++ = val;
                *out++ = (char *)(int_params_store++);
            }
            else
            {
                ret = ( DISPATCH_INVALID_TEST_DATA );
                break;
            }
        }
        else if ( strcmp( type, "exp" ) == 0 )
        {
            int exp_id = strtol( val, NULL, 10 );
            if ( get_expression ( exp_id, int_params_store ) == 0 )
            {
              *out++ = (char *)int_params_store++;
            }
            else
            {
              ret = ( DISPATCH_INVALID_TEST_DATA );
              break;
            }
        }
        else
        {
          ret = ( DISPATCH_INVALID_TEST_DATA );
          break;
        }
    }
    return( ret );
}

/**
 * \brief       Tests snprintf implementation with test input.
 *
 * \note
 * At high optimization levels (e.g. gcc -O3), this function may be
 * inlined in run_test_snprintf. This can trigger a spurious warning about
 * potential misuse of snprintf from gcc -Wformat-truncation (observed with
 * gcc 7.2). This warning makes tests in run_test_snprintf redundant on gcc
 * only. They are still valid for other compilers. Avoid this warning by
 * forbidding inlining of this function by gcc.
 *
 * \param n         Buffer test length.
 * \param ref_buf   Expected buffer.
 * \param ref_ret   Expected snprintf return value.
 *
 * \return      0 for success else 1
 */
#if defined(__GNUC__)
__attribute__((__noinline__))
#endif
static int test_snprintf( size_t n, const char *ref_buf, int ref_ret )
{
    int ret;
    char buf[10] = "xxxxxxxxx";
    const char ref[10] = "xxxxxxxxx";

    if( n >= sizeof( buf ) )
        return( -1 );
    ret = mbedtls_snprintf( buf, n, "%s", "123" );
    if( ret < 0 || (size_t) ret >= n )
        ret = -1;

    if( strncmp( ref_buf, buf, sizeof( buf ) ) != 0 ||
        ref_ret != ret ||
        memcmp( buf + n, ref + n, sizeof( buf ) - n ) != 0 )
    {
        return( 1 );
    }

    return( 0 );
}

/**
 * \brief       Tests snprintf implementation.
 *
 * \return      0 for success else 1
 */
static int run_test_snprintf( void )
{
    return( test_snprintf( 0, "xxxxxxxxx",  -1 ) != 0 ||
            test_snprintf( 1, "",           -1 ) != 0 ||
            test_snprintf( 2, "1",          -1 ) != 0 ||
            test_snprintf( 3, "12",         -1 ) != 0 ||
            test_snprintf( 4, "123",         3 ) != 0 ||
            test_snprintf( 5, "123",         3 ) != 0 );
}

/** \brief Write the description of the test case to the outcome CSV file.
 *
 * \param outcome_file  The file to write to.
 *                      If this is \c NULL, this function does nothing.
 * \param argv0         The test suite name.
 * \param test_case     The test case description.
 */
static void write_outcome_entry( FILE *outcome_file,
                                 const char *argv0,
                                 const char *test_case )
{
    /* The non-varying fields are initialized on first use. */
    static const char *platform = NULL;
    static const char *configuration = NULL;
    static const char *test_suite = NULL;

    if( outcome_file == NULL )
        return;

    if( platform == NULL )
    {
        platform = getenv( "MBEDTLS_TEST_PLATFORM" );
        if( platform == NULL )
            platform = "unknown";
    }
    if( configuration == NULL )
    {
        configuration = getenv( "MBEDTLS_TEST_CONFIGURATION" );
        if( configuration == NULL )
            configuration = "unknown";
    }
    if( test_suite == NULL )
    {
        test_suite = strrchr( argv0, '/' );
        if( test_suite != NULL )
            test_suite += 1; // skip the '/'
        else
            test_suite = argv0;
    }

    /* Write the beginning of the outcome line.
     * Ignore errors: writing the outcome file is on a best-effort basis. */
    mbedtls_fprintf( outcome_file, "%s;%s;%s;%s;",
                     platform, configuration, test_suite, test_case );
}

/** \brief Write the result of the test case to the outcome CSV file.
 *
 * \param outcome_file  The file to write to.
 *                      If this is \c NULL, this function does nothing.
 * \param unmet_dep_count            The number of unmet dependencies.
 * \param unmet_dependencies         The array of unmet dependencies.
 * \param missing_unmet_dependencies Non-zero if there was a problem tracking
 *                                   all unmet dependencies, 0 otherwise.
 * \param ret                        The test dispatch status (DISPATCH_xxx).
 * \param info                       A pointer to the test info structure.
 */
static void write_outcome_result( FILE *outcome_file,
                                  size_t unmet_dep_count,
                                  int unmet_dependencies[],
                                  int missing_unmet_dependencies,
                                  int ret,
                                  const mbedtls_test_info_t *info )
{
    if( outcome_file == NULL )
        return;

    /* Write the end of the outcome line.
     * Ignore errors: writing the outcome file is on a best-effort basis. */
    switch( ret )
    {
        case DISPATCH_TEST_SUCCESS:
            if( unmet_dep_count > 0 )
            {
                size_t i;
                mbedtls_fprintf( outcome_file, "SKIP" );
                for( i = 0; i < unmet_dep_count; i++ )
                {
                    mbedtls_fprintf( outcome_file, "%c%d",
                                     i == 0 ? ';' : ':',
                                     unmet_dependencies[i] );
                }
                if( missing_unmet_dependencies )
                    mbedtls_fprintf( outcome_file, ":..." );
                break;
            }
            switch( info->result )
            {
                case MBEDTLS_TEST_RESULT_SUCCESS:
                    mbedtls_fprintf( outcome_file, "PASS;" );
                    break;
                case MBEDTLS_TEST_RESULT_SKIPPED:
                    mbedtls_fprintf( outcome_file, "SKIP;Runtime skip" );
                    break;
                default:
                    mbedtls_fprintf( outcome_file, "FAIL;%s:%d:%s",
                                     info->filename, info->line_no,
                                     info->test );
                    break;
            }
            break;
        case DISPATCH_TEST_FN_NOT_FOUND:
            mbedtls_fprintf( outcome_file, "FAIL;Test function not found" );
            break;
        case DISPATCH_INVALID_TEST_DATA:
            mbedtls_fprintf( outcome_file, "FAIL;Invalid test data" );
            break;
        case DISPATCH_UNSUPPORTED_SUITE:
            mbedtls_fprintf( outcome_file, "SKIP;Unsupported suite" );
            break;
        default:
            mbedtls_fprintf( outcome_file, "FAIL;Unknown cause" );
            break;
    }
    mbedtls_fprintf( outcome_file, "\n" );
    fflush( outcome_file );
}

/**
 * \brief       Desktop implementation of execute_tests().
 *              Parses command line and executes tests from
 *              supplied or default data file.
 *
 * \param argc  Command line argument count.
 * \param argv  Argument array.
 *
 * \return      Program exit status.
 */
int execute_tests( int argc , const char ** argv )
{
    /* Local Configurations and options */
    const char *default_filename = "./test_suite_mpi.datax";
    const char *test_filename = NULL;
    const char **test_files = NULL;
    size_t testfile_count = 0;
    int option_verbose = 0;
    size_t function_id = 0;

    /* Other Local variables */
    int arg_index = 1;
    const char *next_arg;
    size_t testfile_index, i, cnt;
    int ret;
    unsigned total_errors = 0, total_tests = 0, total_skipped = 0;
    FILE *file;
    char buf[5000];
    char *params[50];
    /* Store for processed integer params. */
    int32_t int_params[50];
    void *pointer;
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
    int stdout_fd = -1;
#endif /* __unix__ || __APPLE__ __MACH__ */
    const char *outcome_file_name = getenv( "MBEDTLS_TEST_OUTCOME_FILE" );
    FILE *outcome_file = NULL;

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
    unsigned char alloc_buf[1000000];
    mbedtls_memory_buffer_alloc_init( alloc_buf, sizeof( alloc_buf ) );
#endif

#if defined(MBEDTLS_TEST_MUTEX_USAGE)
    mbedtls_test_mutex_usage_init( );
#endif

    /*
     * The C standard doesn't guarantee that all-bits-0 is the representation
     * of a NULL pointer. We do however use that in our code for initializing
     * structures, which should work on every modern platform. Let's be sure.
     */
    memset( &pointer, 0, sizeof( void * ) );
    if( pointer != NULL )
    {
        mbedtls_fprintf( stderr, "all-bits-zero is not a NULL pointer\n" );
        return( 1 );
    }

    /*
     * Make sure we have a snprintf that correctly zero-terminates
     */
    if( run_test_snprintf() != 0 )
    {
        mbedtls_fprintf( stderr, "the snprintf implementation is broken\n" );
        return( 1 );
    }

    if( outcome_file_name != NULL && *outcome_file_name != '\0' )
    {
        outcome_file = fopen( outcome_file_name, "a" );
        if( outcome_file == NULL )
        {
            mbedtls_fprintf( stderr, "Unable to open outcome file. Continuing anyway.\n" );
        }
    }

    while( arg_index < argc )
    {
        next_arg = argv[arg_index];

        if( strcmp( next_arg, "--verbose" ) == 0 ||
                 strcmp( next_arg, "-v" ) == 0 )
        {
            option_verbose = 1;
        }
        else if( strcmp(next_arg, "--help" ) == 0 ||
                 strcmp(next_arg, "-h" ) == 0 )
        {
            mbedtls_fprintf( stdout, USAGE );
            mbedtls_exit( EXIT_SUCCESS );
        }
        else
        {
            /* Not an option, therefore treat all further arguments as the file
             * list.
             */
            test_files = &argv[ arg_index ];
            testfile_count = argc - arg_index;
        }

        arg_index++;
    }

    /* If no files were specified, assume a default */
    if ( test_files == NULL || testfile_count == 0 )
    {
        test_files = &default_filename;
        testfile_count = 1;
    }

    /* Initialize the struct that holds information about the last test */
    mbedtls_test_info_reset( );

    /* Now begin to execute the tests in the testfiles */
    for ( testfile_index = 0;
          testfile_index < testfile_count;
          testfile_index++ )
    {
        size_t unmet_dep_count = 0;
        int unmet_dependencies[20];
        int missing_unmet_dependencies = 0;

        test_filename = test_files[ testfile_index ];

        file = fopen( test_filename, "r" );
        if( file == NULL )
        {
            mbedtls_fprintf( stderr, "Failed to open test file: %s\n",
                             test_filename );
            if( outcome_file != NULL )
                fclose( outcome_file );
            return( 1 );
        }

        while( !feof( file ) )
        {
            if( unmet_dep_count > 0 )
            {
                mbedtls_fprintf( stderr,
                    "FATAL: Dep count larger than zero at start of loop\n" );
                mbedtls_exit( MBEDTLS_EXIT_FAILURE );
            }
            unmet_dep_count = 0;
            missing_unmet_dependencies = 0;

            if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
                break;
            mbedtls_fprintf( stdout, "%s%.66s",
                    mbedtls_test_info.result == MBEDTLS_TEST_RESULT_FAILED ?
                    "\n" : "", buf );
            mbedtls_fprintf( stdout, " " );
            for( i = strlen( buf ) + 1; i < 67; i++ )
                mbedtls_fprintf( stdout, "." );
            mbedtls_fprintf( stdout, " " );
            fflush( stdout );
            write_outcome_entry( outcome_file, argv[0], buf );

            total_tests++;

            if( ( ret = get_line( file, buf, sizeof( buf ) ) ) != 0 )
                break;
            cnt = parse_arguments( buf, strlen( buf ), params,
                                   sizeof( params ) / sizeof( params[0] ) );

            if( strcmp( params[0], "depends_on" ) == 0 )
            {
                for( i = 1; i < cnt; i++ )
                {
                    int dep_id = strtol( params[i], NULL, 10 );
                    if( dep_check( dep_id ) != DEPENDENCY_SUPPORTED )
                    {
                        if( unmet_dep_count <
                            ARRAY_LENGTH( unmet_dependencies ) )
                        {
                            unmet_dependencies[unmet_dep_count] = dep_id;
                            unmet_dep_count++;
                        }
                        else
                        {
                            missing_unmet_dependencies = 1;
                        }
                    }
                }

                if( ( ret = get_line( file, buf, sizeof( buf ) ) ) != 0 )
                    break;
                cnt = parse_arguments( buf, strlen( buf ), params,
                                       sizeof( params ) / sizeof( params[0] ) );
            }

            // If there are no unmet dependencies execute the test
            if( unmet_dep_count == 0 )
            {
                mbedtls_test_info_reset( );

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
                /* Suppress all output from the library unless we're verbose
                 * mode
                 */
                if( !option_verbose )
                {
                    stdout_fd = redirect_output( stdout, "/dev/null" );
                    if( stdout_fd == -1 )
                    {
                        /* Redirection has failed with no stdout so exit */
                        exit( 1 );
                    }
                }
#endif /* __unix__ || __APPLE__ __MACH__ */

                function_id = strtoul( params[0], NULL, 10 );
                if ( (ret = check_test( function_id )) == DISPATCH_TEST_SUCCESS )
                {
                    ret = convert_params( cnt - 1, params + 1, int_params );
                    if ( DISPATCH_TEST_SUCCESS == ret )
                    {
                        ret = dispatch_test( function_id, (void **)( params + 1 ) );
                    }
                }

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
                if( !option_verbose && restore_output( stdout, stdout_fd ) )
                {
                        /* Redirection has failed with no stdout so exit */
                        exit( 1 );
                }
#endif /* __unix__ || __APPLE__ __MACH__ */

            }

            write_outcome_result( outcome_file,
                                  unmet_dep_count, unmet_dependencies,
                                  missing_unmet_dependencies,
                                  ret, &mbedtls_test_info );
            if( unmet_dep_count > 0 || ret == DISPATCH_UNSUPPORTED_SUITE )
            {
                total_skipped++;
                mbedtls_fprintf( stdout, "----" );

                if( 1 == option_verbose && ret == DISPATCH_UNSUPPORTED_SUITE )
                {
                    mbedtls_fprintf( stdout, "\n   Test Suite not enabled" );
                }

                if( 1 == option_verbose && unmet_dep_count > 0 )
                {
                    mbedtls_fprintf( stdout, "\n   Unmet dependencies: " );
                    for( i = 0; i < unmet_dep_count; i++ )
                    {
                        mbedtls_fprintf( stdout, "%d ",
                                        unmet_dependencies[i] );
                    }
                    if( missing_unmet_dependencies )
                        mbedtls_fprintf( stdout, "..." );
                }
                mbedtls_fprintf( stdout, "\n" );
                fflush( stdout );

                unmet_dep_count = 0;
                missing_unmet_dependencies = 0;
            }
            else if( ret == DISPATCH_TEST_SUCCESS )
            {
                if( mbedtls_test_info.result == MBEDTLS_TEST_RESULT_SUCCESS )
                {
                    mbedtls_fprintf( stdout, "PASS\n" );
                }
                else if( mbedtls_test_info.result == MBEDTLS_TEST_RESULT_SKIPPED )
                {
                    mbedtls_fprintf( stdout, "----\n" );
                    total_skipped++;
                }
                else
                {
                    total_errors++;
                    mbedtls_fprintf( stdout, "FAILED\n" );
                    mbedtls_fprintf( stdout, "  %s\n  at ",
                                     mbedtls_test_info.test );
                    if( mbedtls_test_info.step != (unsigned long)( -1 ) )
                    {
                        mbedtls_fprintf( stdout, "step %lu, ",
                                         mbedtls_test_info.step );
                    }
                    mbedtls_fprintf( stdout, "line %d, %s",
                                     mbedtls_test_info.line_no,
                                     mbedtls_test_info.filename );
                    if( mbedtls_test_info.line1[0] != 0 )
                        mbedtls_fprintf( stdout, "\n  %s",
                                         mbedtls_test_info.line1 );
                    if( mbedtls_test_info.line2[0] != 0 )
                        mbedtls_fprintf( stdout, "\n  %s",
                                         mbedtls_test_info.line2 );
                }
                fflush( stdout );
            }
            else if( ret == DISPATCH_INVALID_TEST_DATA )
            {
                mbedtls_fprintf( stderr, "FAILED: FATAL PARSE ERROR\n" );
                fclose( file );
                mbedtls_exit( 2 );
            }
            else if( ret == DISPATCH_TEST_FN_NOT_FOUND )
            {
                mbedtls_fprintf( stderr, "FAILED: FATAL TEST FUNCTION NOT FOUND\n" );
                fclose( file );
                mbedtls_exit( 2 );
            }
            else
                total_errors++;
        }
        fclose( file );
    }

    if( outcome_file != NULL )
        fclose( outcome_file );

    mbedtls_fprintf( stdout, "\n----------------------------------------------------------------------------\n\n");
    if( total_errors == 0 )
        mbedtls_fprintf( stdout, "PASSED" );
    else
        mbedtls_fprintf( stdout, "FAILED" );

    mbedtls_fprintf( stdout, " (%u / %u tests (%u skipped))\n",
                     total_tests - total_errors, total_tests, total_skipped );

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
#if defined(MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_status();
#endif
    mbedtls_memory_buffer_alloc_free();
#endif

    return( total_errors != 0 );
}


#line 225 "suites/main_test.function"

/*----------------------------------------------------------------------------*/
/* Main Test code */


/**
 * \brief       Program main. Invokes platform specific execute_tests().
 *
 * \param argc      Command line arguments count.
 * \param argv      Array of command line arguments.
 *
 * \return       Exit code.
 */
int main( int argc, const char *argv[] )
{
#if defined(MBEDTLS_TEST_HOOKS)
    extern void (*mbedtls_test_hook_test_fail)( const char * test, int line, const char * file );
    mbedtls_test_hook_test_fail = &mbedtls_test_fail;
#if defined(MBEDTLS_ERROR_C)
    mbedtls_test_hook_error_add = &mbedtls_test_err_add_check;
#endif
#endif

    int ret = mbedtls_test_platform_setup();
    if( ret != 0 )
    {
        mbedtls_fprintf( stderr,
                         "FATAL: Failed to initialize platform - error %d\n",
                         ret );
        return( -1 );
    }

    ret = execute_tests( argc, argv );
    mbedtls_test_platform_teardown();
    return( ret );
}
