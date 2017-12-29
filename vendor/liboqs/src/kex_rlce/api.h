#ifndef api_h
#define api_h
#define CRYPTO_SECRETKEYBYTES 179946
#define CRYPTO_PUBLICKEYBYTES 118441
#define CRYPTO_BYTES 64
#define CRYPTO_CIPHERTEXTBYTES 785
#define CRYPTO_SCHEME 1 /* 1 for 128A, 3 for 192A, 5 for 256A*/
#define CRYPTO_PADDING 1 
#define CRYPTO_VERSION "RLCEpad128mediumA"
#define CRYPTO_ALGNAME "RLCEKEM128A"

#include <oqs/rand.h>

int oqs_kex_rlce_encrypt(
    unsigned char *c, size_t *clen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *pk,
    OQS_RAND *r);

int oqs_kex_rlce_decrypt(
    unsigned char *m, size_t *mlen,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *sk);

int oqs_kex_rlce_gen_keypair(
    unsigned char *pk,
    unsigned char *sk,
    OQS_RAND *r);
	
#endif

