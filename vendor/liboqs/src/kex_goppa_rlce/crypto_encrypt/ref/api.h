#define CRYPTO_VERSION "1.0"

#ifndef __OQS_RLCE_H
#define __OQS_RLCE_H

#ifndef api_h
#define api_h
#define CRYPTO_BYTES 64
#define CRYPTO_SCHEME 1 /* 1 for 128A, 3 for 192A, 5 for 256A*/
#define CRYPTO_SECRETKEYBYTES 179946
#define CRYPTO_PUBLICKEYBYTES 118441
//#define CRYPTO_BYTES 785
#define CRYPTO_ALGNAME “RLCE”

int oqs_kex_goppa_rlce_encrypt(
    unsigned char *c, size_t *clen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *pk,
    OQS_RAND *r);

int oqs_kex_goppa_rlce_decrypt(
    unsigned char *m, size_t *mlen,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *sk);

int oqs_kex_goppa_rlce_gen_keypair(
    unsigned char *pk,
    unsigned char *sk,
    OQS_RAND *r);

#endif


