/* kem.c --> rlce.c
 * https://bench.cr.yp.to/call-encrypt.html
 * http://csrc.nist.gov/groups/ST/post-quantum-crypto/documents/example-files/api-notes.pdf
 */
#include "config.h"
#include "api.h"
#include <oqs/rand.h>
#include "rlce.h"

 //Signature matches that provided in rlce.h
int oqs_kex_goppa_rlce_gen_keypair(
	unsigned char *pk,
	unsigned char *sk,
	OQS_RAND *rand) {
	unsigned int para[PARASIZE];
	int ret;
	ret = getRLCEparameters(para, CRYPTO_SCHEME, CRYPTO_PADDING);
	if (ret < 0) return ret;
	unsigned char randomness[para[19]];
	OQS_RAND_n(rand, randomness, para[19]);
	RLCE_private_key_t RLCEsk = RLCE_private_key_init(para);
	RLCE_public_key_t RLCEpk = RLCE_public_key_init(para);
	unsigned char nonce[] = { 0x5e,0x7d,0x69,0xe1,0x87,0x57,0x7b,0x04,0x33,0xee,0xe8,0xea,0xb9,0xf7,0x77,0x31 };
	ret = RLCE_key_setup((unsigned char *)randomness, para[19], nonce, 16, RLCEpk, RLCEsk);
	if (ret < 0) return ret;
	unsigned int sklen = CRYPTO_SECRETKEYBYTES;
	unsigned int pklen = CRYPTO_PUBLICKEYBYTES;
	ret = pk2B(RLCEpk, pk, &pklen);
	ret = sk2B(RLCEsk, sk, &sklen);
	return ret;
}


int oqs_kex_goppa_rlce_encrypt(
	unsigned char *c, size_t *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *pk,
	OQS_RAND *rand) {
	int ret;
	RLCE_public_key_t RLCEpk = B2pk(pk, CRYPTO_PUBLICKEYBYTES);
	if (RLCEpk == NULL) return -1;
	unsigned long long RLCEmlen = RLCEpk->para[6];
	unsigned char randomness[RLCEpk->para[19]];
	OQS_RAND_n(rand, randomness, RLCEpk->para[19]);
	unsigned char *message = calloc(RLCEmlen, sizeof(unsigned char));
	

	if (clen == 0) {
		return -1;
	}
	 
	if (mlen == 0) {
		return -1;
	}
	  
	memcpy(message, m, mlen);
	clen[0] = RLCEpk->para[16];
	unsigned char nonce[1];
	ret = RLCE_encrypt(message, RLCEmlen, (unsigned char *)randomness, RLCEpk->para[19], nonce, 0, RLCEpk, c, (unsigned long long *)clen);
	free(message);
	return ret;
}

int oqs_kex_goppa_rlce_decrypt(
	unsigned char *ss, size_t *mlen,
	const unsigned char *cipherText, unsigned long long clen,
	const unsigned char *sk) {
	int ret;
	if (clen == 0) {
		return -1;
	}
	 
	if (mlen == 0)  {
		return -1;
	}
	 
	unsigned int para[PARASIZE];
	ret = getRLCEparameters(para, CRYPTO_SCHEME, CRYPTO_PADDING);
	RLCE_private_key_t RLCEsk=B2sk(sk, CRYPTO_SECRETKEYBYTES);
    if (RLCEsk==NULL) return -1;
    unsigned char message[RLCEsk->para[6]];
    mlen[0]=RLCEsk->para[6];
    ret=RLCE_decrypt((unsigned char *)cipherText,para[CRYPTO_CIPHERTEXTBYTES],RLCEsk,message,(unsigned long long *)mlen);
    if (ret<0) return ret;
    memcpy(ss, message, CRYPTO_BYTES);
    return ret;
}
