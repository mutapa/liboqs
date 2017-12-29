/*
 * https://bench.cr.yp.to/call-encrypt.html
 * http://csrc.nist.gov/groups/ST/post-quantum-crypto/documents/example-files/api-notes.pdf
 */
#include "config.h"
#include "api.h"
#include <oqs/rand.h>
#include "rlce.h"

/*
 * GENERATE KEY PAIR
 * pk = public key
 * sk = private or secret key
 */
int oqs_kex_rlce_gen_keypair(
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

/*
 * PUBLIC KEY ENCRYPTION
 * ct = cipherText returned after encryption
 * clen = message of cipherText message
 * ss = shared secret or Bob's unencrypted message
 * mlen = shared secret message length
 * pk = Alice's public key
 */
int oqs_kex_rlce_encrypt(
	unsigned char *ct, size_t *clen,
	const unsigned char *ss, unsigned long long mlen,
	const unsigned char *pk,
	OQS_RAND *rand) {
	int ret;
	RLCE_public_key_t RLCEpk = B2pk(pk, CRYPTO_PUBLICKEYBYTES);
	if (RLCEpk == NULL) return -1;
	unsigned long long RLCEmlen = RLCEpk->para[6];
	unsigned char randomness[RLCEpk->para[19]];
	OQS_RAND_n(rand, randomness, RLCEpk->para[19]);
	unsigned char *message = calloc(RLCEmlen, sizeof(unsigned char));

	clen = 0;
	//To prevent error: parameter ‘clen’ set but not used [-Werror=unused-but-set-parameter] on gcc compiler
	if (clen == 0) {}

	mlen = 0;
	//To prevent error:  parameter ‘mlen’ set but not used [-Werror=unused-but-set-parameter] on gcc compiler
	if (mlen == 0) {}

	memcpy(message, ss, CRYPTO_BYTES);
	unsigned long long ctlen = CRYPTO_CIPHERTEXTBYTES;
	unsigned char nonce[1];
	ret = RLCE_encrypt(message, RLCEmlen, (unsigned char *)randomness, RLCEpk->para[19], nonce, 0, RLCEpk, ct, &ctlen);
	free(message);
	return ret;
}

/*
 * PUBLIC KEY DECRYPTION
 * ss = shared secret or message returned after decryption
 * mleng = message length
 * ct = Bob's encrypted cipherText message
 * clen = cipherText message length
 * sk = Alice's private key for decryption
*/
int oqs_kex_rlce_decrypt(
	unsigned char *ss, size_t *mleng,
	const unsigned char *ct, unsigned long long clen,
	const unsigned char *sk) {
	int ret;

    mleng = 0;
	//To prevent error: parameter ‘mleng’ set but not used [-Werror=unused-but-set-parameter] on gcc compiler
	if (mleng == 0) {}
	//Unused parameter
	clen = 0;
	//To prevent error: parameter ‘clen’ set but not used [-Werror=unused-but-set-parameter] on gcc compiler
	if (clen == 0) {}

	RLCE_private_key_t RLCEsk=B2sk(sk, CRYPTO_SECRETKEYBYTES);
    if (RLCEsk==NULL) return -1;
    unsigned char message[RLCEsk->para[6]];
	unsigned long long mlen = RLCEsk->para[6];
    ret=RLCE_decrypt((unsigned char *)ct,CRYPTO_CIPHERTEXTBYTES,RLCEsk,message, &mlen);
    if (ret<0) return ret;
    memcpy(ss, message, CRYPTO_BYTES);
    return ret;
}
