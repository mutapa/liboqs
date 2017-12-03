/* kem.c --> rlce.c
 * https://bench.cr.yp.to/call-encrypt.html
 * http://csrc.nist.gov/groups/ST/post-quantum-crypto/documents/example-files/api-notes.pdf
 */
#include "api.h"
#include "rlce.h"
#include <oqs/rand.h>

//Signature matches that provided in rlce.h
int oqs_kex_goppa_rlce_gen_keypair(
    unsigned char *pk,
    unsigned char *sk,
    OQS_RAND *rand){
  unsigned int para[PARASIZE];
  int ret;
  ret=getRLCEparameters(para,CRYPTO_SCHEME,CRYPTO_PADDING);
  if (ret<0) return ret;
  unsigned char randomness[para[19]];
  //line below commented out and replaced with the OQS_RAND_n call
  //randombytes(randomness, para[19]);
  //use the OQS_RAND_n to populate randomness with data
  OQS_RAND_n(rand, randomness, para[19]);
  RLCE_private_key_t RLCEsk=RLCE_private_key_init(para);
  RLCE_public_key_t RLCEpk=RLCE_public_key_init(para);
  unsigned char nonce[]={0x5e,0x7d,0x69,0xe1,0x87,0x57,0x7b,0x04,0x33,0xee,0xe8,0xea,0xb9,0xf7,0x77,0x31};
  ret=RLCE_key_setup((unsigned char *)randomness,para[19], nonce, 16, RLCEpk, RLCEsk);
  if (ret<0) return ret;
  unsigned int sklen=CRYPTO_SECRETKEYBYTES;
  unsigned int pklen=CRYPTO_PUBLICKEYBYTES;
  ret=pk2B(RLCEpk,pk,&pklen);
  ret=sk2B(RLCEsk,sk,&sklen);
  return ret;

	}


int oqs_kex_goppa_rlce_encrypt(
    unsigned char *c, size_t *clen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *pk,
    OQS_RAND *rand){
  int ret;
  RLCE_public_key_t RLCEpk=B2pk(pk, CRYPTO_PUBLICKEYBYTES);
  if (RLCEpk==NULL) return -1;
  unsigned long long RLCEmlen=RLCEpk->para[6];
  unsigned char randomness[RLCEpk->para[19]];
  //Comment the line below and replace with OQS_RAND_n call
  //randombytes(randomness, RLCEpk->para[19]);
  //Use the OQS_RAND_n to populate randomness with data
  OQS_RAND_n(rand, randomness, para[19]);
  unsigned char *message=calloc(RLCEmlen, sizeof(unsigned char));
  memcpy(message, ss, CRYPTO_BYTES);
  unsigned long long ctlen=CRYPTO_CIPHERTEXTBYTES;
  unsigned char nonce[1];
  ret=RLCE_encrypt(message,RLCEmlen,(unsigned char *)randomness,RLCEpk->para[19],nonce,0,RLCEpk,ct,&ctlen);
  free(message);
  return ret;

	}

int oqs_kex_goppa_rlce_decrypt(
    unsigned char *message, size_t *mlen,
    const unsigned char *cipherText, unsigned long long clen,
    const unsigned char *sk){
  RLCE_private_key_t RLCEsk=B2sk(sk, CRYPTO_SECRETKEYBYTES);
  if (RLCEsk==NULL) return -1;
  //Lines commented out as parameters should come from the function body
  //unsigned char message[RLCEsk->para[6]];
  //unsigned long long mlen=RLCEsk->para[6];
  ret=RLCE_decrypt((unsigned char *)cipherText,CRYPTO_CIPHERTEXTBYTES,RLCEsk,message,&mlen);
  if (ret<0) return ret;
  memcpy(ss, message, CRYPTO_BYTES);
  return ret;
	}


