
/*Generates a keypair - pk is the public key and sk is the secret key. */

 int crypto_sign_keypair(
 unsigned char *pk,
 unsigned char *sk
 )

 /*Sign a message: sm is the signed message, m is the original message,
 and sk is the secret key. */

  int crypto_sign(
  unsigned char *sm, unsigned long long *smlen,
  const unsigned char *m, unsigned long long mlen,
  const unsigned char *sk
 )

/* Verify a message signature: m is the original message, sm is the signed
message, pk is the public key. */

 int crypto_sign_open(
 unsigned char *m, unsigned long long *mlen,
 const unsigned char *sm, unsigned long long smlen,
 const unsigned char *pk
 )