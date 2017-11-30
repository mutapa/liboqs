/* rlce.c
 *
 * Code was written: November 19, 2016-February 8, 2017
 *
 * rlce.c implements crypto oprations 
 * for RLCE scheme that is part of the package 
 * RLCE.tar - Random Linear Code Encryption Scheme
 *
 * Copyright (C) 2016-2017 Yongge Wang
 * 
 * Yongge Wang
 * Department of Software and Information Systems
 * UNC Charlotte
 * Charlotte, NC 28223
 * yonwang@uncc.edu
 *
 */

#include "rlce.h"
int RLCEspad(unsigned char bytes[],unsigned int BLen,
	     unsigned char padded[], unsigned int paddedLen,
	     RLCE_public_key_t pk,
	     unsigned char randomness[], unsigned int randLen,
	     unsigned char e0[], unsigned int e0Len);
int RLCEspadDecode(unsigned char encoded[],unsigned int encodedLen,
		   unsigned char message[], unsigned long long *mlen,
		   RLCE_private_key_t sk,
		   unsigned char e0[], unsigned int e0Len);

int RLCEpad(unsigned char bytes[],unsigned int bytesLen,
	    unsigned char padded[], unsigned int paddedLen,
	    RLCE_public_key_t pk,
	    unsigned char randomness[], unsigned int randLen,
	    unsigned char e0[], unsigned int e0Len);
int RLCEpadDecode(unsigned char encoded[],unsigned int encodedLen,
		  unsigned char message[], unsigned long long *mlen,
		  RLCE_private_key_t sk,
		  unsigned char e0[], unsigned int e0Len);
int rangeadd(unsigned char bytes1[], unsigned char bytes2[], int bytesize);
poly_t genPolyTable(int deg);

int getRLCEparameters(unsigned int para[], unsigned int scheme, unsigned int padding) {
  para[9]=padding;  /* 0 for RLCEspad-mediumEncoding
                        1 for RLCEpad-mediumEncoding
                        2 for RLCEspad-basicEncoding
                        3 for RLCEpad-basicEncoding
                        4 for RLCEspad-advancedEncoding
                        5 for RLCEpad-advancedEncoding*/
  para[10]=scheme;   /* scheme ID */
  switch (scheme) {
  case 0:
    para[0]=630; /* n */
    para[1]=470; /* k */
    para[2]=160; /* w */
    para[3]=10;  /* GFsize */
    para[4]=2;   /* hash type */
    para[11]=80;   /* t */
    para[12]=0;   /* omega for list-decoding */
    para[13]=0;   /* L_omega: for list-decoding only */
    para[14]=128; /* kappa-128 */
    para[15]=200; /* u: used for un-recovered msg symbols by RS */
    para[16]=988; /* cipher len in bytes*/
    if (DECODINGMETHOD!=2) {
      para[17]=310116; /* sk bytes for decodingalgorithm 0,1*/
    } else para[17]=192029; /* sk bytes for decoding algorithm 2*/
    para[18]=188001; /* pk bytes */
    para[19]=32; /* random input bytes*/
    switch (padding) {
    case 0: /* 0:RLCEspad */
      para[5]=5500; /*mLen for mediumEncoding */
      para[6]=171;  /* k1 for mediumEncoding */
      para[7]=171;  /* k2 for mediumEncoding */
      para[8]=346; /* k3 for mediumEncoding */
      break;
    case 1: /* 1:RLCEpad  */
      para[5]=5500; /*mLen for mediumEncoding */
      para[6]=624;  /* k1 for mediumEncoding */
      para[7]=32;  /* k2 for mediumEncoding */
      para[8]=32; /* k3 for mediumEncoding */
      break;
    case 2:
      para[5]=4700; /*mLen bEncoding */
      para[6]=146; /* k1 for basicEncoding */
      para[7]=146; /* k2 for basidEncoding */
      para[8]=296;/* k3 for basicEncoding */
      break;
    case 3:
      para[5]=4700; /*mLen bEncoding */
      para[6]=524; /* k1 for basicEncoding */
      para[7]=32; /* k2 for basidEncoding */
      para[8]=32;/* k3 for basicEncoding */
      break;
    case 4:
      para[5]=5869; /*mLen for advancedEncoding */
      para[6]=183; /* k1 for advancedEncoding */
      para[7]=183; /* k2 for advancedEncoding */
      para[8]=368; /* k3 for advancedEncoding */
      break;
    case 5:
      para[5]=5869; /*mLen for advancedEncoding */      
      para[6]=670; /* k1 for advancedEncoding */
      para[7]=32; /* k2 for advancedEncoding */
      para[8]=32;/* k3 for advancedEncoding */
      break;
    default:
      return RLCEPADDINGNOTDEFINED;
    }          
    break;    
  case 1:
    para[0]=532; /* n */
    para[1]=376; /* k */
    para[2]=96; /* w */
    para[3]=10;  /* GFsize */
    para[4]=2;   /* hash type */
    para[11]=78;   /* t */
    para[12]=0;   /* omega for list-decoding */
    para[13]=0;   /* L_omega: for list-decoding only */
    para[14]=128; /* kappa-128 */
    para[15]=123; /* u: used for un-recovered msg symbols by RS */
    para[16]=785; /* cipher len in bytes*/
    if (DECODINGMETHOD!=2) {
      para[17]=179946; /* sk bytes for decodingalgorithm 0,1*/
    } else para[17]=121666; /* sk bytes for decoding algorithm 2*/
    para[18]=118441; /* pk bytes */
    para[19]=32; /* random input bytes*/
    switch (padding) {
    case 0: /* 0:RLCEspad */
      para[5]=4540; /*mLen for mediumEncoding */
      para[6]=141;  /* k1 for mediumEncoding */
      para[7]=141;  /* k2 for mediumEncoding */
      para[8]=286; /* k3 for mediumEncoding */
      break;
    case 1: /* 1:RLCEpad  */
      para[5]=4540; /*mLen for mediumEncoding */
      para[6]=504;  /* k1 for mediumEncoding */
      para[7]=32;  /* k2 for mediumEncoding */
      para[8]=32; /* k3 for mediumEncoding */
      break;
    case 2:
      para[5]=3760; /*mLen bEncoding */
      para[6]=117; /* k1 for basicEncoding */
      para[7]=117; /* k2 for basidEncoding */
      para[8]=236;/* k3 for basicEncoding */
      break;
    case 3:
      para[5]=3760; /*mLen bEncoding */
      para[6]=406; /* k1 for basicEncoding */
      para[7]=32; /* k2 for basidEncoding */
      para[8]=32;/* k3 for basicEncoding */
      break;
    case 4:
      para[5]=4875; /*mLen for advancedEncoding */
      para[6]=152; /* k1 for advancedEncoding */
      para[7]=152; /* k2 for advancedEncoding */
      para[8]=306; /* k3 for advancedEncoding */
      break;
    case 5:
      para[5]=4875; /*mLen for advancedEncoding */      
      para[6]=546; /* k1 for advancedEncoding */
      para[7]=32; /* k2 for advancedEncoding */
      para[8]=32;/* k3 for advancedEncoding */
      break;
    default:
      return RLCEPADDINGNOTDEFINED;
    }             
    break;
  case 2:
    para[0]=1000; /* n */
    para[1]=764; /* k */
    para[2]=236; /* w */
    para[3]=10;  /* GFsize */
    para[4]=2;   /* hash type */
    para[11]=118;   /* t */
    para[12]=0;   /* omega for list-decoding */
    para[13]=0;   /* L_omega: for list-decoding only */
    para[14]=192; /* kappa-192 */
    para[15]=303; /* u: used for un-recovered msg symbols by RS */
    para[16]=1545; /* cipher len in bytes*/
    if (DECODINGMETHOD!=2) {
      para[17]=747393; /* sk bytes for decodingalgorithm 0,1*/
    } else para[17]=457073; /* sk bytes for decoding algorithm 2*/
    para[18]=450761; /* pk bytes */
    para[19]=40; /* random input bytes*/
    switch (padding) {
    case 0: /* 0:RLCEspad */
      para[5]=8820; /*mLen for mediumEncoding */
      para[6]=275;  /* k1 for mediumEncoding */
      para[7]=275;  /* k2 for mediumEncoding */
      para[8]=553; /* k3 for mediumEncoding */
      break;
    case 1: /* 1:RLCEpad  */
      para[5]=8820; /*mLen for mediumEncoding */
      para[6]=1007;  /* k1 for mediumEncoding */
      para[7]=48;  /* k2 for mediumEncoding */
      para[8]=48; /* k3 for mediumEncoding */
      break;
    case 2:
      para[5]=7640; /*mLen bEncoding */
      para[6]=238; /* k1 for basicEncoding */
      para[7]=238; /* k2 for basidEncoding */
      para[8]=479;/* k3 for basicEncoding */
      break;
    case 3:
      para[5]=7640; /*mLen bEncoding */
      para[6]=859; /* k1 for basicEncoding */
      para[7]=48; /* k2 for basidEncoding */
      para[8]=48;/* k3 for basicEncoding */
      break;
    case 4:
      para[5]=9377; /*mLen for advancedEncoding */
      para[6]=293; /* k1 for advancedEncoding */
      para[7]=293; /* k2 for advancedEncoding */
      para[8]=587; /* k3 for advancedEncoding */
      break;
    case 5:
      para[5]=9377; /*mLen for advancedEncoding */      
      para[6]=1077; /* k1 for advancedEncoding */
      para[7]=48; /* k2 for advancedEncoding */
      para[8]=48;/* k3 for advancedEncoding */
      break;
    default:
      return RLCEPADDINGNOTDEFINED;
    }     
    break;
  case 3:
    para[0]=846; /* n */
    para[1]=618; /* k */
    para[2]=144; /* w */
    para[3]=10;  /* GFsize */
    para[4]=2;   /* hash type */
    para[11]=114;   /* t */
    para[12]=0;   /* omega for list-decoding */
    para[13]=0;   /* L_omega: for list-decoding only */
    para[14]=192; /* kappa-192 */
    para[15]=190; /* u: used for un-recovered msg symbols by RS */
    para[16]=1238; /* cipher len in bytes*/
    if (DECODINGMETHOD!=2) {
      para[17]=440008; /* sk bytes for decodingalgorithm 0,1*/
    } else para[17]=292461; /* sk bytes for decoding algorithm 2*/
    para[18]=287371; /* pk bytes */
    para[19]=40; /* random input bytes*/
    switch (padding) {
    case 0: /* 0:RLCEspad */
      para[5]=7320; /*mLen for mediumEncoding */
      para[6]=228;  /* k1 for mediumEncoding */
      para[7]=228;  /* k2 for mediumEncoding */
      para[8]=459; /* k3 for mediumEncoding */
      break;
    case 1: /* 1:RLCEpad  */
      para[5]=7320; /*mLen for mediumEncoding */
      para[6]=819;  /* k1 for mediumEncoding */
      para[7]=48;  /* k2 for mediumEncoding */
      para[8]=48; /* k3 for mediumEncoding */
      break;
    case 2:
      para[5]=6180; /*mLen bEncoding */
      para[6]=193; /* k1 for basicEncoding */
      para[7]=193; /* k2 for basidEncoding */
      para[8]=387;/* k3 for basicEncoding */
      break;
    case 3:
      para[5]=6180; /*mLen bEncoding */
      para[6]=677; /* k1 for basicEncoding */
      para[7]=48; /* k2 for basidEncoding */
      para[8]=48;/* k3 for basicEncoding */
      break;
    case 4:
      para[5]=7825; /*mLen for advancedEncoding */
      para[6]=244; /* k1 for advancedEncoding */
      para[7]=244; /* k2 for advancedEncoding */
      para[8]=491; /* k3 for advancedEncoding */
      break;
    case 5:
      para[5]=7825; /*mLen for advancedEncoding */      
      para[6]=883; /* k1 for advancedEncoding */
      para[7]=48; /* k2 for advancedEncoding */
      para[8]=48;/* k3 for advancedEncoding */
      break;
    default:
      return RLCEPADDINGNOTDEFINED;
    }       
    break;
  case 4:
    para[0]=1360; /* n */
    para[1]=800;  /* k */
    para[2]=560;  /* w */
    para[3]=11;   /* GF size */
    para[4]=2;    /* hash type */
    para[11]=280;   /* t */
    para[12]=0;   /* omega for list-decoding */
    para[13]=0;   /* L_omega: for list-decoding only */
    para[14]=256; /* kappa-256 */
    para[15]=482; /* u: used for un-recovered msg symbols by RS */
    para[16]=2640; /* cipher len in bytes*/
    if (DECODINGMETHOD!=2) {
      para[17]=1773271; /* sk bytes for decodingalgorithm 0,1*/
    } else para[17]=1241971; /* sk bytes for decoding algorithm 2*/
    para[18]=1232001; /* pk bytes */
    para[19]=48; /* random input bytes*/
    switch (padding) {
    case 0: /* 0:RLCEspad */
      para[5]=11880; /*mLen for mediumEncoding */
      para[6]=371;  /* k1 for mediumEncoding */
      para[7]=371;  /* k2 for mediumEncoding */
      para[8]=743; /* k3 for mediumEncoding */
      break;
    case 1: /* 1:RLCEpad  */
      para[5]=11880; /*mLen for mediumEncoding */
      para[6]=1365;  /* k1 for mediumEncoding */
      para[7]=60;  /* k2 for mediumEncoding */
      para[8]=60; /* k3 for mediumEncoding */
      break;
    case 2:
      para[5]=8800; /*mLen bEncoding */
      para[6]=275; /* k1 for basicEncoding */
      para[7]=275; /* k2 for basidEncoding */
      para[8]=550;/* k3 for basicEncoding */
      break;
    case 3:
      para[5]=8800; /*mLen bEncoding */
      para[6]=980; /* k1 for basicEncoding */
      para[7]=60; /* k2 for basidEncoding */
      para[8]=60;/* k3 for basicEncoding */
      break;
    case 4:
      para[5]=13025; /*mLen for advancedEncoding */
      para[6]=407; /* k1 for advancedEncoding */
      para[7]=407; /* k2 for advancedEncoding */
      para[8]=815; /* k3 for advancedEncoding */
      break;
    case 5:
      para[5]=13205; /*mLen for advancedEncoding */      
      para[6]=1509; /* k1 for advancedEncoding */
      para[7]=60; /* k2 for advancedEncoding */
      para[8]=60;/* k3 for advancedEncoding */
      break;
    default:
      return RLCEPADDINGNOTDEFINED;
    }    
    break;
  case 5:
    para[0]=1160; /* n */
    para[1]=700; /* k */
    para[2]=311; /* w */
    para[3]=11;  /* GFsize */
    para[4]=2;   /* hash type */
    para[11]=230;   /* t */
    para[12]=0;   /* omega for list-decoding */
    para[13]=0;   /* L_omega: for list-decoding only */
    para[14]=256; /* kappa-256 */
    para[15]=309; /* u: used for un-recovered msg symbols by RS */
    para[16]=2023; /* cipher len in bytes*/
    if (DECODINGMETHOD!=2) {
      para[17]=1048176; /* sk bytes for decodingalgorithm 0,1*/
    } else para[17]=749801; /* sk bytes for decoding algorithm 2*/
    para[18]=742089; /* pk bytes */
    para[19]=48; /* random input bytes*/
    switch (padding) {
    case 0: /* 0:RLCEspad */
      para[5]=10230; /*mLen for mediumEncoding */
      para[6]=319;  /* k1 for mediumEncoding */
      para[7]=319;  /* k2 for mediumEncoding */
      para[8]=641; /* k3 for mediumEncoding */
      break;
    case 1: /* 1:RLCEpad  */
      para[5]=10230; /*mLen for mediumEncoding */
      para[6]=1159;  /* k1 for mediumEncoding */
      para[7]=60;  /* k2 for mediumEncoding */
      para[8]=60; /* k3 for mediumEncoding */
      break;
    case 2:
      para[5]=7700; /*mLen bEncoding */
      para[6]=240; /* k1 for basicEncoding */
      para[7]=240; /* k2 for basidEncoding */
      para[8]=483;/* k3 for basicEncoding */
      break;
    case 3:
      para[5]=7700; /*mLen bEncoding */
      para[6]=843; /* k1 for basicEncoding */
      para[7]=60; /* k2 for basidEncoding */
      para[8]=60;/* k3 for basicEncoding */
      break;
    case 4:
      para[5]=11145; /*mLen for advancedEncoding */
      para[6]=348; /* k1 for advancedEncoding */
      para[7]=348; /* k2 for advancedEncoding */
      para[8]=698; /* k3 for advancedEncoding */
      break;
    case 5:
      para[5]=11145; /*mLen for advancedEncoding */      
      para[6]=1274; /* k1 for advancedEncoding */
      para[7]=60; /* k2 for advancedEncoding */
      para[8]=60;/* k3 for advancedEncoding */
      break;
    default:
      return RLCEPADDINGNOTDEFINED;
    }  
    break;
  default:
    return RLCEIDPARANOTDEFINED;
  }
  return 0;
}



RLCE_private_key_t RLCE_private_key_init (unsigned int para[]) {
  RLCE_private_key_t key;
  key= (RLCE_private_key_t) malloc(sizeof (struct RLCE_private_key));
  key->para = malloc(PARASIZE * sizeof(unsigned int));
  int i;
  for (i=0; i<PARASIZE; i++) (key->para[i])=para[i];
  key->perm1 =vec_init(para[0]);
  key->perm2 =vec_init(para[0]+para[2]); /* n+w */
  key->A =matrixA_init(para[2]);
  if (DECODINGMETHOD!=2) key->S = matrix_init(para[1], para[15]+1);
  key->grs = vec_init(para[0]);
  key->G = matrix_init(para[1], para[0]+para[2]-para[1]); /* k\times (n+w)-k */
  return key;
}



void RLCE_free_sk(RLCE_private_key_t sk) {
  free(sk->para);
  if (DECODINGMETHOD!=2) matrix_free(sk->S);
  vector_free(sk->perm1);
  vector_free(sk->perm2);
  matrixA_free(sk->A);
  vector_free(sk->grs);
  if (sk->G !=NULL) matrix_free(sk->G);
  free(sk);
  sk=NULL;
}

RLCE_public_key_t RLCE_public_key_init (unsigned int para[]) {
  RLCE_public_key_t pk;
  int i;
  pk= (RLCE_public_key_t) malloc(sizeof (struct RLCE_public_key));
  pk->para = malloc(PARASIZE * sizeof(unsigned int));
  for (i=0; i<PARASIZE; i++) (pk->para[i])=para[i];
  pk->G = matrix_init(para[1], para[0]+para[2]-para[1]); /* k\times (n+w)-k */
  return pk;
}

void RLCE_free_pk(RLCE_public_key_t pk) {
  free(pk->para);
  if (pk->G != NULL) matrix_free(pk->G);
  free(pk);
  pk=NULL;
}



int pk2B (RLCE_public_key_t pk, unsigned char pkB[], unsigned int *blen) {
  int i, ret;
  if (blen[0]<pk->para[18]) return KEYBYTE2SMALL;
  pkB[0]= (pk->para[10])|(pk->para[9]<<4);
  unsigned int nplusw=pk->para[0]+pk->para[2];
  unsigned int k=pk->para[1];
  unsigned int pkLen=k*(nplusw-k);
  vector_t FE=vec_init(pkLen);
  for (i=0;i<k;i++) memcpy(&(FE->data[i*(nplusw-k)]),(pk->G)->data[i],(nplusw-k)*sizeof(field_t));
  blen[0] = (pkLen*(pk->para[3]))/8;
  if ((pkLen*(pk->para[3]))%8 > 0) blen[0]++;
  if ((pk->para[3])==10) ret=FE2B10(FE, &pkB[1], blen[0]);
  if ((pk->para[3])==11) ret=FE2B11(FE, &pkB[1], blen[0]);
  if (ret<0) return ret;
  vector_free(FE);
  blen[0]++;
  return 0;
}

int sk2B (RLCE_private_key_t sk, unsigned char skB[], unsigned int *blen) {
  unsigned int sklen =sk->para[17];
  if (blen[0]<sklen) return KEYBYTE2SMALL;
  int i,j,ret;
  int n=sk->para[0];
  int k=sk->para[1];
  int w=sk->para[2];
  skB[0]= (sk->para[10])|(sk->para[9]<<4);
  j=1;
  for (i=0;i<n;i++) {
    skB[j]=(((sk->perm1)->data[i])>>8);
    skB[j+1]=(sk->perm1)->data[i];
    j=j+2;
  }
  j=1+2*n;
  for (i=0;i<n+w;i++) {
    skB[j]=(((sk->perm2)->data[i])>>8);
    skB[j+1]=(sk->perm2)->data[i];
    j=j+2;
  }
  j=0;
  unsigned int invSLen=0;
  if (DECODINGMETHOD!=2) invSLen= ((sk->S)->numR) *  ((sk->S)->numC);
  unsigned int totalFELen=2*w+invSLen+n+k*(n+w-k);
  vector_t FE=vec_init(totalFELen);
  for (i=0; i<w; i++) {
    FE->data[j]=((sk->A)->A[i])->data[0][0];
    FE->data[j+1]=((sk->A)->A[i])->data[1][0];
    j=j+2;
  }
  if (invSLen>0) {
    for (i=0;i<(sk->S)->numR; i++) {
      memcpy(&(FE->data[j]),(sk->S)->data[i],((sk->S)->numC)*sizeof(field_t));
      j=j+(sk->S)->numC;
    }
  }
  memcpy(&(FE->data[j]),(sk->grs)->data,n*sizeof(field_t));
  j=j+n;
  for (i=0;i<sk->para[1]; i++) {
    memcpy(&(FE->data[j]),(sk->G)->data[i],(n+w-k)*sizeof(field_t));
    j=j+n+w-k;  
  }
  int byteLen = totalFELen*(sk->para[3])/8;
  if ((totalFELen*(sk->para[3]))%8 > 0) byteLen++;
  if (sklen != (4*n+2*w+1+byteLen)) return SKWRONG;
  if ((sk->para[3])==10) ret=FE2B10(FE, &skB[4*n+2*w+1], byteLen);
  if ((sk->para[3])==11) ret=FE2B11(FE, &skB[4*n+2*w+1], byteLen);
  if (ret<0) return ret;    
  vector_free(FE);
  return 0;
}

RLCE_public_key_t B2pk(const unsigned char binByte[], unsigned long long blen) {
  int i,ret=0;
  unsigned int scheme=binByte[0] & 0x0F;
  unsigned int padding=binByte[0]>>4;
  unsigned int para[PARASIZE];
  ret=getRLCEparameters(para, scheme,padding);
  if (ret<0) return NULL;
  RLCE_public_key_t pk = RLCE_public_key_init(para);
  unsigned int nplusw=pk->para[0]+pk->para[2];
  unsigned int k=pk->para[1];
  unsigned int pkLen=k*(nplusw-k);
  vector_t FE=vec_init(pkLen);
  int byteLen = (pkLen*(pk->para[3]))/8;
  if ((pkLen*(pk->para[3]))%8 > 0) byteLen++;
  if (byteLen>blen-1) return NULL;
  if ((pk->para[3])==10) ret=B2FE10((unsigned char*)&(binByte[1]), byteLen,FE);
  if ((pk->para[3])==11) ret=B2FE11((unsigned char*)&(binByte[1]), byteLen,FE);
  if (ret<0) return NULL;
  for (i=0;i<k;i++) memcpy((pk->G)->data[i], &(FE->data[i*(nplusw-k)]),(nplusw-k)*sizeof(field_t));
  vector_free(FE);
  return pk;
}

RLCE_private_key_t B2sk(const unsigned char binByte[], unsigned long long blen) {
  unsigned int scheme=binByte[0] & 0x0F;
  unsigned int padding=binByte[0]>>4;
  unsigned int para[PARASIZE];  
  getRLCEparameters(para, scheme,padding);
  RLCE_private_key_t sk = RLCE_private_key_init (para);
  int sklen =sk->para[17];
  if (blen<sklen) {
    RLCE_free_sk(sk);
    return NULL;
  }
  int i,j,ret;
  int n=sk->para[0];
  int k=sk->para[1];
  int w=sk->para[2];
  int SnumR=0, SnumC=0;
  if (DECODINGMETHOD!=2) {
    SnumR=k;
    SnumC=sk->para[15]+1;
  }  
  unsigned int invSLen=0;
  if (DECODINGMETHOD!=2) invSLen= SnumR * SnumC;
  unsigned int totalFELen=2*w+invSLen+n+k*(n+w-k);
  vector_t FE=vec_init(totalFELen);
  int permByteLen=4*n+2*w;
  j=1;  
  for (i=0;i<sk->para[0];i++) {
    (sk->perm1)->data[i]=binByte[j];
    (sk->perm1)->data[i]=((sk->perm1)->data[i]<<8);
    (sk->perm1)->data[i]= (binByte[j+1] | (sk->perm1)->data[i]);
    j=j+2;
  }
  j=2*n+1;
  for (i=0;i<n+w;i++) {
    (sk->perm2)->data[i]=binByte[j];
    (sk->perm2)->data[i]=((sk->perm2)->data[i]<<8);
    (sk->perm2)->data[i]=((sk->perm2)->data[i]|binByte[j+1]);
    j=j+2;
  }
  (sk->perm1)->size=n;
  (sk->perm2)->size=n+w;
  
  int byteLen = totalFELen*(sk->para[3])/8;
  if ((totalFELen*(sk->para[3]))%8 > 0) byteLen++;
  if (byteLen>blen-permByteLen-1) return NULL;  
  if ((sk->para[3])==10) ret=B2FE10((unsigned char*)&(binByte[permByteLen+1]), byteLen,FE);
  if ((sk->para[3])==11) ret=B2FE11((unsigned char*)&(binByte[permByteLen+1]), byteLen,FE);
  if (ret<0) return NULL;
  j=0;
  for (i=0; i<w; i++) {
    ((sk->A)->A[i])->data[0][0]=FE->data[j];
    ((sk->A)->A[i])->data[1][0]=FE->data[j+1];
    j=j+2;
  }
  j=2*w;
  if (invSLen>0) {
    for (i=0;i<SnumR; i++) {
      memcpy((sk->S)->data[i],&(FE->data[j]),SnumC*sizeof(field_t));
      j=j+SnumC;
    }
  }
  j=2*w+invSLen;
  memcpy((sk->grs)->data,&(FE->data[j]),n*sizeof(field_t));
  j=2*w+invSLen+n;
  for (i=0;i<k;i++) {
    memcpy((sk->G)->data[i],&(FE->data[j]),(n+w-k)*sizeof(field_t));
    j=j+n+w-k;  
  }  
  vector_free(FE);
  return sk;
}

int RLCE_key_setup (unsigned char entropy[], int entropylen,
		    unsigned char nonce[], int noncelen,
		    RLCE_public_key_t pk, RLCE_private_key_t sk) {
  return 0;
}

int RLCE_encrypt(unsigned char msg[], unsigned long long msgLen,
                 unsigned char entropy[], unsigned int entropylen,
		 unsigned char nonce[], unsigned int noncelen,
                 RLCE_public_key_t pk, unsigned char cipher[], unsigned long long *clen){
  memcpy(cipher, msg, msgLen*sizeof(unsigned char));
  return 0;  
}

int RLCE_decrypt(unsigned char cipher[], unsigned long long clen, RLCE_private_key_t sk, unsigned char msg[],
		 unsigned long long *mlen){
  memcpy(msg, cipher, *mlen*sizeof(unsigned char));
  return 0;  
}

