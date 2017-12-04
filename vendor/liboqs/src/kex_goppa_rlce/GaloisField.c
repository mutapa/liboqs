/* GaloisField.c
 * Yongge Wang 
 *
 * Code was written: November 1, 2016-December 1, 2016
 *
 * galois.c implements the field arithmetics 
 * for RLCE scheme that is part of the package 
 * RLCE.tar - Random Linear Code Encryption Scheme
 *
 * Copright (C) 2016 Yongge Wang
 * 
 * Yongge Wang
 * Department of Software and Information Systems
 * UNC Charlotte
 * Charlotte, NC 28223
 * yonwang@uncc.edu
 *
 Primitive polynomials are used for Galois field
 For GF(2^m), we use a primitive polynomial of degree m
 List of primitive polynomials from the  paper: 
        Stahnke, Wayne. "Primitive binary polynomials." 
        Math. of Comput. 27.124 (1973): 977-980.
 A tuple (9,4,0) represents the polynomial g(x)=x^9+x^4+1
 We can also denote a polynomial using it coefficients.
 e.g., (9, 4, 0) is written as  0000 0010 0001 0001 

 (8, 6, 5, 1, 0)     or  0000 0001 0110 0011 or 0x0163 or 0435
 (9, 4, 0)           or  0000 0010 0001 0001 or 0x0211 or 01021
 (10, 3, 0)          or  0000 0100 0000 1001 or 0x0409 or 02011
 (11, 2, 0)          or  0000 1000 0000 0101 or 0x0805 or 04005
 (12, 7, 4, 3, 0)    or  0001 0000 1001 1001 or 0x1099 or 010123
 (13, 4, 3, 1, 0)    or  0010 0000 0001 1011 or 0x2129 or 020033
 (14, 12, 11, 1, 0)  or  0101 1000 0000 0011 or 0x5803 or 042103
 (15, 1, 0)          or  1000 0000 0000 0011 or 0x8003 or 0100003
 (16, 5, 3, 2, 0)    or 10000 0000 0010 1101 or 0x002D or 0210013
 for GF(2^16), the primitive polynomial should be 0x1002D
 but we will ignore the most important bit
 This implementation only includes GF(2^8), .., GF(2^16)
 for GF(2^8) we may use uint8_t as the data type
 */

#include "rlce.h"
static int poly[17] = {0,0,0,0,0,0,0,0,0x0163,0x0211,0x0409,0x0805,0x1099,0x2129,0x5803,0x8003,0x002D};  
static int fieldSize[17]={0,0,0,0,0,0,0,0,(1u<<8), (1u<<9),(1u<<10),(1u<<11),(1u<<12),(1u<<13),(1u<<14),(1u<<15),(1u<<16)};
static int fieldOrder[17]={0,0,0,0,0,0,0,0,(1u<<8)-1,(1u<<9)-1,(1u<<10)-1,(1u<<11)-1,(1u<<12)-1,(1u<<13)-1,(1u<<14)-1,(1u<<15)-1,(1u<<16)-1};

static short *GFlogTable[17]={NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL};
static short *GFexpTable[17]={NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL};

int GF_init_logexp_table(int m) {
  field_t j,fE=1;
  if (GFlogTable[m] != NULL) return 0;
  GFlogTable[m] = (short *) calloc(fieldSize[m], sizeof(short)); 
  if (GFlogTable[m] == NULL) return GFTABLEERR; 
  GFexpTable[m] = (short *)calloc(fieldSize[m], sizeof(short)); 
  if (GFexpTable[m] == NULL) { 
    free(GFlogTable[m]);
    GFlogTable[m] = NULL;
    return GFTABLEERR ;
  } 
  for (j=0;j<fieldSize[m];j++) GFlogTable[m][j]=fieldOrder[m];
  GFexpTable[m][0] = 1;
  GFexpTable[m][fieldOrder[m]] = 1;
  for (j = 0; j < fieldOrder[m]; j++) {
    GFlogTable[m][fE] = j; 
    GFexpTable[m][j] = fE;
    fE = fE << 1; 
    if (fE & fieldSize[m]) fE = (fE ^ poly[m]) & (fieldOrder[m]);
  }
  return 0;
}

field_t GF_add(field_t x, field_t y) {return x^y;}

int GF_addvec(field_t vec1[], field_t vec2[],field_t vec3[], int vecSize){
  int i, longsize;
  longsize = sizeof(unsigned long long);
  if (vec3==NULL) vec3=vec2;
  unsigned int size=(sizeof(field_t)*vecSize)/longsize;
  unsigned long long* longvec1=(unsigned long long*) vec1;
  unsigned long long* longvec2=(unsigned long long*) vec2;
  unsigned long long* longvec3=(unsigned long long*) vec3;
  for (i=0; i<size; i++) longvec3[i]= longvec2[i] ^ longvec1[i];
  for (i=(longsize*size)/sizeof(field_t); i<vecSize; i++) vec3[i] =vec2[i]^vec1[i];
  return 0;
}
 
field_t GF_mul(field_t x, field_t y, int m) {
  int result;
  GF_init_logexp_table(m);
  if (x == field_zero() || y == field_zero()) return 0;
  result = (GFlogTable[m][x] + GFlogTable[m][y])%fieldOrder[m];
  return GFexpTable[m][result];
}

field_t GF_div(field_t x, field_t y, int m) {
  int result;
  GF_init_logexp_table(m);
  if (y == field_zero()) return -1;
  if (x == field_zero()) return field_zero(); 
  result = (GFlogTable[m][x]+fieldOrder[m]-GFlogTable[m][y])%(fieldOrder[m]);
  return GFexpTable[m][result];
}

field_t GF_exp(int x, int m){
  GF_init_logexp_table(m);
  return GFexpTable[m][x];
}

int GF_log(field_t x, int m){
  GF_init_logexp_table(m);
  return GFlogTable[m][x];
}


