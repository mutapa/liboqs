/* fieldMatrix.c
 * Yongge Wang 
 *
 * Code was written: November 10, 2016-
 *
 * fieldMatrix.c implements matrix arithmetics 
 * for RLCE scheme that is part of the package 
 * RLCE.tar - Random Linear Code Encryption Scheme
 *
 * Copyright (C) 2016 Yongge Wang
 * 
 * Yongge Wang
 * Department of Software and Information Systems
 * UNC Charlotte
 * Charlotte, NC 28223
 * yonwang@uncc.edu
 *
 */


#include "rlce.h"

matrix_t matrix_init(int row, int column) {
  /* this will allocate memory spaces for a matrix of "row" rows and "column" columns */
  matrix_t mat;
  int i;
  mat = (matrix_t) malloc(sizeof (struct matrix));
  mat->numR = row;
  mat->numC = column;
  mat->data = calloc(row, sizeof(int*));
  for (i=0; i<row; i++) {
    mat->data[i]= (field_t *) calloc(column, sizeof(field_t));
  }
  return mat;
}

void matrix_free(matrix_t A){
  /* release the memory spaces used by the matrix A*/
  int i;
  for (i=0; i<A->numR; i++) free(A->data[i]);
  free(A->data);
  free(A);
  return;
}

int vector_copy(vector_t v, vector_t dest) {
  /* a vector structure contains the size and data. This process copy 
     the vector v to vector dest */
  dest->size = v->size;
  memcpy(dest->data, v->data, (v->size) * sizeof (field_t));
  return 0;
}


matrixA_t matrixA_init(int size) {
  matrixA_t matA;
  matA = (matrixA_t) malloc(sizeof (struct matrixA));
  matA->size = size;
  matA->A = malloc(size * sizeof(int*));
  int i;
  for (i=0; i<size; i++) matA->A[i]= matrix_init(2, 2);
  return matA;
}

void matrixA_free(matrixA_t A){
  int i;
  for (i=0; i<A->size; i++) {
    matrix_free(A->A[i]);
    A->A[i]=NULL;
  }
  free(A->A);
  A->A=NULL;
  free(A);
  A=NULL;
  return;
}


vector_t vec_init(int n) {
  vector_t v;
  v = (vector_t) malloc(sizeof (struct vector));
  v->size = n;
  v->data = (field_t *) calloc(n, sizeof (field_t));
  return v;
}

void vector_free(vector_t v) {
  free(v->data);
  v->data=NULL;
  free(v);
  v=NULL;
}

vector_t permu_inv(vector_t p) {
  int i;
  vector_t result;
  result = vec_init(p->size);
  for (i=0; i<p->size; i++) {
    result->data[p->data[i]]=i;
  }
  return result;
}


int randomBytes2FE(unsigned char randomBytes[], int nRB,
		   field_t output[], int outputSize, int m) {
  vector_t Vec;
  Vec =vec_init(outputSize);
  int ret = 0;
  switch (m) {
  case 10:
    ret=B2FE10(randomBytes,nRB, Vec);
    if (ret<0) return ret;
    break;
  case 11:
    ret=B2FE11(randomBytes,nRB, Vec);
    if (ret<0) return ret;
    break;
  default:
    return B2FEORFE2BNOTDEFINED;
  }
  memcpy(output, Vec->data, outputSize *sizeof(field_t));
  vector_free(Vec);
  return 0; 	 
}

int getShortIntegers(unsigned char randB[], int nRB,unsigned short output[], int outputSize) {
  int i;
  for (i=0; i<outputSize; i++) {
    output[i]=randB[2*i];
    output[i]= (output[i]<<8);
    output[i]= output[i] | randB[2*i+1];
  }
  return 0; 	 
}


void I2BS (unsigned int X, unsigned char S[], int slen) {
  int i;
  for (i=slen-1; i>=0; i--) S[i]=(0xFF & (X>>((slen-1-i)*8)));
}

int BS2I (unsigned char S[], int slen) {
  unsigned int i, X=0;
  for (i=0; i<slen; i++) X=(X<<8)^S[i];
  return X;
}


int B2FE10 (unsigned char bytes[], unsigned int BLen, vector_t FE) {
  int vecLen =FE->size;  
  if (10*vecLen>8*BLen) {
    return BYTEVECTORTOOSMALL;
  }
  int j=0;
  int i;
  int used = 0;

  unsigned char bits = 0x00;
  for (i=0; i<vecLen; i++) {

    switch (used) {
    case 0:
      FE->data[i]=bytes[j];
      FE->data[i]=FE->data[i]<<2;
      j++;
      bits = (bytes[j] & 0xC0);
      bits = bits >>6;
      FE->data[i]=(FE->data[i]) | bits;
      used = 2;
      break;
    case 2:
      FE->data[i]= (bytes[j]<< 2) & 0x00FF;
      FE->data[i]=FE->data[i]<<2;
      j++;
      bits = (bytes[j] & 0xF0);
      bits = bits >>4;
      FE->data[i]=(FE->data[i]) | bits;
      used = 4;
      break;
    case 4:
      FE->data[i]= (bytes[j]<< 4) & 0x00FF;
      FE->data[i]=FE->data[i]<<2;
      j++;
      bits = (bytes[j] & 0xFC);
      bits = bits >>2;
      FE->data[i]=(FE->data[i]) | bits;
      used = 6;
      break;
    case 6:
      FE->data[i]= (bytes[j]<< 6) & 0x00FF;
      FE->data[i]=FE->data[i]<<2;
      j++;
      bits = (bytes[j] & 0xFF);
      FE->data[i]=(FE->data[i]) | bits;
      j++;
      used = 0;
      break;
    default:
      return -1;
    }
  }
  return 0;
}

int FE2B10 (vector_t FE, unsigned char bytes[], unsigned int BLen) {
  int vecLen =FE->size;
  if ((8*BLen) < (vecLen *10)) {
    return BYTEVECTORTOOSMALL;
  }
  int used = 0;
  int j=0;
  int i;
  bytes[j]=0x00;
  unsigned char bits = 0x00;

  for (i=0;i<vecLen;i++){
    switch (used) {
    case 0:
      bytes[j]=(FE->data[i])>>2;
      j++;
      bits = FE->data[i] & 0x0003;
      bytes[j]= bits <<6;
      used = 2;
      break;
    case 2:
      bytes[j]=(((FE->data[i])>>4) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x000F;
      bytes[j]= bits<<4;
      used = 4;      
      break;
    case 4:
      bytes[j]=(((FE->data[i])>>6) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x003F;
      bytes[j]= bits<<2;
      used = 6;      
      break;
    case 6:
      bytes[j]=(((FE->data[i])>>8) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x00FF;
      bytes[j]= bits;
      used = 0;
      j++;
      break;      
    default:
      return -1;
    }
  }
  return 0;  
}




int B2FE11 (unsigned char bytes[], unsigned int BLen, vector_t FE) {
  int vecLen =FE->size;  
  if (11*vecLen>8*BLen) {
    return BYTEVECTORTOOSMALL;
  }
  int j=0;
  int i;
  int used = 0;

  unsigned char bits = 0x00;
  for (i=0; i<vecLen; i++) {

    switch (used) {
    case 0:
      FE->data[i]=bytes[j];
      FE->data[i]=FE->data[i]<<3;
      j++;
      bits = (bytes[j] & 0xE0);
      bits = bits >>5;
      FE->data[i]=(FE->data[i]) | bits;
      used = 3;
      break;
    case 3:
      FE->data[i]= (bytes[j]<< 3) & 0x00FF;
      FE->data[i]=FE->data[i]<<3;
      j++;
      bits = (bytes[j] & 0xFC);
      bits = bits >>2;
      FE->data[i]=(FE->data[i]) | bits;
      used = 6;
      break;
    case 6:
      FE->data[i]= (bytes[j]<< 6) & 0x00FF;
      FE->data[i]=FE->data[i]<<2;
      j++;
      bits = (bytes[j] & 0xFF);
      FE->data[i]=(FE->data[i]) | bits;
      FE->data[i]=FE->data[i]<<1;
      j++;
      bits = (bytes[j] & 0x80);
      bits = bits >>7;
      FE->data[i]=(FE->data[i]) | bits;     
      used = 1;
      break;
    case 1:
      FE->data[i]= (bytes[j]<< 1) & 0x00FF;
      FE->data[i]=FE->data[i]<<3;
      j++;
      bits = (bytes[j] & 0xF0);
      bits = bits >>4;
      FE->data[i]=(FE->data[i]) | bits;
      used = 4;
      break;
    case 4:
      FE->data[i]= (bytes[j]<< 4) & 0x00FF;
      FE->data[i]=FE->data[i]<<3;
      j++;
      bits = (bytes[j] & 0xFE);
      bits = bits >>1;
      FE->data[i]=(FE->data[i]) | bits;
      used = 7;
      break;
    case 7:
      FE->data[i]= (bytes[j]<< 7) & 0x00FF;
      FE->data[i]=FE->data[i]<<1;
      j++;
      bits = (bytes[j] & 0xFF);
      FE->data[i]=(FE->data[i]) | bits;
      FE->data[i]=FE->data[i]<<2;
      j++;
      bits = (bytes[j] & 0xC0);
      bits = bits >>6;      
      FE->data[i]=(FE->data[i]) | bits;
      used = 2;
      break;
    case 2:
      FE->data[i]= (bytes[j]<< 2) & 0x00FF;
      FE->data[i]=FE->data[i]<<3;
      j++;
      bits = (bytes[j] & 0xF8);
      bits = bits >>3;
      FE->data[i]=(FE->data[i]) | bits;
      used = 5;
      break;      
    case 5:
      FE->data[i]= (bytes[j]<< 5) & 0x00FF;
      FE->data[i]=FE->data[i]<<3;
      j++;
      bits = (bytes[j] & 0xFF);
      FE->data[i]=(FE->data[i]) | bits;
      j++;
      used = 0;
      break;
    default:
      return -1;
    }
  }
  return 0;
}

int FE2B11 (vector_t FE, unsigned char bytes[], unsigned int BLen) {
  int vecLen =FE->size;
  if ((8*BLen) < (vecLen *11)) {
    return BYTEVECTORTOOSMALL;
  }
  int used = 0;
  int j=0;
  int i;
  bytes[j]=0x00;
  unsigned char bits = 0x00;

  for (i=0;i<vecLen;i++){
    switch (used) {
    case 0:
      bytes[j]=(FE->data[i])>>3;
      j++;
      bits = FE->data[i] & 0x0007;
      bytes[j]= bits <<5;
      used = 3;
      break;
    case 3:
      bytes[j]=(((FE->data[i])>>6) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x003F;
      bytes[j]= bits<<2;
      used = 6;      
      break;
    case 6:
      bytes[j]=(((FE->data[i])>>9) | bytes[j]);
      j++;
      bytes[j] = (FE->data[i]>>1) & 0x00FF;
      j++;
      bits = FE->data[i] & 0x0001;
      bytes[j]= bits<<7;
      used = 1;      
      break;
    case 1:
      bytes[j]=(((FE->data[i])>>4) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x000F;
      bytes[j]= bits<<4;
      used = 4;
      break;
    case 4:
      bytes[j]=(((FE->data[i])>>7) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x007F;
      bytes[j]= bits<<1;
      used = 7;
      break;
    case 7:
      bytes[j]=(((FE->data[i])>>10) | bytes[j]);
      j++;
      bytes[j] = (FE->data[i]>>2) & 0x00FF;
      j++;
      bits = FE->data[i] & 0x0003;
      bytes[j]= bits<<6;
      used = 2;      
      break;
    case 2:
      bytes[j]=(((FE->data[i])>>5) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x001F;
      bytes[j]= bits<<3;
      used = 5;
      break;
    case 5:
      bytes[j]=(((FE->data[i])>>8) | bytes[j]);
      j++;
      bytes[j] = (FE->data[i]) & 0x00FF;
      j++;
      used = 0;      
      break;      
    default:
      return -1;
    }
  }
  return 0;  
}
