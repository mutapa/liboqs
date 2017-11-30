/* fieldPoly.c
 * Yongge Wang 
 *
 * Code was written: November 4, 2016-
 *
 * fieldPoly.c implements polynomial arithmetics 
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

poly_t poly_init(int n) {
  poly_t p;
  p = (poly_t) malloc(sizeof (struct polynomial));
  p->deg = -1;
  p->size = n;
  p->coeff = (field_t *) calloc(n, sizeof (field_t));
  return p;
}

void poly_clear(poly_t p) {
  memset(&(p->coeff[1+p->deg]), 0, (p->size -1-(p->deg))*sizeof(field_t));
}

void poly_zero(poly_t p) {
  p->deg = -1;
  memset(p->coeff, 0, (p->size)*sizeof(field_t));
}

void poly_copy(poly_t p, poly_t q) {
  memset(q->coeff, 0, (q->size)*sizeof(field_t));
  q->deg = p->deg;
  memcpy(q->coeff, p->coeff, (p->size) * sizeof (field_t));
}


void poly_free(poly_t p) {
  free(p->coeff);
  p->coeff=NULL;
  free(p);
  p=NULL;
}

