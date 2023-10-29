/* Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#ifndef __BRAINFLAYER_FFRNG_H_
#define __BRAINFLAYER_FFRNG_H_
void ffrng_init(int64_t *ctx, int64_t seed);
uint64_t ffrng_next(int64_t *ctx, int bits);
double ffrng_double(int64_t *ctx);
void ffrng_bytes(int64_t *ctx, unsigned char *buf, size_t buf_sz);
void ffrng_bytes_seed(unsigned char *buf, size_t buf_sz, int64_t seed);
#endif /* __BRAINFLAYER_FFRNG_H_ */
/*  vim: set ts=2 sw=2 et ai si: */
