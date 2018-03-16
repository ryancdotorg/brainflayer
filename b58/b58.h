#ifndef __B58_H_
#define __B58_H_
ssize_t b58e_raw(unsigned char *out, size_t out_sz, const unsigned char *in, size_t in_sz);
ssize_t b58d_raw(unsigned char *out, size_t out_sz, const unsigned char *in, size_t in_sz);
ssize_t b58e_chk(unsigned char *out, size_t out_sz, const unsigned char *in, size_t in_sz, unsigned char ver);
ssize_t b58d_chk(unsigned char *out, size_t out_sz, const unsigned char *in, size_t in_sz, unsigned char *ver);
ssize_t b58e_chkl(unsigned char *out, size_t out_sz, const unsigned char *in, size_t in_sz, uint32_t ver);
ssize_t b58d_chkl(unsigned char *out, size_t out_sz, const unsigned char *in, size_t in_sz, uint32_t *ver);
#endif//__B58_H_
