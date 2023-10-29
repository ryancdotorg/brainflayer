#ifndef __BCONV_H_
#define __BCONV_H_

/* byte conversion */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define be32(x) __builtin_bswap32(x)
# define be64(x) __builtin_bswap64(x)
#else
# define be32(x) (x)
# define be64(x) (x)
#endif

#endif//__BCONV_H_
