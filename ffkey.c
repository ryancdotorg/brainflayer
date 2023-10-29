#include <limits.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <sys/time.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

#define BATCH 256

static const int64_t RNG_MULTIPLIER = 0x5DEECE66DLL;
static const int64_t RNG_ADDEND = 0xBLL;
static const int64_t RNG_MASK = (1LL << 48) - 1;
static const double RNG_DSCALE = (double)(1LL << 53);

uint64_t rng_ctx;

void ffrng_init(int64_t *ctx, int64_t seed) {
  *ctx = (seed ^ RNG_MULTIPLIER) & RNG_MASK;
}

static inline uint64_t ffrng_next(int64_t *ctx, int bits) {
  uint64_t nextseed = *ctx * RNG_MULTIPLIER;
  nextseed += RNG_ADDEND;
  nextseed &= RNG_MASK;
  *ctx = nextseed;
  return nextseed >> (48 - bits);
}

static inline double ffrng_double(int64_t *ctx) {
  double r = ((double)((ffrng_next(ctx, 26) << 27) + ffrng_next(ctx, 27))) / RNG_DSCALE;
  return r;
}

static void generate_address(uint8_t *pub) {
	uint8_t hash1[32];
	uint8_t a[21 + 32];
	BN_CTX *bnctx;
	BIGNUM bntmp, bntmp2, bnrem, bnbase;
	BIGNUM *bn, *bndiv, *bnptmp;
	char b58[40];
	int i;

	SHA256(pub, 65, hash1);
	RIPEMD160(hash1, 32, &a[1]);
    for (i = 1; i < 21; ++i) {
      printf("%02x", a[i]);
    }
    printf("\n");
}

int main(int argc, char **argv) {
	BN_CTX *ctx = BN_CTX_new();
	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_GROUP_precompute_mult(group, ctx);
	EC_POINT *addT[256], *subT[256], *p, *pbatch[BATCH];
	BIGNUM bn, bn256;
    uint64_t seed;
    uint8_t addB, subB;
	uint8_t r[32], pkey[65];
    uint8_t keys[32*BATCH];
	int x = 0, ri = 0, i, j, k;
	struct timeval tv, tv2;

	BN_init(&bn256);
    BN_set_word(&bn256, 256);

	seed = 1394366103664ULL;
    ffrng_init(&rng_ctx, seed);
	memset(r, 0, sizeof(r));
	BN_init(&bn);

    // infinity is the additive identity (aka zero)
	p = EC_POINT_new(group);
    EC_POINT_set_to_infinity(group, p);

    // set up add/subtract tables
    addT[0] = EC_POINT_new(group);
    subT[0] = EC_POINT_new(group);
    EC_POINT_set_to_infinity(group, addT[0]);
    EC_POINT_set_to_infinity(group, subT[0]);
	for (i = 1; i < 256; ++i) {
		BN_set_word(&bn, i);
		addT[i] = EC_POINT_new(group);
		EC_POINT_mul(group, addT[i], &bn, NULL, NULL, ctx);
		BN_lshift(&bn, &bn, 256 - 8);
		subT[i] = EC_POINT_new(group);
		EC_POINT_mul(group, subT[i], &bn, NULL, NULL, ctx);
		EC_POINT_invert(group, subT[i], ctx); // negate
	}

    for (i = 0; i < BATCH; ++i) {
      pbatch[i] = EC_POINT_new(group);
    }

    while (1) {
      ffrng_init(&rng_ctx, seed++);
      memset(r, 0, sizeof(r));
      for (i = 0; i < 32; ++i) {
        r[i] = (((double)256) * ffrng_double(&rng_ctx));
      }
      memcpy(keys, r, 32);
      BN_bin2bn(r, 32, &bn);
      EC_POINT_mul(group, pbatch[0], &bn, NULL, NULL, ctx);
      for (i = 1; i < BATCH; ++i) {
        EC_POINT_add(group, pbatch[i], pbatch[i-1], subT[r[0]], ctx);

        // shift the bytes
        for (j = 0; j < 31; ++j) { r[j] = r[j+1]; }
        // next byte from rng
        r[31] = (((double)256) * ffrng_double(&rng_ctx)); 
        //*
        EC_POINT_dbl(group, pbatch[i], pbatch[i], ctx);
        EC_POINT_dbl(group, pbatch[i], pbatch[i], ctx);
        EC_POINT_dbl(group, pbatch[i], pbatch[i], ctx);
        EC_POINT_dbl(group, pbatch[i], pbatch[i], ctx);
        EC_POINT_dbl(group, pbatch[i], pbatch[i], ctx);
        EC_POINT_dbl(group, pbatch[i], pbatch[i], ctx);
        EC_POINT_dbl(group, pbatch[i], pbatch[i], ctx);
        EC_POINT_dbl(group, pbatch[i], pbatch[i], ctx);

        EC_POINT_add(group, pbatch[i], pbatch[i], addT[r[31]], ctx);
        //*/
        //BN_bin2bn(r, 32, &bn);
        //EC_POINT_mul(group, pbatch[i], &bn, NULL, NULL, ctx);
        memcpy(keys+i*32, r, 32);
      }

      EC_POINTs_make_affine(group, BATCH, pbatch, ctx);

      for (i = 0; i < BATCH; ++i) {
		EC_POINT_point2oct(group, pbatch[i], POINT_CONVERSION_UNCOMPRESSED, pkey, 65, NULL);
        //for (j = 0; j < 32; ++j) { printf("%02x", keys[j+i*32]); } printf("\n");
        //for (j = 0; j < 65; ++j) { printf("%02X", pkey[j]); }      printf("\n");
		generate_address(pkey);
      }
    }

	gettimeofday(&tv, NULL);
	while (1) {
        //*
		if (++x % 0x1000 == 0) {
			tv2 = tv;
			gettimeofday(&tv, NULL);
			double dt = tv.tv_sec - tv2.tv_sec +
				(tv.tv_usec - tv2.tv_usec) / 1000000.0;
			fprintf(stderr, "%g Hz\n", 0x1000 / dt);
		}//*/
	}
	return 0;
}

/*
int EC_KEY_regenerate_key(EC_KEY *eckey, BIGNUM *priv_key)
{
    int ok = 0;
    BN_CTX *ctx = NULL;
    EC_POINT *pub_key = NULL;

    if (!eckey) return 0;

    const EC_GROUP *group = EC_KEY_get0_group(eckey);

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;

    pub_key = EC_POINT_new(group);

    if (pub_key == NULL)
        goto err;

    if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
        goto err;

    EC_KEY_set_private_key(eckey,priv_key);
    EC_KEY_set_public_key(eckey,pub_key);

    ok = 1;

err:

    if (pub_key)
        EC_POINT_free(pub_key);
    if (ctx != NULL)
        BN_CTX_free(ctx);

    return(ok);
}
static void
generate_pub_key(uint8_t *priv, uint8_t *pub)
{
	EC_KEY *pkey;
	BIGNUM bn;
	int rc;

	pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
	assert(pkey != NULL);
	BN_init(&bn);
        BN_bin2bn(priv, 32, &bn);
	rc = EC_KEY_regenerate_key(pkey, &bn);
	assert(rc);
	BN_clear_free(&bn);
	EC_KEY_set_conv_form(pkey, POINT_CONVERSION_UNCOMPRESSED);
	i2o_ECPublicKey(pkey, &pub); // moves pub, wtf?
	EC_KEY_free(pkey);
}
*/

