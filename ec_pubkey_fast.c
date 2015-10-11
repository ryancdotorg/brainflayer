/* Copyright (c) 2015 Nicolas Courtois, Guangyan Song, Ryan Castellucci, All Rights Reserved */
#include "ec_pubkey_fast.h"

#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "secp256k1/src/libsecp256k1-config.h"
#include "secp256k1/include/secp256k1.h"

#include "secp256k1/src/util.h"
#include "secp256k1/src/num_impl.h"
#include "secp256k1/src/field_impl.h"
#include "secp256k1/src/field_10x26_impl.h"
#include "secp256k1/src/scalar_impl.h"
#include "secp256k1/src/group_impl.h"
#include "secp256k1/src/ecmult_gen_impl.h"
#include "secp256k1/src/ecmult.h"

#undef ASSERT

#define READBIT(A, B) ((A >> (B & 7)) & 1)
#define SETBIT(T, B, V) (T = V ? T | (1<<B) : T & ~(1<<B))

int n_windows = 0; 
int n_values;
secp256k1_gej_t nums_gej;
secp256k1_ge_t *prec; 
int remmining = 0;
int WINDOW_SIZE = 0;
size_t MMAP_SIZE;

int secp256k1_ec_pubkey_precomp_table_save(int window_size, unsigned char *filename) {
    int fd, ret;
    size_t records;
    FILE *dest;

    if ((ret = secp256k1_ec_pubkey_precomp_table(window_size, NULL)) < 0)
        return ret;

    if ((fd = open(filename, O_RDWR | O_CREAT | O_EXCL, 0660)) < 0)
        return fd;

    records = n_windows*n_values;
    dest = fdopen(fd, "w");
    if (fwrite(prec, sizeof(secp256k1_ge_t), n_windows*n_values, dest) != records)
        return -1;

    return 0;
}

int secp256k1_ec_pubkey_precomp_table(int window_size, unsigned char *filename) {
    int ret, fd;
    struct stat sb;
    size_t prec_sz, page_sz, mmap_sz;
	secp256k1_gej_t gj; // base point in jacobian coordinates
	secp256k1_gej_t *table;

    if (filename) {
        if (stat(filename, &sb) == 0) {
            if (!S_ISREG(sb.st_mode))
                return -100;
        } else {
            return -101;
        }
    }

    for (;;) {
	    WINDOW_SIZE = window_size;
        n_values = 1 << window_size;
	    if (256 % window_size == 0) {
		    n_windows = (256 / window_size);
	    } else {
		    n_windows = (256 / window_size) + 1;
	    }
	    remmining = 256 % window_size;
        prec_sz = n_windows*n_values*sizeof(secp256k1_ge_t);
        if (!filename || sb.st_size <= prec_sz)
            break;
        ++window_size;
    }

    page_sz = sysconf(_SC_PAGE_SIZE);
    // round up to the next multiple of the page size
    mmap_sz = prec_sz % page_sz ? (prec_sz/page_sz+1)*page_sz : prec_sz;

	//prec = malloc(prec_sz);
    if (prec != NULL) munmap(prec, MMAP_SIZE); // work correctly if called again
    if (filename) {
        if (stat(filename, &sb) == 0) {
            if (!S_ISREG(sb.st_mode))
                return -100;
            if (sb.st_size != prec_sz)
                return -102;
            if ((fd = open(filename, O_RDONLY)) < 0)
                return fd;
            if ((ret = posix_fadvise(fd, 0, 0, POSIX_FADV_WILLNEED|POSIX_FADV_RANDOM)) < 0)
                return ret;
            if ((prec = mmap(NULL, MMAP_SIZE = mmap_sz, PROT_READ, MAP_SHARED|MAP_NORESERVE|MAP_POPULATE, fd, 0)) == NULL)
                return -103;
        } else {
            return -101;
        }
        
        return 0;
    } else {
        prec = mmap(NULL, MMAP_SIZE = mmap_sz, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    }

	table = malloc(n_windows*n_values*sizeof(secp256k1_gej_t));

	secp256k1_gej_set_ge(&gj, &secp256k1_ge_const_g);

	//fprintf(stderr, "%d %d %d %d %zu\n", window_size, n_windows, n_values, remmining, prec_sz);

    static const unsigned char nums_b32[33] = "The scalar for this x is unknown";
    secp256k1_fe_t nums_x;
    secp256k1_ge_t nums_ge;
    VERIFY_CHECK(secp256k1_fe_set_b32(&nums_x, nums_b32));
    VERIFY_CHECK(secp256k1_ge_set_xo_var(&nums_ge, &nums_x, 0));
    secp256k1_gej_set_ge(&nums_gej, &nums_ge);
    /* Add G to make the bits in x uniformly distributed. */
    secp256k1_gej_add_ge_var(&nums_gej, &nums_gej, &secp256k1_ge_const_g, NULL);
	
	secp256k1_gej_t gbase;
    secp256k1_gej_t numsbase;
    gbase = gj; /* (2^w_size)^num_of_windows * G */
    numsbase = nums_gej; /* 2^num_of_windows * nums. */

	for (int j = 0; j < n_windows; j++) {
        //[number of windows][each value from 0 - (2^window_size - 1)]
        table[j*n_values] = numsbase;
        for (int i = 1; i < n_values; i++) {
            secp256k1_gej_add_var(&table[j*n_values + i], &table[j*n_values + i - 1], &gbase, NULL);
        }
        
        for (int i = 0; i < window_size; i++) {
            secp256k1_gej_double_var(&gbase, &gbase, NULL);
        }
        /* Multiply numbase by 2. */
        secp256k1_gej_double_var(&numsbase, &numsbase, NULL);
        if (j == n_windows-2) {
            /* In the last iteration, numsbase is (1 - 2^j) * nums instead. */
            secp256k1_gej_neg(&numsbase, &numsbase);
            secp256k1_gej_add_var(&numsbase, &numsbase, &nums_gej, NULL);
        }
    }
	secp256k1_ge_set_all_gej_var(n_windows*n_values, prec, table, 0);

    free(table);
    return 0;
}

static void secp256k1_ecmult_gen2(secp256k1_gej_t *r, const unsigned char *seckey){
	unsigned char a[256];
	for (int j = 0; j < 32; j++) {
		for (int i = 0; i < 8; i++) {
			a[i+j*8] = READBIT(seckey[31-j], i);
		}
	}

	r->infinity = 1;
	int bits;

	for (int j = 0; j < n_windows; j++) {
		if (j == n_windows -1 && remmining != 0) {
			bits = 0;
			for (int i = 0; i < remmining; i++) {
				SETBIT(bits,i,a[i + j * WINDOW_SIZE]);
			}
		} else {
			bits = 0;
			for (int i = 0; i < WINDOW_SIZE; i++) {
				SETBIT(bits,i,a[i + j * WINDOW_SIZE]);
			}
		}
#if 1
 		secp256k1_gej_add_ge_var(r, r, &prec[j*n_values + bits], NULL);
#else
        secp256k1_gej_add_ge(r, r, &prec[j*n_values + bits]);
#endif
    }
}

#ifdef USE_BL_ARITHMETIC
static void secp256k1_gej_add_ge_bl(secp256k1_gej_t *r, const secp256k1_gej_t *a, const secp256k1_ge_t *b, secp256k1_fe_t *rzr) {
	secp256k1_fe_t z1z1, /*z1,*/ u2, x1, y1, t0, s2, h, hh, i, j, t1, rr,  v, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11;
	// 7M + 4S + 2 normalize + 22 mul_int/add/negate
	if (a->infinity) {
        VERIFY_CHECK(rzr == NULL);
        secp256k1_gej_set_ge(r, b);
        return;
    }
    if (b->infinity) {
        if (rzr) {
            secp256k1_fe_set_int(rzr, 1);
        }
        *r = *a;
        return;
    }
    r->infinity = 0;

	x1 = a->x; secp256k1_fe_normalize_weak(&x1);
	y1 = a->y; secp256k1_fe_normalize_weak(&y1);
	
    secp256k1_fe_sqr(&z1z1, &a->z);								// z1z1 = z1^2
	secp256k1_fe_mul(&u2, &b->x, &z1z1);					 	// u2 = x2*z1z1
	secp256k1_fe_mul(&t0, &a->z, &z1z1);	                    // t0 = z1*z1z1
	secp256k1_fe_mul(&s2, &b->y, &t0);							// s2 = y2 * t0
	secp256k1_fe_negate(&h, &x1, 1); secp256k1_fe_add(&h, &u2); // h = u2-x1  (3)
	secp256k1_fe_sqr(&hh,&h);									// hh = h^2
	i = hh; secp256k1_fe_mul_int(&i,4);							// i = 4*hh
	if (secp256k1_fe_normalizes_to_zero_var(&h)) {
        if (secp256k1_fe_normalizes_to_zero_var(&i)) {
            secp256k1_gej_double_var(r, a, rzr);
        } else {
            if (rzr) {
                secp256k1_fe_set_int(rzr, 0);
            }
            r->infinity = 1;
        }
        return;
    }
	secp256k1_fe_mul(&j,&h,&i);									// j = h*i
	secp256k1_fe_negate(&t1, &y1, 1); secp256k1_fe_add(&t1, &s2); // t1 = s2-y1
	rr = t1; secp256k1_fe_mul_int(&rr, 2);						// rr = 2 * t1;
	secp256k1_fe_mul(&v, &x1, &i);								// v = x1 * i
	secp256k1_fe_sqr(&t2, &rr);									// t2 = rr^2
	t3 = v; secp256k1_fe_mul_int(&t3, 2);						// t3 = 2*v
	secp256k1_fe_negate(&t4, &j, 1);   secp256k1_fe_add(&t4, &t2); // t4 = t2 - j
	secp256k1_fe_negate(&r->x, &t3, 2); secp256k1_fe_add(&r->x, &t4); // x3 = t4 - t3;
	//secp256k1_fe_normalize_weak(&r->x);
	secp256k1_fe_negate(&t5, &r->x, 6); secp256k1_fe_add(&t5, &v); // t5 = v - x3
	secp256k1_fe_mul(&t6,&y1,&j);								// t6 = y1 * j
	t7 = t6; secp256k1_fe_mul_int(&t7,2);						// t7 = 2*t6;
	secp256k1_fe_mul(&t8,&rr,&t5);								// t8 = rr* t5;
	secp256k1_fe_negate(&r->y, &t7, 2); secp256k1_fe_add(&r->y,&t8);// y3 = t8-t7
	//secp256k1_fe_normalize_weak(&r->y);
	t9 = h; secp256k1_fe_add(&t9, &a->z);						// t9 = z1 + h
	secp256k1_fe_sqr(&t10, &t9);								// t10 = t9^2
	secp256k1_fe_negate(&t11, &z1z1, 1); secp256k1_fe_add(&t11, &t10); // t11 = t10-z1z1
	secp256k1_fe_negate(&r->z, &hh, 1); secp256k1_fe_add(&r->z, &t11); // z3 = t11 - hh

}

static void secp256k1_ecmult_gen_bl(secp256k1_gej_t *r, const unsigned char *seckey){
	unsigned char a[256];
	for (int j = 0; j < 32; j++){
		for (int i = 0; i < 8; i++){
			a[i+j*8] = READBIT(seckey[31-j], i);
		}
	}

	r->infinity = 1;
	int bits;

	for (int j = 0; j < n_windows; j++) {
		if (j == n_windows -1 && remmining != 0) {
			bits = 0;
			for (int i = 0; i < remmining; i++) {
				SETBIT(bits,i,a[i + j * WINDOW_SIZE]);
			}
			//bits = secp256k1_scalar_get_bits2(a, j * WINDOW_SIZE, remmining);
		} else {
			bits = 0;
			for (int i = 0; i < WINDOW_SIZE; i++) {
				SETBIT(bits,i,a[i + j * WINDOW_SIZE]);
			}
			//bits = secp256k1_scalar_get_bits2(a, j * WINDOW_SIZE, WINDOW_SIZE);
		}
		secp256k1_gej_add_ge_bl(r, r, &prec[j*n_values + bits], NULL);
    }
}
#endif

int secp256k1_ec_pubkey_create_precomp(unsigned char *pub_chr, int *pub_chr_sz, const unsigned char *seckey) {
    secp256k1_gej_t pj;
    secp256k1_ge_t p;

#ifdef USE_BL_ARITHMETIC
    secp256k1_ecmult_gen_bl(&pj, seckey);
#else
    secp256k1_ecmult_gen2(&pj, seckey);
#endif
    secp256k1_ge_set_gej(&p, &pj);

    *pub_chr_sz = 65;
    pub_chr[0] = 4;

    secp256k1_fe_normalize_var(&p.x);
    secp256k1_fe_normalize_var(&p.y);
    secp256k1_fe_get_b32(pub_chr +  1, &p.x);
    secp256k1_fe_get_b32(pub_chr + 33, &p.y);

    return 0;
}
