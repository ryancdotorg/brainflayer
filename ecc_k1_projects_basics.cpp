#include "ecc_k1_projects_basics.h"
void Espace(void)	/* waits until SPACE key is pressed.*/
/* in borland does not work in win32s programs ????*/
{
	printf("\nPress Space : ");
	#ifdef _MSC_VER
//		while(getch()!=32);//This POSIX function is deprecated. Use the ISO C++ conformant _getch instead.
		while(_getch()!=32);
	#else
		while(getchar()!=32);
	#endif
	printf("continuing.\n");
}

#undef ASSERT
static secp256k1_context_t *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

void BitcoinECCgetPubkey_secp256k1(unsigned char *Here64x,unsigned char *Secret){
	unsigned char privkey[32];
    unsigned char pubkeyc[65];
    int pubkeyclen = 65;
    secp256k1_pubkey_t pubkey;
	unsigned char digest[SHA256_DIGEST_LENGTH];
	unsigned char digest2[20];

	//secp256k1_ec_seckey_verify(ctx,Secret);
	secp256k1_ec_pubkey_create(ctx, &pubkey, Secret);

	secp256k1_ec_pubkey_serialize(ctx, pubkeyc, &pubkeyclen, &pubkey, 0);

	SHA256((unsigned char*)pubkeyc, pubkeyclen, digest);

	RIPEMD160((unsigned char*)digest, SHA256_DIGEST_LENGTH, digest2);
	
	for (int i = 0; i < 20; i++){
		sprintf((char*)Here64x+i*2, "%02x", digest2[i]);	
	}

	return;
}



//----------------------------------------------------



int PointAdditions=27000;
int LargerTestValue = 27000000;

struct secp256k1_context_struct {
    secp256k1_ecmult_context_t ecmult_ctx;
    secp256k1_ecmult_gen_context_t ecmult_gen_ctx;
    callback_t illegal_callback;
    callback_t error_callback;
};


void ge_equals_gej(const secp256k1_ge_t *a, const secp256k1_gej_t *b) {
    secp256k1_fe_t z2s;
    secp256k1_fe_t u1, u2, s1, s2;
    CHECK(a->infinity == b->infinity);
    if (a->infinity) {
        return;
    }
    /* Check a.x * b.z^2 == b.x && a.y * b.z^3 == b.y, to avoid inverses. */
    secp256k1_fe_sqr(&z2s, &b->z);
    secp256k1_fe_mul(&u1, &a->x, &z2s);
    u2 = b->x; secp256k1_fe_normalize_weak(&u2);
    secp256k1_fe_mul(&s1, &a->y, &z2s); secp256k1_fe_mul(&s1, &s1, &b->z);
    s2 = b->y; secp256k1_fe_normalize_weak(&s2);
    CHECK(secp256k1_fe_equal_var(&u1, &u2));
    CHECK(secp256k1_fe_equal_var(&s1, &s2));
}


/*
my own implementation
*/


int numberOfWindows = 0; 
int numberOfValues;
secp256k1_gej_t nums_gej;
secp256k1_ge_t * prec; 
int remmining = 0;
int WINDOW_SIZE = 0;
void displayHex(secp256k1_fe_t* p){
	for (int i = 9; i > 0; i--){
		printf("%08x ",p->n[i]);
	}
	printf("\n");
}

void precomputeTable(int window_size){
	secp256k1_gej_t gj; // base point in jacobian coordinates
	secp256k1_gej_t *table;

	WINDOW_SIZE = window_size;
	numberOfValues = (int) pow(2.0,window_size);

	if (256 % window_size == 0){
		numberOfWindows = (256 / window_size);
	}else{
		numberOfWindows = (256 / window_size) + 1;
	}
	remmining = 256 % window_size;

	
	table = (secp256k1_gej_t *)malloc(numberOfWindows*numberOfValues*sizeof(secp256k1_gej_t));
	prec = (secp256k1_ge_t *)malloc(numberOfWindows*numberOfValues*sizeof(secp256k1_ge_t));
	secp256k1_gej_set_ge(&gj, &secp256k1_ge_const_g);

	printf("%d %d %d %d\n",window_size,numberOfWindows,numberOfValues,remmining);
	secp256k1_ge_const_g;

	{
        static const unsigned char nums_b32[33] = "The scalar for this x is unknown";
        secp256k1_fe_t nums_x;
        secp256k1_ge_t nums_ge;
        VERIFY_CHECK(secp256k1_fe_set_b32(&nums_x, nums_b32));
        VERIFY_CHECK(secp256k1_ge_set_xo_var(&nums_ge, &nums_x, 0));
        secp256k1_gej_set_ge(&nums_gej, &nums_ge);
        /* Add G to make the bits in x uniformly distributed. */
        secp256k1_gej_add_ge_var(&nums_gej, &nums_gej, &secp256k1_ge_const_g, NULL);
    }
	
	secp256k1_gej_t gbase;
    secp256k1_gej_t numsbase;
    gbase = gj; /* (2^w_size)^num_of_windows * G */
    numsbase = nums_gej; /* 2^num_of_windows * nums. */

	for (int j = 0; j < numberOfWindows; j++) {
        //[number of windows][each value from 0 - (2^window_size - 1)]
        table[j*numberOfValues] = numsbase;
        for (int i = 1; i < numberOfValues; i++) {
            secp256k1_gej_add_var(&table[j*numberOfValues + i], &table[j*numberOfValues + i - 1], &gbase, NULL);
        }
        
        for (int i = 0; i < window_size; i++) {
            secp256k1_gej_double_var(&gbase, &gbase, NULL);
        }
        /* Multiply numbase by 2. */
        secp256k1_gej_double_var(&numsbase, &numsbase, NULL);
        if (j == numberOfWindows-2) {
            /* In the last iteration, numsbase is (1 - 2^j) * nums instead. */
            secp256k1_gej_neg(&numsbase, &numsbase);
            secp256k1_gej_add_var(&numsbase, &numsbase, &nums_gej, NULL);
        }
    }
	secp256k1_ge_set_all_gej_var(numberOfWindows*numberOfValues, prec, table, 0);

	printf("");
    free(table);
}

void secp256k1_ecmult_gen(secp256k1_gej_t *r, const secp256k1_scalar_t *gn) {

	r->infinity = 1;
	int bits;


	for (int j = 0; j < numberOfWindows; j++) {
		if (j == numberOfWindows -1 && remmining != 0){
			bits = secp256k1_scalar_get_bits(gn, j * WINDOW_SIZE, remmining);
		}else{
			bits = secp256k1_scalar_get_bits(gn, j * WINDOW_SIZE, WINDOW_SIZE);
		}
		secp256k1_gej_add_ge(r, r,  &prec[j*numberOfValues + bits]);
    }

    bits = 0;
}

static void secp256k1_pubkey_save(secp256k1_pubkey_t* pubkey, secp256k1_ge_t* ge) {
    if (sizeof(secp256k1_ge_storage_t) == 64) {
        secp256k1_ge_storage_t s;
        secp256k1_ge_to_storage(&s, ge);
        memcpy(&pubkey->data[0], &s, 64);
    } else {
        VERIFY_CHECK(!secp256k1_ge_is_infinity(ge));
        secp256k1_fe_normalize_var(&ge->x);
        secp256k1_fe_normalize_var(&ge->y);
        secp256k1_fe_get_b32(pubkey->data, &ge->x);
        secp256k1_fe_get_b32(pubkey->data + 32, &ge->y);
    }
}

unsigned char ReadBit(const unsigned char A, int columnnb)
{
   return A >> (columnnb & 7) & 1;
}

void SetBit(unsigned char &a, int nb, unsigned char value)
{
        if (value)      a |= ( (unsigned char)1 )<< nb;
                else    a &= ~( ( (unsigned char) 1 )<< nb);    
}

void SetBit(int &a, int nb, unsigned char value)
{
        if (value)      a |= ((unsigned char)1)<<nb;
                else    a &= ~(((unsigned char)1)<<nb);   
}

void secp256k1_ecmult_gen2(secp256k1_gej_t *r, const unsigned char *seckey){
	unsigned char a [256];
	for (int j = 0 ; j < 32; j++){
		for (int i = 0 ; i < 8 ; i ++ ){
			a[i+j*8] = ReadBit(seckey[31-j],i);
		}
	}

	r->infinity = 1;
	int bits;

	for (int j = 0; j < numberOfWindows; j++) {
		if (j == numberOfWindows -1 && remmining != 0){
			bits = 0;
			for (int i = 0; i < remmining; i++){
				SetBit(bits,i,a[i + j * WINDOW_SIZE]);
			}
		}else{
			bits = 0;
			for (int i = 0; i < WINDOW_SIZE; i++){
				SetBit(bits,i,a[i + j * WINDOW_SIZE]);
			}
		}
 		secp256k1_gej_add_ge_var(r, r,  &prec[j*numberOfValues + bits],NULL);
    }
}

void secp256k1_ecmult_gen3(secp256k1_gej_t *r, const unsigned char *seckey){
	unsigned char a [256];
	for (int j = 0 ; j < 32; j++){
		for (int i = 0 ; i < 8 ; i ++ ){
			a[i+j*8] = ReadBit(seckey[31-j],i);
		}
	}

	r->infinity = 1;
	int bits;

	for (int j = 0; j < numberOfWindows; j++) {
		if (j == numberOfWindows -1 && remmining != 0){
			bits = 0;
			for (int i = 0; i < remmining; i++){
				SetBit(bits,i,a[i + j * WINDOW_SIZE]);
			}
		}else{
			bits = 0;
			for (int i = 0; i < WINDOW_SIZE; i++){
				SetBit(bits,i,a[i + j * WINDOW_SIZE]);
			}
		}
		secp256k1_gej_add_ge(r, r,  &prec[j*numberOfValues + bits]);
    }
}
static void secp256k1_gej_add_ge_bl(secp256k1_gej_t *r, const secp256k1_gej_t *a, const secp256k1_ge_t *b, secp256k1_fe_t *rzr) {
	secp256k1_fe_t z1z1, z1, u2, x1, y1, t0, s2, h, hh, i, j, t1, rr,  v, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11;
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

void secp256k1_ecmult_gen_bl(secp256k1_gej_t *r, const unsigned char *seckey){
	unsigned char a [256];
	for (int j = 0 ; j < 32; j++){
		for (int i = 0 ; i < 8 ; i ++ ){
			a[i+j*8] = ReadBit(seckey[31-j],i);
		}
	}

	r->infinity = 1;
	int bits;

	for (int j = 0; j < numberOfWindows; j++) {
		if (j == numberOfWindows -1 && remmining != 0){
			bits = 0;
			for (int i = 0; i < remmining; i++){
				SetBit(bits,i,a[i + j * WINDOW_SIZE]);
			}
			//bits = secp256k1_scalar_get_bits2(a, j * WINDOW_SIZE, remmining);
		}else{
			bits = 0;
			for (int i = 0; i < WINDOW_SIZE; i++){
				SetBit(bits,i,a[i + j * WINDOW_SIZE]);
			}
			//bits = secp256k1_scalar_get_bits2(a, j * WINDOW_SIZE, WINDOW_SIZE);
		}
		secp256k1_gej_add_ge_bl(r, r,  &prec[j*numberOfValues + bits],NULL);
    }
	//printf("%d\n",b);
}

int My_secp256k1_ec_pubkey_create(secp256k1_pubkey_t *pubkey, const unsigned char *seckey, int window_size) {
	   int ret = 0;
	   secp256k1_gej_t pj;
	   secp256k1_ge_t p;
	   secp256k1_scalar_t sec;
	   
	   int overflow;
	   secp256k1_scalar_set_b32(&sec, seckey, &overflow);
	   //secp256k1_ecmult_gen(&pj, &sec);
	   secp256k1_ecmult_gen2(&pj, seckey);
	   secp256k1_ge_set_gej(&p, &pj);
	   secp256k1_pubkey_save(pubkey, &p);
	   
	   return ret;
}
int My_Bitcoin_ECC_Testing93000(char * argv){
	int window_size = atoi(argv);
	precomputeTable(window_size);
	secp256k1_pubkey_t pubkey;

	std::ifstream infile("D:\\rockyou.txt");
	std::string line;
		
	time_t lastspeeds;struct _timeb lastspeedms;time_t speeds;struct _timeb speedms;int speed=0;	time( &lastspeeds );_ftime( &lastspeedms );

	char _Sec[300] = {0};
	char Secret[120]={0};
	unsigned char pubkeyc[65];
	int pubkeyclen = 65;
	unsigned char digest[SHA256_DIGEST_LENGTH];   //sha1
	int ct = 0, lastct = 0;
	while(std::getline (infile,line) )
	{
		strcpy( (char*) _Sec, line.c_str() );
		if(1)
		{
			SHA256((unsigned char*)&_Sec, strlen(_Sec), (unsigned char*)&digest);
			My_secp256k1_ec_pubkey_create(&pubkey, (unsigned char*) digest, window_size);
		}
		if (ct>=lastct+1000000){
			time( &speeds );_ftime( &speedms );	double timems=1+(speeds-lastspeeds)*(double)1000+(speedms.millitm-lastspeedms.millitm);		
			printf("%d  %7.0f\n",ct, (ct-lastct)*1000/timems);
			time( &lastspeeds );_ftime( &lastspeedms );
			lastct=ct;
		}
		ct ++;
	}
	return 0;
}
