#ifndef _ECC_K1_PR_BASICS_DEFINED
#define _ECC_K1_PR_BASICS_DEFINED

#include <conio.h>
#include <math.h>
#include "uint256.h"
#include "include/secp256k1.h"
#include <openssl/pem.h>
#include <openssl/ripemd.h>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/timeb.h>
#include <time.h>
#include "util.h"
#include "num_impl.h"
#include "field_impl.h"
#include "field_10x26_impl.h"
#include "scalar_impl.h"
#include "group_impl.h"
#include <ecmult_gen_impl.h>
#include <ecmult.h>

void Espace(void);
int My_Bitcoin_ECC_Testing93000(char * argv);
#endif
