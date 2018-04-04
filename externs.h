/* externs.h - System-specific declarations */

#define _GNU_SOURCE    // Use the GNU C Library Extensions

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <pthread.h>

#include <CL/opencl.h>

#undef bool
#undef uint32_t
#undef uint64_t
#define bool uint8_t
#define uint32_t unsigned long int
#define uint64_t unsigned long long int

/* Swap the values of two integers, quadwords, doubles, etc. */
#define XCHG(a,b) (void)({ typeof(a) _temp=a; a=b; b=_temp; })
/* ...The same thing can be done using:  a ^= b, b ^= a, a ^= b */

/* Rotate a 32-bit word right or left */
#define ROR(x,n) ({ u32 _x=(x), _n=(n); (_x >> _n) | (_x << (32-_n)); })
#define ROL(x,n) ({ u32 _x=(x), _n=(n); (_x << _n) | (_x >> (32-_n)); })

/* Generic min() and max() functions */
#undef min
#undef max
#define min(x,y) ({ typeof(x) _x=x; typeof(y) _y=y; (_x < _y)?_x:_y; })
#define max(x,y) ({ typeof(x) _x=x; typeof(y) _y=y; (_x > _y)?_x:_y; })

/* Optimal way of keeping a number within a set range */
#define RANGE(x,lo,hi) ({ typeof(x) _val=x, _lo=lo, _hi=hi; \
                          (_val < _lo)?_lo:(_val > _hi)?_hi:_val; })

/* Determines the number of elements in a static array */
#define NELEM(array) (int)(sizeof(array)/sizeof(array[0]))


/**** Module declarations ****************************************************/

/* libsecp256k1 */
#include "secp256k1.h"

/* base58.c */
extern bool b58tobin(void *bin, size_t *binszp, const char *b58, size_t b58sz);
extern bool b58enc(char *b58, const void *data, size_t binsz);
