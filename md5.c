#include <stdio.h>
#include <string.h>

#define BYTEORDER 0x4321
#define MD5_DEBUG

typedef unsigned int UINT;
typedef unsigned int U32;
typedef unsigned char UCHAR;

#define TO32(l)    (l)
#define TRUNC32(l)

#if BYTEORDER == 0x1234 || BYTEORDER == 0x12345678
#define byteswap(x) (x)
#elif BYTEORDER == 0x4321  || BYTEORDER == 0x87654321
#define byteswap(x) 	((((x)&0xFF)<<24)	\
			|(((x)>>24)&0xFF)	\
			|(((x)&0x0000FF00)<<8)	\
			|(((x)&0x00FF0000)>>8)	)
#else

static U32 byteswap(U32 x);  /* function */

#endif

#ifdef MD5_DEBUG
static void my_memcpy(char *b, char*d, const char*s, unsigned int len)
{
    static int mcount = 0;
    printf("%5d: memcpy(b+%d, %p, %d)\n", ++mcount, d-b, s, len);
    memcpy(d,s,len);
}
#define memcpy(d,s,l) my_memcpy(ctx->buffer,(d),(s),(l))
#endif

typedef struct {
  U32 A, B, C, D;
  U32 bytes_low;
  U32 bytes_high;
  UCHAR buffer[128];
} MD5_CTX;

static unsigned char PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* Constants for MD5Transform routine.
 */

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

/* F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) (((x) & ((y) ^ (z)) ^ (z)))
#define G(x, y, z) F(z, x, y)
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n) | ((x) >> (32-(n)))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
 * Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, s, ac)                    \
 (a) += F ((b), (c), (d)) + (NEXTx) + (U32)(ac); \
 TRUNC32((a));                                   \
 (a) = ROTATE_LEFT ((a), (s));                   \
 (a) += (b);                                     \
 TRUNC32((a));

#define GG(a, b, c, d, x, s, ac)                 \
 (a) += G ((b), (c), (d)) + X[x] + (U32)(ac);    \
 TRUNC32((a));                                   \
 (a) = ROTATE_LEFT ((a), (s));                   \
 (a) += (b);                                     \
 TRUNC32((a));

#define HH(a, b, c, d, x, s, ac)                 \
 (a) += H ((b), (c), (d)) + X[x] + (U32)(ac);    \
 TRUNC32((a));                                   \
 (a) = ROTATE_LEFT ((a), (s));                   \
 (a) += (b);                                     \
 TRUNC32((a));

#define II(a, b, c, d, x, s, ac)                 \
 (a) += I ((b), (c), (d)) + X[x] + (U32)(ac);    \
 TRUNC32((a));                                   \
 (a) = ROTATE_LEFT ((a), (s));                   \
 (a) += (b);                                     \
 TRUNC32((a));

static void
MD5Init(MD5_CTX *ctx)
{
  /* Start state */
  ctx->A = 0x67452301;
  ctx->B = 0xefcdab89;
  ctx->C = 0x98badcfe;
  ctx->D = 0x10325476;

  ctx->bytes_low = ctx->bytes_high = 0;
}

static void
MD5Transform(MD5_CTX* ctx, const void* buf, UINT blocks)
{
  static int tcount = 0;

  U32 A = ctx->A;
  U32 B = ctx->B;
  U32 C = ctx->C;
  U32 D = ctx->D;

  const U32 *x = buf;  /* really just type casting */

  while(blocks--) {
    U32 a = A;
    U32 b = B;
    U32 c = C;
    U32 d = D;

#if BYTEORDER == 0x1234
    const U32 *X = x;
    #define NEXTx *x++
#else
    U32 X[16];
    U32 *saveswapped = X;
    U32 tmp;
    #define NEXTx tmp=*x++, *saveswapped++ = byteswap(tmp)
#endif

#ifdef MD5_DEBUG
    if (buf == ctx->buffer)
      printf("%5d: Transform ctx->buffer", ++tcount);
    else 
      printf("%5d: Transform %p (%d)", ++tcount, buf, blocks);

    {
	int i;
	printf("[");
	for (i = 0; i < 16; i++) {
	    printf("%x,", x[i]);
	}
	printf("]\n");
    }
#endif


    /* Round 1 */
    FF (a, b, c, d, S11, 0xd76aa478); /* 1 */
    FF (d, a, b, c, S12, 0xe8c7b756); /* 2 */
    FF (c, d, a, b, S13, 0x242070db); /* 3 */
    FF (b, c, d, a, S14, 0xc1bdceee); /* 4 */
    FF (a, b, c, d, S11, 0xf57c0faf); /* 5 */
    FF (d, a, b, c, S12, 0x4787c62a); /* 6 */
    FF (c, d, a, b, S13, 0xa8304613); /* 7 */
    FF (b, c, d, a, S14, 0xfd469501); /* 8 */
    FF (a, b, c, d, S11, 0x698098d8); /* 9 */
    FF (d, a, b, c, S12, 0x8b44f7af); /* 10 */
    FF (c, d, a, b, S13, 0xffff5bb1); /* 11 */
    FF (b, c, d, a, S14, 0x895cd7be); /* 12 */
    FF (a, b, c, d, S11, 0x6b901122); /* 13 */
    FF (d, a, b, c, S12, 0xfd987193); /* 14 */
    FF (c, d, a, b, S13, 0xa679438e); /* 15 */
    FF (b, c, d, a, S14, 0x49b40821); /* 16 */

    /* Round 2 */
    GG (a, b, c, d,  1, S21, 0xf61e2562); /* 17 */
    GG (d, a, b, c,  6, S22, 0xc040b340); /* 18 */
    GG (c, d, a, b, 11, S23, 0x265e5a51); /* 19 */
    GG (b, c, d, a,  0, S24, 0xe9b6c7aa); /* 20 */
    GG (a, b, c, d,  5, S21, 0xd62f105d); /* 21 */
    GG (d, a, b, c, 10, S22,  0x2441453); /* 22 */
    GG (c, d, a, b, 15, S23, 0xd8a1e681); /* 23 */
    GG (b, c, d, a,  4, S24, 0xe7d3fbc8); /* 24 */
    GG (a, b, c, d,  9, S21, 0x21e1cde6); /* 25 */
    GG (d, a, b, c, 14, S22, 0xc33707d6); /* 26 */
    GG (c, d, a, b,  3, S23, 0xf4d50d87); /* 27 */
    GG (b, c, d, a,  8, S24, 0x455a14ed); /* 28 */
    GG (a, b, c, d, 13, S21, 0xa9e3e905); /* 29 */
    GG (d, a, b, c,  2, S22, 0xfcefa3f8); /* 30 */
    GG (c, d, a, b,  7, S23, 0x676f02d9); /* 31 */
    GG (b, c, d, a, 12, S24, 0x8d2a4c8a); /* 32 */

    /* Round 3 */
    HH (a, b, c, d,  5, S31, 0xfffa3942); /* 33 */
    HH (d, a, b, c,  8, S32, 0x8771f681); /* 34 */
    HH (c, d, a, b, 11, S33, 0x6d9d6122); /* 35 */
    HH (b, c, d, a, 14, S34, 0xfde5380c); /* 36 */
    HH (a, b, c, d,  1, S31, 0xa4beea44); /* 37 */
    HH (d, a, b, c,  4, S32, 0x4bdecfa9); /* 38 */
    HH (c, d, a, b,  7, S33, 0xf6bb4b60); /* 39 */
    HH (b, c, d, a, 10, S34, 0xbebfbc70); /* 40 */
    HH (a, b, c, d, 13, S31, 0x289b7ec6); /* 41 */
    HH (d, a, b, c,  0, S32, 0xeaa127fa); /* 42 */
    HH (c, d, a, b,  3, S33, 0xd4ef3085); /* 43 */
    HH (b, c, d, a,  6, S34,  0x4881d05); /* 44 */
    HH (a, b, c, d,  9, S31, 0xd9d4d039); /* 45 */
    HH (d, a, b, c, 12, S32, 0xe6db99e5); /* 46 */
    HH (c, d, a, b, 15, S33, 0x1fa27cf8); /* 47 */
    HH (b, c, d, a,  2, S34, 0xc4ac5665); /* 48 */

    /* Round 4 */
    II (a, b, c, d,  0, S41, 0xf4292244); /* 49 */
    II (d, a, b, c,  7, S42, 0x432aff97); /* 50 */
    II (c, d, a, b, 14, S43, 0xab9423a7); /* 51 */
    II (b, c, d, a,  5, S44, 0xfc93a039); /* 52 */
    II (a, b, c, d, 12, S41, 0x655b59c3); /* 53 */
    II (d, a, b, c,  3, S42, 0x8f0ccc92); /* 54 */
    II (c, d, a, b, 10, S43, 0xffeff47d); /* 55 */
    II (b, c, d, a,  1, S44, 0x85845dd1); /* 56 */
    II (a, b, c, d,  8, S41, 0x6fa87e4f); /* 57 */
    II (d, a, b, c, 15, S42, 0xfe2ce6e0); /* 58 */
    II (c, d, a, b,  6, S43, 0xa3014314); /* 59 */
    II (b, c, d, a, 13, S44, 0x4e0811a1); /* 60 */
    II (a, b, c, d,  4, S41, 0xf7537e82); /* 61 */
    II (d, a, b, c, 11, S42, 0xbd3af235); /* 62 */
    II (c, d, a, b,  2, S43, 0x2ad7d2bb); /* 63 */
    II (b, c, d, a,  9, S44, 0xeb86d391); /* 64 */

    A += a;  TRUNC32(A);
    B += b;  TRUNC32(A);
    C += c;  TRUNC32(A);
    D += d;  TRUNC32(A);

  }
  ctx->A = A;
  ctx->B = B;
  ctx->C = C;
  ctx->D = D;
}

#ifdef MD5_DEBUG
static char*
ctx_dump(MD5_CTX* ctx)
{
  static char buf[1024];
  sprintf(buf, "{A,B,C,D,%d,%d,%d}",
	       ctx->bytes_low, ctx->bytes_high, (ctx->bytes_low&0x3F));
  return buf;
}
#endif


static void
MD5Update(MD5_CTX* ctx, const void* buf, UINT len)
{
  UINT blocks;
  UINT fill = ctx->bytes_low & 0x3F;

#ifdef MD5_DEBUG  
  static int ucount = 0;
  printf("%5i: Update(%s, %p, %d)\n", ++ucount, ctx_dump(ctx), buf, len);
#endif

  ctx->bytes_low += len;
  if (ctx->bytes_low < len) /* wrap around */
    ctx->bytes_high++;

  if (fill) {
    UINT missing = 64 - fill;
    if (len < missing) {
      memcpy(ctx->buffer + fill, buf, len);
      return;
    }
    memcpy(ctx->buffer + fill, buf, missing);
    MD5Transform(ctx, ctx->buffer, 1);
    buf += missing;
    len -= missing;
  }

  blocks = len >> 6;
  if (blocks)
    MD5Transform(ctx, buf, blocks);
  if ( (len &= 0x3F)) {
    memcpy(ctx->buffer, buf + (blocks << 6), len);
  }
}

static void
MD5Final(UCHAR* digest, MD5_CTX *ctx)
{

  UINT fill = ctx->bytes_low & 0x3F;
  UINT padlen = (fill < 56 ? 56 : 120) - fill;
#ifdef MD5_DEBUG
  printf("       Final: %s\n", ctx_dump(ctx));
#endif
  memcpy(ctx->buffer + fill, PADDING, padlen);
  fill += padlen;

  *(U32*)(ctx->buffer + fill) = byteswap(ctx->bytes_low << 3);
  fill += 4;
  *(U32*)(ctx->buffer + fill) = byteswap((ctx->bytes_high << 3) ||
					 (ctx->bytes_low  >> 29));
  fill += 4;
  MD5Transform(ctx, ctx->buffer, fill >> 6);

  *(U32*)digest = byteswap(ctx->A);  digest += 4;
  *(U32*)digest = byteswap(ctx->B);  digest += 4;
  *(U32*)digest = byteswap(ctx->C);  digest += 4;
  *(U32*)digest = byteswap(ctx->D);
}

//--------------------------------


static char* hex_16(unsigned char* from, char* to)
{
    static char *hexdigits = "0123456789abcdef";
    unsigned char *end = from + 16;
    char *d = to;

    while (from < end) {
	*d++ = hexdigits[(*from >> 4)];
	*d++ = hexdigits[(*from & 0x0F)];
	from++;
    }
    *d = '\0';
    return to;
}


int main()
{
    int i;
    MD5_CTX ctx;
    char data[3];
    unsigned char digeststr[16];
    char result[33];

    memset(data, 'a', sizeof(data));

    MD5Init(&ctx);
    for (i = 0; i < 1; i++) {
      MD5Update(&ctx, data, sizeof(data));
    }
    MD5Final(digeststr, &ctx);

    printf("MD5=%s (%p)\n", hex_16(digeststr, result), PADDING);

    return 0;
}
