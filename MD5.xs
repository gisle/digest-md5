/*
**	Perl Extension for the
**
**	RSA Data Security Inc. MD5 Message-Digest Algorithm
**
**	This module by Neil Winton (N.Winton@axion.bt.co.uk)
**
**	This extension may be distributed under the same terms
**	as Perl. The MD5 code is covered by separate copyright and
**	licence, but this does not prohibit distribution under the
**	GNU or Artistic licences. See the file MD5.pm for more details.
*/

#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#ifdef __cplusplus
}
#endif


/* UINT4 defines a four byte word.
  We use the Perl byte-order definition to discover if a long has more than
  4 bytes. If so we will try to use an unsigned int. This is OK for DEC
  Alpha but may not work everywhere. See the TO32 definition below.
 */
#if (BYTEORDER <= 0x4321) || defined(UINT4_IS_LONG)
typedef unsigned long UINT4;
#else
typedef unsigned int UINT4;
#endif

/* TO32 ensures that UINT4 values are truncated to 32 bits.
  A Cray has short, int and long all at 64 bits so we need to apply this
  macro to reduce UINT4 values to 32 bits at appropriate places. If UINT4
  really does have 32 bits then this is a no-op.
 */
#if defined(cray) || defined(TRUNCATE_UINT4)
#define TO32(x)	((x) & 0xffffffff)
#else
#define TO32(x)	(x)
#endif


/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

/* MD5 context. */
typedef struct {
  UINT4 state[4];                                   /* state (ABCD) */
  UINT4 count[2];        /* number of bits, modulo 2^64 (lsb first) */
  unsigned char buffer[64];                         /* input buffer */
} MD5_CTX;

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

static unsigned char PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) TO32((((x) & (y)) | ((~x) & (z))))
#define G(x, y, z) TO32((((x) & (z)) | ((y) & (~z))))
#define H(x, y, z) TO32(((x) ^ (y) ^ (z)))
#define I(x, y, z) TO32(((y) ^ ((x) | (~z))))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) TO32((((x) << (n)) | (TO32((x)) >> (32-(n)))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
 * Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
 TO32((a)); \
  }
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
 TO32((a)); \
  }
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
 TO32((a)); \
  }
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
 TO32((a)); \
  }

#if BYTEORDER == 0x1234  /* 32bit little endian */

   #define Encode(output, input, len)  Copy(input, output, len, char)
   #define Decode(output, input, len)  Copy(input, output, len, char)

#else

/* Encodes input (UINT4) into output (unsigned char). Assumes len is
 * a multiple of 4.
 */
static void Encode (output, input, len)
unsigned char *output;
UINT4 *input;
unsigned long len;
{
#if BYTEORDER == 0x4321 && defined(HAS_HTONL)
    long *out = (long*)output;
    len /= 4;
    while (len--) *out++ =  htovl(*input++);
#else
    unsigned long i, j;
    for (i = 0, j = 0; j < len; i++, j += 4) {
	output[j] = (unsigned char)(input[i] & 0xff);
	output[j+1] = (unsigned char)((input[i] >> 8) & 0xff);
	output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);
	output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);
    }
#endif
}

/* Decodes input (unsigned char) into output (UINT4). Assumes len is
 * a multiple of 4.
 */
static void Decode (output, input, len)
UINT4 *output;
unsigned char *input;
unsigned long len;
{
#if BYTEORDER == 0x4321 && defined(HAS_HTONL)
    long *in = (long*)input;
    len /= 4;
    while (len--) *output++ = htovl(*input++);
#else
    unsigned long i, j;
    for (i = 0, j = 0; j < len; i++, j += 4)
	output[i] = ((UINT4)input[j]) | (((UINT4)input[j+1]) << 8) |
	           (((UINT4)input[j+2]) << 16) | (((UINT4)input[j+3]) << 24);
#endif
}

#endif /* 32bit little endian */

/* MD5 initialization. Begins an MD5 operation, writing a new context.
 */
static void MD5Init (context)
MD5_CTX *context;                                        /* context */
{
    context->count[0] = context->count[1] = 0;

    /* Load magic initialization constants. */
    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;
}

/* MD5 basic transformation. Transforms state based on block.
 */
static void MD5Transform (state, block)
UINT4 state[4];
unsigned char block[64];
{
    UINT4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];

    Decode (x, block, 64);

    /* Round 1 */
    FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
    FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
    FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
    FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
    FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
    FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
    FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
    FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
    FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
    FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
    FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
    FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
    FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
    FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
    FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
    FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

    /* Round 2 */
    GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
    GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
    GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
    GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
    GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
    GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
    GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
    GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
    GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
    GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
    GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
    GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
    GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
    GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
    GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
    GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

    /* Round 3 */
    HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
    HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
    HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
    HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
    HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
    HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
    HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
    HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
    HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
    HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
    HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
    HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
    HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
    HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
    HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
    HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

    /* Round 4 */
    II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
    II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
    II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
    II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
    II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
    II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
    II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
    II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
    II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
    II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
    II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
    II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
    II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
    II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
    II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
    II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

    state[0] += a; TO32(state[0]);
    state[1] += b; TO32(state[1]);
    state[2] += c; TO32(state[2]);
    state[3] += d; TO32(state[3]);

    Zero(x, 1, x); /* Zeroize sensitive information. */
}


/* MD5 block update operation. Continues an MD5 message-digest
 * operation, processing another message block, and updating the
 * context.
 */
static void MD5Update (context, input, inputLen)
MD5_CTX *context;                                        /* context */
unsigned char *input;                                /* input block */
unsigned long inputLen;                    /* length of input block */
{
    unsigned long i, index, partLen;

    /* Compute number of bytes mod 64 */
    index = (unsigned long)((context->count[0] >> 3) & 0x3F);

    /* Update number of bits */
    if (TO32(context->count[0] += (inputLen << 3))
	< TO32(inputLen << 3))
	context->count[1]++;
    context->count[1] += (inputLen >> 29);

    partLen = 64 - index;

  /* Transform as many times as possible. */
    if (inputLen >= partLen) {
	Copy(input, &context->buffer[index], partLen, char);
	MD5Transform (context->state, context->buffer);
	
	for (i = partLen; i + 63 < inputLen; i += 64)
	    MD5Transform (context->state, &input[i]);

	index = 0;
    }
    else
	i = 0;

    /* Buffer remaining input */
    Copy(&input[i], &context->buffer[index], inputLen-i, char);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
 * the message digest and zeroizing the context.
 */
static void MD5Final (digest, context)
unsigned char digest[16];                         /* message digest */
MD5_CTX *context;                                       /* context */
{
    unsigned char bits[8];
    unsigned long index, padLen;

    /* Save number of bits */
    Encode (bits, context->count, 8);

    /* Pad out to 56 mod 64. */
    index = (unsigned long)((context->count[0] >> 3) & 0x3f);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    MD5Update (context, PADDING, padLen);

    /* Append length (before padding) */
    MD5Update (context, bits, 8);

    /* Store state in digest */
    Encode (digest, context->state, 16);

    Zero(context, 1, *context);  /* Zeroize sensitive information. */
}

static MD5_CTX* get_md5_ctx(SV* sv)
{
    if (sv_derived_from(sv, "Digest::MD5"))
	return (MD5_CTX*)SvIV(SvRV(sv));
    croak("Not a reference to a Digest::MD5 object");
}

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

static char* base64_16(unsigned char* from, char* to)
{
    static char* base64 =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned char *end = from + 16;
    unsigned char c1, c2, c3;
    char *d = to;

    while (1) {
	c1 = *from++;
	*d++ = base64[c1>>2];
	if (from == end) {
	    *d++ = base64[(c1 & 0x3) << 4];
	    break;
	}
	c2 = *from++;
	c3 = *from++;
	*d++ = base64[((c1 & 0x3) << 4) | ((c2 & 0xF0) >> 4)];
	*d++ = base64[((c2 & 0xF) << 2) | ((c3 & 0xC0) >>6)];
	*d++ = base64[c3 & 0x3F];
    }
    *d = '\0';
    return to;
}


/********************************************************************/

typedef PerlIO* InputStream;

MODULE = Digest::MD5		PACKAGE = Digest::MD5

PROTOTYPES: DISABLE

void
new(xclass)
	SV* xclass
    PREINIT:
	MD5_CTX* context;
    PPCODE:
	if (!SvROK(xclass)) {
	    char *sclass = SvPV(xclass, na);
	    New(55, context, 1, MD5_CTX);
	    ST(0) = sv_newmortal();
	    sv_setref_pv(ST(0), sclass, (void*)context);
	    SvREADONLY_on(SvRV(ST(0)));
	} else {
	    context = get_md5_ctx(xclass);
	}
        MD5Init(context);
	XSRETURN(1);

void
DESTROY(context)
	MD5_CTX* context
    CODE:
        Safefree(context);

void
add(self, ...)
	SV* self
    PREINIT:
	MD5_CTX* context = get_md5_ctx(self);
	STRLEN len;
	unsigned char *data;
	int i;
    PPCODE:
	for (i = 1; i < items; i++) {
	    data = (unsigned char *)(SvPV(ST(i), len));
	    MD5Update(context, data, len);
	}
	XSRETURN(1);  /* self */

void
addfile(self, fh)
	SV* self
	InputStream fh
    PREINIT:
	MD5_CTX* context = get_md5_ctx(self);
	char buffer[1024];
	int  n;
    CODE:
        while ( (n = PerlIO_read(fh, buffer, sizeof(buffer)))) {
	    MD5Update(context, buffer, n);
	}
	XSRETURN(1);  /* self */

SV *
digest(context)
	MD5_CTX* context
    PREINIT:
	unsigned char digeststr[16];
    CODE:
        MD5Final(digeststr, context);
	ST(0) = sv_2mortal(newSVpv((char *)digeststr, 16));

char*
hexdigest(context)
	MD5_CTX* context
    PREINIT:
	unsigned char digeststr[16];
	char hexstr[33];
    CODE:
        MD5Final(digeststr, context);
	RETVAL = hex_16(digeststr, hexstr);
    OUTPUT:
	RETVAL

char*
b64digest(context)
	MD5_CTX* context
    PREINIT:
	unsigned char digeststr[16];
        char b64str[23];
    CODE:
	MD5Final(digeststr, context);
	RETVAL = base64_16(digeststr, b64str);
    OUTPUT:
	RETVAL

SV*
md5(...)
    ALIAS:
	Digest::MD5::md5_bin    = 1
	Digest::MD5::md5_hex    = 2
	Digest::MD5::md5_base64 = 3
    PREINIT:
	MD5_CTX ctx;
	int i;
	STRLEN len;
	unsigned char *data;
	unsigned char digeststr[16];
        char result[33];
        char *str;
    PPCODE:
	MD5Init(&ctx);
	for (i = 0; i < items; i++) {
	    data = (unsigned char *)(SvPV(ST(i), len));
	    MD5Update(&ctx, data, len);
	}
	MD5Final(digeststr, &ctx);

        switch (ix) {
	case 1:
	    str = (char*)digeststr;
	    len = 16;
	    break;
	case 2:
	    str = hex_16(digeststr, result);
	    len = 32;
	    break;
	case 3:
	    str = base64_16(digeststr, result);
	    len = 22;
	    break;
	default:
	    croak("Bad md5 function index");
	    break;
	}
        ST(0) = sv_2mortal(newSVpv(str,len));
        XSRETURN(1);
