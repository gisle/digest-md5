/* $Id$ */

/* 
 * This library is free software; you can redistribute it and/or
 * modify it under the same terms as Perl itself.
 * 
 *  Copyright 1998 Gisle Aas.
 *  Copyright 1990-1992 RSA Data Security, Inc.
 *
 * This code is derived from the reference implementation in RFC 1231
 * which comes with this message:
 *
 * Copyright (C) 1990-2, RSA Data Security, Inc. Created 1990. All
 * rights reserved.
 *
 * License to copy and use this software is granted for
 * non-commercial Internet Privacy-Enhanced Mail provided that it is
 * identified as the "RSA Data Security, Inc. MD2 Message Digest
 * Algorithm" in all material mentioning or referencing this software
 * or this function.
 *
 * RSA Data Security, Inc. makes no representations concerning either
 * the merchantability of this software or the suitability of this
 * software for any particular purpose. It is provided "as is"
 * without express or implied warranty of any kind.
 *
 * These notices must be retained in any copies of any part of this
 * documentation and/or software.

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

typedef struct {
  unsigned char state[16];                                 /* state */
  unsigned char checksum[16];                           /* checksum */
  unsigned int count;                 /* number of bytes, modulo 16 */
  unsigned char buffer[16];                         /* input buffer */
} MD2_CTX;

/* Permutation of 0..255 constructed from the digits of pi. It gives a
   "random" nonlinear byte substitution operation.
 */
static unsigned char PI_SUBST[256] = {
  41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
  19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
  76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
  138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
  245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
  148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
  39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
  181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
  150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
  112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
  96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
  85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
  234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
  129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
  8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
  203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
  166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
  31, 26, 219, 153, 141, 51, 159, 17, 131, 20
};

static unsigned char *PADDING[] = {
  (unsigned char *)"",
  (unsigned char *)"\001",
  (unsigned char *)"\002\002",
  (unsigned char *)"\003\003\003",
  (unsigned char *)"\004\004\004\004",
  (unsigned char *)"\005\005\005\005\005",
  (unsigned char *)"\006\006\006\006\006\006",
  (unsigned char *)"\007\007\007\007\007\007\007",
  (unsigned char *)"\010\010\010\010\010\010\010\010",
  (unsigned char *)"\011\011\011\011\011\011\011\011\011",
  (unsigned char *)"\012\012\012\012\012\012\012\012\012\012",
  (unsigned char *)"\013\013\013\013\013\013\013\013\013\013\013",
  (unsigned char *)"\014\014\014\014\014\014\014\014\014\014\014\014",
  (unsigned char *)
    "\015\015\015\015\015\015\015\015\015\015\015\015\015",
  (unsigned char *)
    "\016\016\016\016\016\016\016\016\016\016\016\016\016\016",
  (unsigned char *)
    "\017\017\017\017\017\017\017\017\017\017\017\017\017\017\017",
  (unsigned char *)
    "\020\020\020\020\020\020\020\020\020\020\020\020\020\020\020\020"
};


static void
MD2Init(MD2_CTX* context)
{
  Zero(context, 1, MD2_CTX);
  context->count = 0;
}

static void
MD2Transform (state, checksum, block)
unsigned char state[16];
unsigned char checksum[16];
unsigned char block[16];
{
  unsigned int i, j, t;
  unsigned char x[48];

  /* Form encryption block from state, block, state ^ block.
   */
  Copy(state, x, 16, char);
//  MD2_memcpy ((POINTER)x, (POINTER)state, 16);
  Copy(block, x+16, 16, char);
//  MD2_memcpy ((POINTER)x+16, (POINTER)block, 16);
  for (i = 0; i < 16; i++)
    x[i+32] = state[i] ^ block[i];

  /* Encrypt block (18 rounds).
   */
  t = 0;
  for (i = 0; i < 18; i++) {
    for (j = 0; j < 48; j++)
      t = x[j] ^= PI_SUBST[t];
    t = (t + i) & 0xff;
  }

  /* Save new state */
  Copy(x, state, 16, char);
//  MD2_memcpy ((POINTER)state, (POINTER)x, 16);

  /* Update checksum.
   */
  t = checksum[15];
  for (i = 0; i < 16; i++)
    t = checksum[i] ^= PI_SUBST[block[i] ^ t];

  /* Zeroize sensitive information.
   */
   Zero(x, 1, x);
//  MD2_memset ((POINTER)x, 0, sizeof (x));
}

static void
MD2Update (MD2_CTX* context, U8 *input, STRLEN inputLen)
{
  unsigned int i, index, partLen;

  /* Update number of bytes mod 16 */
  index = context->count;
  context->count = (index + inputLen) & 0xf;

  partLen = 16 - index;

  /* Transform as many times as possible.
    */
  if (inputLen >= partLen) {
//    MD2_memcpy
//      ((POINTER)&context->buffer[index], (POINTER)input, partLen);
      Copy(input, context->buffer+index, partLen, char);
    MD2Transform (context->state, context->checksum, context->buffer);

    for (i = partLen; i + 15 < inputLen; i += 16)
      MD2Transform (context->state, context->checksum, &input[i]);

    index = 0;
  }
  else
    i = 0;

  /* Buffer remaining input */
   Copy(input+i, context->buffer + index, inputLen-i, char);
//  MD2_memcpy
//    ((POINTER)&context->buffer[index], (POINTER)&input[i],
//     inputLen-i);
}

static void
MD2Final (U8* digest, MD2_CTX *context)
{
  unsigned int index, padLen;

  /* Pad out to multiple of 16.
   */
  index = context->count;
  padLen = 16 - index;
  MD2Update (context, PADDING[padLen], padLen);

  /* Extend with checksum */
  MD2Update (context, context->checksum, 16);

  /* Store state in digest */
   Copy(context->state, digest, 16, char);
//  MD2_memcpy ((POINTER)digest, (POINTER)context->state, 16);

  /* Zeroize sensitive information.
   */
   Zero(context, 1, MD2_CTX);
//  MD2_memset ((POINTER)context, 0, sizeof (*context));
    
}



static MD2_CTX* get_md2_ctx(SV* sv)
{
    if (sv_derived_from(sv, "Digest::MD2"))
	return (MD2_CTX*)SvIV(SvRV(sv));
    croak("Not a reference to a Digest::MD2 object");
}


static char* hex_16(const unsigned char* from, char* to)
{
    static char *hexdigits = "0123456789abcdef";
    const unsigned char *end = from + 16;
    char *d = to;

    while (from < end) {
	*d++ = hexdigits[(*from >> 4)];
	*d++ = hexdigits[(*from & 0x0F)];
	from++;
    }
    *d = '\0';
    return to;
}

static char* base64_16(const unsigned char* from, char* to)
{
    static char* base64 =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const unsigned char *end = from + 16;
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

/* Formats */
#define F_BIN 0
#define F_HEX 1
#define F_B64 2

static SV* make_mortal_sv(const unsigned char *src, int type)
{
    STRLEN len;
    char result[33];
    char *ret;
    
    switch (type) {
    case F_BIN:
	ret = (char*)src;
	len = 16;
	break;
    case F_HEX:
	ret = hex_16(src, result);
	len = 32;
	break;
    case F_B64:
	ret = base64_16(src, result);
	len = 22;
	break;
    default:
	croak("Bad convertion type (%d)", type);
	break;
    }
    return sv_2mortal(newSVpv(ret,len));
}


/********************************************************************/

typedef PerlIO* InputStream;

MODULE = Digest::MD2		PACKAGE = Digest::MD2

PROTOTYPES: DISABLE

void
new(xclass)
	SV* xclass
    PREINIT:
	MD2_CTX* context;
    PPCODE:
	if (!SvROK(xclass)) {
	    char *sclass = SvPV(xclass, na);
	    New(55, context, 1, MD2_CTX);
	    ST(0) = sv_newmortal();
	    sv_setref_pv(ST(0), sclass, (void*)context);
	    SvREADONLY_on(SvRV(ST(0)));
	} else {
	    context = get_md2_ctx(xclass);
	}
        MD2Init(context);
	XSRETURN(1);

void
DESTROY(context)
	MD2_CTX* context
    CODE:
        Safefree(context);

void
add(self, ...)
	SV* self
    PREINIT:
	MD2_CTX* context = get_md2_ctx(self);
	int i;
	unsigned char *data;
	STRLEN len;
    PPCODE:
	for (i = 1; i < items; i++) {
	    data = (unsigned char *)(SvPV(ST(i), len));
	    MD2Update(context, data, len);
	}
	XSRETURN(1);  /* self */

void
addfile(self, fh)
	SV* self
	InputStream fh
    PREINIT:
	MD2_CTX* context = get_md2_ctx(self);
	char buffer[4096];
	int  n;
    CODE:
	/* Process blocks until EOF */
        while ( (n = PerlIO_read(fh, buffer, sizeof(buffer)))) {
	    MD2Update(context, buffer, n);
	}
	XSRETURN(1);  /* self */

SV *
digest(context)
	MD2_CTX* context
    ALIAS:
	Digest::MD2::digest    = F_BIN
	Digest::MD2::hexdigest = F_HEX
	Digest::MD2::b64digest = F_B64
    PREINIT:
	unsigned char digeststr[16];
    PPCODE:
        MD2Final(digeststr, context);
	MD2Init(context);  /* In case it is reused */
        ST(0) = make_mortal_sv(digeststr, ix);
        XSRETURN(1);

SV*
md2(...)
    ALIAS:
	Digest::MD2::md2        = F_BIN
	Digest::MD2::md2_hex    = F_HEX
	Digest::MD2::md2_base64 = F_B64
    PREINIT:
	MD2_CTX ctx;
	int i;
	unsigned char *data;
        STRLEN len;
	unsigned char digeststr[16];
    PPCODE:
	MD2Init(&ctx);
	for (i = 0; i < items; i++) {
	    data = (unsigned char *)(SvPV(ST(i), len));
	    MD2Update(&ctx, data, len);
	}
	MD2Final(digeststr, &ctx);
        ST(0) = make_mortal_sv(digeststr, ix);
        XSRETURN(1);
