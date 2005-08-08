#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <time.h>
#include <stdlib.h>
#include <stdint.h>

/* NIST Secure Hash Algorithm */
/* heavily modified by Uwe Hollerbach <uh@alumni.caltech edu> */
/* from Peter C. Gutmann's implementation as found in */
/* Applied Cryptography by Bruce Schneier */
/* Further modifications to include the "UNRAVEL" stuff, below */

/* This code is in the public domain */

/* pcg: I was tempted to just rip this code off, after all, if you don't
 * demand anything I am inclined not to give anything. *Sigh* something
 * kept me from doing it, so here's the truth: I took this code from the
 * SHA1 perl module, since it looked reasonably well-crafted. I modified
 * it here and there, though.
 */

/*
 * we have lots of micro-optimizations here, this is just for toying
 * around...
 */

/* don't expect _too_ much from compilers for now. */
#if __GNUC__ > 2
#  define restrict __restrict__
#  define inline __inline__
#  ifdef __i386
#     define GCCX86ASM 1
#  endif
#elif __STDC_VERSION__ < 199900
#  define restrict
#  define inline
#endif

#if __GNUC__ < 2
#  define __attribute__(x)
#endif

#ifdef __i386
#  define a_regparm(n) __attribute__((__regparm__(n)))
#else
#  define a_regparm(n)
#endif

#define a_const __attribute__((__const__))

/* Useful defines & typedefs */

#if defined(U64TYPE) && (defined(USE_64_BIT_INT) || ((BYTEORDER != 0x1234) && (BYTEORDER != 0x4321)))
typedef U64TYPE ULONG;
#  if BYTEORDER == 0x1234
#    undef BYTEORDER
#    define BYTEORDER 0x12345678
#  elif BYTEORDER == 0x4321
#    undef BYTEORDER
#    define BYTEORDER 0x87654321   
#  endif
#else
typedef uint_fast32_t ULONG;     /* 32-or-more-bit quantity */
#endif

#if GCCX86ASM
#  define zprefix(n) ({ int _r; __asm__ ("bsrl %1, %0" : "=r" (_r) : "r" (n)); 31 - _r ; })
#elif __GNUC__ > 2 && __GNUC_MINOR__ > 3
#  define zprefix(n) (__extension__ ({ uint32_t n__ = (n); n ? __builtin_clz (n) : 32; }))
#else
static int a_const zprefix (ULONG n)
{
  static char zp[256] =
    {
      8, 7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4,
      3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
      2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
      2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    };

  return
    n > 0xffffff ?      zp[n >> 24]
    : n > 0xffff ?  8 + zp[n >> 16]
    : n >   0xff ? 16 + zp[n >>  8]
    :              24 + zp[n];
}
#endif

#define SHA_BLOCKSIZE		64
#define SHA_DIGESTSIZE		20

typedef struct {
    ULONG digest[5];		/* message digest */
    ULONG count;		/* 32-bit bit count */
    int local;			/* unprocessed amount in data */
    U8 data[SHA_BLOCKSIZE];	/* SHA data buffer */
} SHA_INFO;


/* SHA f()-functions */
#define f1(x,y,z)	((x & y) | (~x & z))
#define f2(x,y,z)	(x ^ y ^ z)
#define f3(x,y,z)	((x & y) | (x & z) | (y & z))
#define f4(x,y,z)	(x ^ y ^ z)

/* SHA constants */
#define CONST1		0x5a827999L
#define CONST2		0x6ed9eba1L
#define CONST3		0x8f1bbcdcL
#define CONST4		0xca62c1d6L

/* truncate to 32 bits -- should be a null op on 32-bit machines */
#define T32(x)	((x) & 0xffffffffL)

/* 32-bit rotate */
#define R32(x,n)	T32(((x << n) | (x >> (32 - n))))

/* specific cases, for when the overall rotation is unraveled */
#define FA(n)	\
    T = T32(R32(A,5) + f##n(B,C,D) + E + *WP++ + CONST##n); B = R32(B,30)

#define FB(n)	\
    E = T32(R32(T,5) + f##n(A,B,C) + D + *WP++ + CONST##n); A = R32(A,30)

#define FC(n)	\
    D = T32(R32(E,5) + f##n(T,A,B) + C + *WP++ + CONST##n); T = R32(T,30)

#define FD(n)	\
    C = T32(R32(D,5) + f##n(E,T,A) + B + *WP++ + CONST##n); E = R32(E,30)

#define FE(n)	\
    B = T32(R32(C,5) + f##n(D,E,T) + A + *WP++ + CONST##n); D = R32(D,30)

#define FT(n)	\
    A = T32(R32(B,5) + f##n(C,D,E) + T + *WP++ + CONST##n); C = R32(C,30)

static void a_regparm(1) sha_transform(SHA_INFO *restrict sha_info)
{
    int i;
    U8 *restrict dp;
    ULONG T, A, B, C, D, E, W[80], *restrict WP;

    dp = sha_info->data;

#if BYTEORDER == 0x1234
    assert(sizeof(ULONG) == 4);
#  ifdef HAS_NTOHL
    for (i = 0; i < 16; ++i) {
	T = *((ULONG *) dp);
	dp += 4;
        W[i] = ntohl (T);
    }
#  else
    for (i = 0; i < 16; ++i) {
	T = *((ULONG *) dp);
	dp += 4;
	W[i] =  ((T << 24) & 0xff000000) | ((T <<  8) & 0x00ff0000) |
		((T >>  8) & 0x0000ff00) | ((T >> 24) & 0x000000ff);
    }
#  endif
#elif BYTEORDER == 0x4321
    assert(sizeof(ULONG) == 4);
    for (i = 0; i < 16; ++i) {
	T = *((ULONG *) dp);
	dp += 4;
	W[i] = T32(T);
    }
#elif BYTEORDER == 0x12345678
    assert(sizeof(ULONG) == 8);
    for (i = 0; i < 16; i += 2) {
	T = *((ULONG *) dp);
	dp += 8;
	W[i] =  ((T << 24) & 0xff000000) | ((T <<  8) & 0x00ff0000) |
		((T >>  8) & 0x0000ff00) | ((T >> 24) & 0x000000ff);
	T >>= 32;
	W[i+1] = ((T << 24) & 0xff000000) | ((T <<  8) & 0x00ff0000) |
		 ((T >>  8) & 0x0000ff00) | ((T >> 24) & 0x000000ff);
    }
#elif BYTEORDER == 0x87654321
    assert(sizeof(ULONG) == 8);
    for (i = 0; i < 16; i += 2) {
	T = *((ULONG *) dp);
	dp += 8;
	W[i] = T32(T >> 32);
	W[i+1] = T32(T);
    }
#else
#error Unknown byte order -- you need to add code here
#endif

    for (i = 16; i < 80; ++i)
      {
        T = W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16];
        W[i] = R32(T,1);
      }

    A = sha_info->digest[0];
    B = sha_info->digest[1];
    C = sha_info->digest[2];
    D = sha_info->digest[3];
    E = sha_info->digest[4];

    WP = W;
    FA(1); FB(1); FC(1); FD(1); FE(1); FT(1); FA(1); FB(1); FC(1); FD(1);
    FE(1); FT(1); FA(1); FB(1); FC(1); FD(1); FE(1); FT(1); FA(1); FB(1);
    FC(2); FD(2); FE(2); FT(2); FA(2); FB(2); FC(2); FD(2); FE(2); FT(2);
    FA(2); FB(2); FC(2); FD(2); FE(2); FT(2); FA(2); FB(2); FC(2); FD(2);
    FE(3); FT(3); FA(3); FB(3); FC(3); FD(3); FE(3); FT(3); FA(3); FB(3);
    FC(3); FD(3); FE(3); FT(3); FA(3); FB(3); FC(3); FD(3); FE(3); FT(3);
    FA(4); FB(4); FC(4); FD(4); FE(4); FT(4); FA(4); FB(4); FC(4); FD(4);
    FE(4); FT(4); FA(4); FB(4); FC(4); FD(4); FE(4); FT(4); FA(4); FB(4);

    sha_info->digest[0] = T32(sha_info->digest[0] + E);
    sha_info->digest[1] = T32(sha_info->digest[1] + T);
    sha_info->digest[2] = T32(sha_info->digest[2] + A);
    sha_info->digest[3] = T32(sha_info->digest[3] + B);
    sha_info->digest[4] = T32(sha_info->digest[4] + C);
}

/* initialize the SHA digest */

static void sha_init(SHA_INFO *restrict sha_info)
{
    sha_info->digest[0] = 0x67452301L;
    sha_info->digest[1] = 0xefcdab89L;
    sha_info->digest[2] = 0x98badcfeL;
    sha_info->digest[3] = 0x10325476L;
    sha_info->digest[4] = 0xc3d2e1f0L;
    sha_info->count = 0L;
    sha_info->local = 0;
}

/* update the SHA digest */

static void sha_update(SHA_INFO *restrict sha_info, U8 *restrict buffer, int count)
{
    int i;

    sha_info->count += count;
    if (sha_info->local) {
	i = SHA_BLOCKSIZE - sha_info->local;
	if (i > count) {
	    i = count;
	}
	memcpy(((U8 *) sha_info->data) + sha_info->local, buffer, i);
	count -= i;
	buffer += i;
	sha_info->local += i;
	if (sha_info->local == SHA_BLOCKSIZE) {
	    sha_transform(sha_info);
	} else {
	    return;
	}
    }
    while (count >= SHA_BLOCKSIZE) {
	memcpy(sha_info->data, buffer, SHA_BLOCKSIZE);
	buffer += SHA_BLOCKSIZE;
	count -= SHA_BLOCKSIZE;
	sha_transform(sha_info);
    }
    memcpy(sha_info->data, buffer, count);
    sha_info->local = count;
}

/* finish computing the SHA digest */
static int sha_final(SHA_INFO *sha_info)
{
  int count = sha_info->count;
  int local = sha_info->local;

  sha_info->data[local] = 0x80;

  if (sha_info->local >= SHA_BLOCKSIZE - 8) {
    memset(sha_info->data + local + 1, 0, SHA_BLOCKSIZE - 1 - local);
    sha_transform(sha_info);
    memset(sha_info->data, 0, SHA_BLOCKSIZE - 2);
  } else {
    memset(sha_info->data + local + 1, 0, SHA_BLOCKSIZE - 3 - local);
  }

  sha_info->data[62] = count >> 5;
  sha_info->data[63] = count << 3;

  sha_transform (sha_info);

  return sha_info->digest[0]
           ? zprefix (sha_info->digest[0])
           : zprefix (sha_info->digest[1]) + 32;
}

#define TRIALCHAR "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"

/* sizeof includes \0 */
#define TRIALLEN ( sizeof (TRIALCHAR) -1 ) 

static char       nextenc[256];

/* on machines that have /dev/urandom -- use it */

#if defined( __linux__ ) || defined( __FreeBSD__ ) || defined( __MACH__ ) || \
    defined( __OpenBSD__ ) || defined( DEV_URANDOM )

#define URANDOM_FILE "/dev/urandom"
FILE* urandom = NULL;
int initialized = 0;

int random_init( void )
{
    int res = (urandom = fopen( URANDOM_FILE, "r" )) != NULL;
    if ( res ) { initialized = 1; }
    return res;
}

int random_getbytes( void* data, size_t len )
{
    if ( !initialized && !random_init() ) { return 0; }
    return fread( data, len, 1, urandom );
}

int random_final( void )
{
    int res = 0;
    if ( urandom ) { res = (fclose( urandom ) == 0); }
    return res;
}

#else

#if defined( unix ) || defined( VMS )
    #include <unistd.h>
    #include <sys/time.h>
#elif defined( WIN32 )
    #include <process.h>
    #include <windows.h>
    #include <wincrypt.h>
    #include <sys/time.h>
#else
    #include <time.h>
#endif
#include <time.h>

#if defined( WIN32 )
    #define pid_t int
    typedef BOOL (WINAPI *CRYPTACQUIRECONTEXT)(HCRYPTPROV *, LPCTSTR, LPCTSTR,
					       DWORD, DWORD);
    typedef BOOL (WINAPI *CRYPTGENRANDOM)(HCRYPTPROV, DWORD, BYTE *);
    typedef BOOL (WINAPI *CRYPTRELEASECONTEXT)(HCRYPTPROV, DWORD);
    HCRYPTPROV hProvider = 0;
    CRYPTRELEASECONTEXT release = 0;
    CRYPTGENRANDOM gen = 0;
#endif

#define byte unsigned char

byte state[ SHA1_DIGEST_BYTES ];
byte output[ SHA1_DIGEST_BYTES ];
long counter = 0;
int left = 0;

/* output = SHA1( input || time || pid || counter++ ) */

static void random_stir( const byte input[SHA1_DIGEST_BYTES],
			 byte output[SHA1_DIGEST_BYTES] )
{
    SHA1_ctx sha1;
#if defined(__unix__) || defined(WIN32)
    pid_t pid = getpid();
#else
    unsigned long pid = rand();
#endif
    NVTime nvtime = get_nvtime ();
    NV timer;
#if defined(WIN32)
    SYSTEMTIME tw;
    BYTE buf[64];
#endif
    clock_t t = clock();
    time_t t2 = time(0);

    SHA1_Init( &sha1 );
#if defined(__unix__)
    gettimeofday(&tv,&tz);
    SHA1_Update( &sha1, &tv, sizeof( tv ) );
    SHA1_Update( &sha1, &tz, sizeof( tz ) );
#elif defined(WIN32)
    GetSystemTime(&tw);
    SHA1_Update( &sha1, &tw, sizeof( tw ) );    
    if ( gen ) {
	if (gen(hProvider, sizeof(buf), buf)) {
	    SHA1_Update( &sha1, buf, sizeof(buf) );
	}
    }
#endif
    SHA1_Update( &sha1, input, SHA1_DIGEST_BYTES );
    SHA1_Update( &sha1, &t, sizeof( clock_t ) );
    SHA1_Update( &sha1, &t2, sizeof( time_t ) );
    SHA1_Update( &sha1, &pid, sizeof( pid ) );
    SHA1_Update( &sha1, &counter, sizeof( long ) );

    SHA1_Final( &sha1, output );
    counter++;
}

byte rand_pool[SHA1_DIGEST_BYTES];

int random_getbytes( void* data, size_t len )
{
    char* dptr = data;
    int use;
    while ( left < len ) {
	if ( left == 0 ) {
	    random_stir( rand_pool, rand_pool );
	}
	use = MIN( left, len );
	memcpy( dptr, rand_pool+SHA1_DIGEST_BYTES-left, use );
	left -= use;
	len -= use;
    }
    return 1;
}
#endif

static char rand_char ()
{
    char b;
    random_getbytes( &b, 1 );
    return TRIALCHAR[b % TRIALLEN];
}

typedef double (*NVTime)(void);

static double simple_nvtime (void)
{
  return time (0);
}

static NVTime get_nvtime (void)
{
  SV **svp = hv_fetch (PL_modglobal, "Time::NVtime", 12, 0);

  if (svp && SvIOK(*svp))
    return INT2PTR(NVTime, SvIV(*svp));
  else
    return simple_nvtime;

}

MODULE = Digest::Hashcash		PACKAGE = Digest::Hashcash

BOOT:
{
   int i;

   for (i = 0; i < TRIALLEN; i++)
     nextenc[TRIALCHAR[i]] = TRIALCHAR[(i + 1) % TRIALLEN];
}

PROTOTYPES: ENABLE

# could be improved quite a bit in accuracy
NV
_estimate_rounds ()
	CODE:
{
        char data[40];
        NVTime nvtime = get_nvtime ();
        NV t1, t2, t;
        int count = 0;
        SHA_INFO ctx;

        t = nvtime ();
        do {
          t1 = nvtime ();
        } while (t == t1);

        t = t2 = nvtime ();
        do {
          volatile int i;
          sha_init (&ctx);
          sha_update (&ctx, data, sizeof (data));
          i = sha_final (&ctx);

          if (!(++count & 1023))
            t2 = nvtime ();

        } while (t == t2);

        RETVAL = (NV)count / (t2 - t1);
}
        OUTPUT:
        RETVAL

SV *
_gentoken (int size, int vers, IV timestamp, char *resource, char* extension = "", char *trial = "", int extrarand = 0)
	CODE:
{
        SHA_INFO ctx1, ctx;
        char *token, *seq, *s;
        int toklen, i, j;
        time_t tstamp = timestamp ? timestamp : time (0);
        struct tm *tm = gmtime (&tstamp);

	if ( vers == 0 ) {
          New (0, token,
               1 + 1                    // version
               + 12 + 1                 // time field sans century
               + strlen (resource) + 1  // ressource
               + strlen (trial) + extrarand + 8 + 1 // trial
               + 1,
               char);
	} else if ( vers == 1 ) {
          New (0, token,
               1 + 1                    // version
	       + ((size > 9) ? 2 : 1) + 1 // bits
               + 12 + 1                 // time field sans century
               + strlen (resource) + 1  // resource
	       + strlen (extension) + 1 // extension
               + strlen (trial) + extrarand + 12 + 1 // trial
	       + 16 + 1 		// count
               + 1,
               char);
	} else {
	  croak ("unsupported version");
	}

        if (!token)
          croak ("out of memory");

        if (size > 64)
          croak ("size must be <= 64 in this implementation\n");

      again:  /* try again */
	if ( vers == 0 ) { 
          toklen = sprintf (token, "%d:%02d%02d%02d%02d%02d%02d:%s:%s",
                          0, tm->tm_year % 100, tm->tm_mon + 1, tm->tm_mday,
                          tm->tm_hour, tm->tm_min, tm->tm_sec,
                          resource, trial);
	} else {
          toklen = sprintf (token,"%d:%d:%02d%02d%02d%02d%02d%02d:%s:%s:%s",
                          1, size, tm->tm_year % 100, tm->tm_mon + 1, 
			  tm->tm_mday,tm->tm_hour, tm->tm_min, tm->tm_sec,
                          resource, extension, trial);
        }

        if (toklen > 8000)
          croak ("token length must be <= 8000 in this implementation\n");

        i = toklen + extrarand;
        while (toklen < i)
          token[toklen++] = rand_char ();

	if ( vers == 1 ) {
	  i +=  16;
          while (toklen < i)
            token[toklen++] = rand_char ();
	  token[toklen++] = ':';
	}

        sha_init (&ctx1);
        sha_update (&ctx1, token, toklen);

        seq = token + toklen;
        if ( vers == 0 ) {
          i += 16;
          while (toklen < i)
            token[toklen++] = rand_char ();

          for (;;)
            {  // this "optimization" can help a lot for longer resource strings
              ctx = ctx1; 
              sha_update (&ctx, seq, 16);
              i = sha_final (&ctx);

              if (i >= size)
		goto done;

              s = seq;
              do {
                *s = nextenc [*s];
              } while (*s++ == 'a');
            }
        } else {
	  for ( j = 1; j <= 12; j++ ) 
            {
	      memset (seq, 'a', j);
	      seq[j] = '\0';
	      s = seq+j-1;
	      for ( ; s-seq >= 0; ) {
		s = seq+j-1;
		ctx = ctx1;
	        sha_update (&ctx, seq, j);
	        i = sha_final (&ctx);
		
		if (i >= size) { 
		  toklen += j;
		  goto done; 
		}

		do {
		  *s = nextenc [*s];
		} while ( *s == 'a' && s-- && s-seq >=0 );
	      }
            }
	  goto again;
        }
      done:
        RETVAL = newSVpvn (token, toklen);
}
	OUTPUT:
        RETVAL

int
_prefixlen (SV *tok)
	CODE:
{
        STRLEN toklen;
        char *token = SvPV (tok, toklen);
        SHA_INFO ctx;

        sha_init (&ctx);
        sha_update (&ctx, token, toklen);
        RETVAL = sha_final (&ctx);
}
	OUTPUT:
	RETVAL
