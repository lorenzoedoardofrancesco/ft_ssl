#pragma once

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>

////
#include <stdio.h>
#include <string.h>
////

/*\\\\\\\\\\       /\\\\\\\\\\\    /\\\
/\\\/////////\\\   /\\\/////////\\\ \/\\\
\//\\\      \///   \//\\\      \///  \/\\\
 \////\\\           \////\\\         \/\\\
	 \////\\\           \////\\\      \/\\\
		 \////\\\           \////\\\   \/\\\
   /\\\      \//\\\   /\\\      \//\\\  \/\\\
   \///\\\\\\\\\\\/   \///\\\\\\\\\\\/   \/\\\\\\\\\\\\\\\
	  \///////////       \///////////     \/////////////*/

#define HEX_CHARS "0123456789abcdef"

typedef enum
{
	HASH_MD5 = 4,
	HASH_SHA224 = 7,
	HASH_SHA256 = 8,
	HASH_SHA384 = 6,
	HASH_SHA512 = 8,
	HASH_SHA512_224 = 3,
	HASH_SHA512_256 = 4
} hash_size;

typedef void (*hash_function)(void **blocks, size_t num_of_blocks);

typedef struct hash_map_s
{
	const char *name;
	hash_function function;
	size_t words_number;
	size_t word_size;
	size_t length_field_size;
	uint64_t padding_byte;
} hash_map;

void write_hash(uint32_t **hash, hash_size size);
void write_hash_64(uint64_t **hash, hash_size size);

/*\\\            /\\\\   /\\\\\\\\\\\\      /\\\\\\\\\\\\\\\
\/\\\\\\        /\\\\\\  \/\\\////////\\\   \/\\\///////////
 \/\\\//\\\    /\\\//\\\  \/\\\      \//\\\  \/\\\
  \/\\\\///\\\/\\\/ \/\\\  \/\\\       \/\\\  \/\\\\\\\\\\\\
   \/\\\  \///\\\/   \/\\\  \/\\\       \/\\\  \////////////\\\
	\/\\\    \///     \/\\\  \/\\\       \/\\\             \//\\\
	 \/\\\             \/\\\  \/\\\       /\\\   /\\\        \/\\\
	  \/\\\             \/\\\  \/\\\\\\\\\\\\/   \//\\\\\\\\\\\\\/
	   \///              \///   \////////////      \///////////*/

#define MD5_WORDS_NUMBER		16
#define MD5_WORD_SIZE			sizeof(uint32_t)
#define MD5_LENGTH_FIELD_SIZE	sizeof(uint64_t)
#define MD5_PADDING_BYTE		0x80

#define A 0x67452301
#define B 0xefcdab89
#define C 0x98badcfe
#define D 0x10325476

#define F(x, y, z) ((x & y) | (~x & z))
#define G(x, y, z) ((x & z) | (y & ~z))
#define H(x, y, z) (x ^ y ^ z)
#define I(x, y, z) (y ^ (x | ~z))

#define ROTATE_LEFT(x, n) ((x << n) | (x >> (32 - n)))

#define FF(a, b, c, d, x, s, ac)  \
	{                             \
		a += F(b, c, d) + x + ac; \
		a = ROTATE_LEFT(a, s);    \
		a += b;                   \
	}

#define GG(a, b, c, d, x, s, ac)  \
	{                             \
		a += G(b, c, d) + x + ac; \
		a = ROTATE_LEFT(a, s);    \
		a += b;                   \
	}

#define HH(a, b, c, d, x, s, ac)  \
	{                             \
		a += H(b, c, d) + x + ac; \
		a = ROTATE_LEFT(a, s);    \
		a += b;                   \
	}

#define II(a, b, c, d, x, s, ac)  \
	{                             \
		a += I(b, c, d) + x + ac; \
		a = ROTATE_LEFT(a, s);    \
		a += b;                   \
	}

void md5(void **blocks, size_t num_of_blocks);

/*\\\\\\\\\\    /\\\        /\\\     /\\\\\\\\\
/\\\/////////\\\ \/\\\       \/\\\   /\\\\\\\\\\\\\
\//\\\      \///  \/\\\       \/\\\  /\\\/////////\\\
 \////\\\          \/\\\\\\\\\\\\\\\ \/\\\       \/\\\
	 \////\\\       \/\\\/////////\\\ \/\\\\\\\\\\\\\\\
		 \////\\\    \/\\\       \/\\\ \/\\\/////////\\\
   /\\\      \//\\\   \/\\\       \/\\\ \/\\\       \/\\\
   \///\\\\\\\\\\\/    \/\\\       \/\\\ \/\\\       \/\\\
	  \///////////      \///        \///  \///        \///

		/\\\\\\\\\       /\\\\\\\\\\\\\\\             /\\\\\
	   /\\\///////\\\    \/\\\///////////          /\\\\////
	   \///      \//\\\   \/\\\                  /\\\///
				  /\\\/    \/\\\\\\\\\\\\       /\\\\\\\\\\\
				/\\\//      \////////////\\\    /\\\\///////\\\
			  /\\\//                    \//\\\  \/\\\      \//\\\
			 /\\\/            /\\\        \/\\\  \//\\\      /\\\
			 /\\\\\\\\\\\\\\\ \//\\\\\\\\\\\\\/    \///\\\\\\\\\/
			 \///////////////   \/////////////        \///////*/

#define SHA_256_WORDS_NUMBER		16
#define SHA_256_WORD_SIZE			sizeof(uint32_t)
#define SHA_256_LENGTH_FIELD_SIZE	sizeof(uint64_t)
#define SHA_256_PADDING_BYTE		0x80000000

#define SHA_224_H1 0xc1059ed8
#define SHA_224_H2 0x367cd507
#define SHA_224_H3 0x3070dd17
#define SHA_224_H4 0xf70e5939
#define SHA_224_H5 0xffc00b31
#define SHA_224_H6 0x68581511
#define SHA_224_H7 0x64f98fa7
#define SHA_224_H8 0xbefa4fa4

#define SHA_256_H1 0x6a09e667
#define SHA_256_H2 0xbb67ae85
#define SHA_256_H3 0x3c6ef372
#define SHA_256_H4 0xa54ff53a
#define SHA_256_H5 0x510e527f
#define SHA_256_H6 0x9b05688c
#define SHA_256_H7 0x1f83d9ab
#define SHA_256_H8 0x5be0cd19

#define ROTATE_RIGHT(x, n) ((x >> n) | (x << (32 - n)))

#define CH(x, y, z) ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define BSIG0(x) (ROTATE_RIGHT(x, 2) ^ ROTATE_RIGHT(x, 13) ^ ROTATE_RIGHT(x, 22))
#define BSIG1(x) (ROTATE_RIGHT(x, 6) ^ ROTATE_RIGHT(x, 11) ^ ROTATE_RIGHT(x, 25))
#define SSIG0(x) (ROTATE_RIGHT(x, 7) ^ ROTATE_RIGHT(x, 18) ^ (x >> 3))
#define SSIG1(x) (ROTATE_RIGHT(x, 17) ^ ROTATE_RIGHT(x, 19) ^ (x >> 10))

void sha224(void **blocks, size_t num_of_blocks);
void sha256(void **blocks, size_t num_of_blocks);

/*\\\\\\\\\\    /\\\        /\\\     /\\\\\\\\\
/\\\/////////\\\ \/\\\       \/\\\   /\\\\\\\\\\\\\
\//\\\      \///  \/\\\       \/\\\  /\\\/////////\\\
 \////\\\          \/\\\\\\\\\\\\\\\ \/\\\       \/\\\
	 \////\\\       \/\\\/////////\\\ \/\\\\\\\\\\\\\\\
		 \////\\\    \/\\\       \/\\\ \/\\\/////////\\\
   /\\\      \//\\\   \/\\\       \/\\\ \/\\\       \/\\\
   \///\\\\\\\\\\\/    \/\\\       \/\\\ \/\\\       \/\\\
	  \///////////      \///        \///  \///        \///

	   /\\\\\\\\\\\\\\\      /\\\    /\\\\\\\\\     
	   \/\\\///////////    /\\\\\\\  /\\\///////\\\   
	    \/\\\              \/////\\\ \///      \//\\\  
         \/\\\\\\\\\\\\         \/\\\           /\\\/   
	      \////////////\\\       \/\\\        /\\\//     
	                  \//\\\      \/\\\     /\\\//        
	        /\\\        \/\\\      \/\\\   /\\\/           
	        \//\\\\\\\\\\\\\/       \/\\\  /\\\\\\\\\\\\\\\ 
		      \/////////////         \///  \/////////////*/

#define SHA_512_WORDS_NUMBER		16
#define SHA_512_WORD_SIZE			sizeof(uint64_t)
#define SHA_512_LENGTH_FIELD_SIZE	sizeof(__int128_t)
#define SHA_512_PADDING_BYTE		0x8000000000000000

#define SHA_384_H1 0xcbbb9d5dc1059ed8
#define SHA_384_H2 0x629a292a367cd507
#define SHA_384_H3 0x9159015a3070dd17
#define SHA_384_H4 0x152fecd8f70e5939
#define SHA_384_H5 0x67332667ffc00b31
#define SHA_384_H6 0x8eb44a8768581511
#define SHA_384_H7 0xdb0c2e0d64f98fa7
#define SHA_384_H8 0x47b5481dbefa4fa4

#define SHA_512_H1 0x6a09e667f3bcc908
#define SHA_512_H2 0xbb67ae8584caa73b
#define SHA_512_H3 0x3c6ef372fe94f82b
#define SHA_512_H4 0xa54ff53a5f1d36f1
#define SHA_512_H5 0x510e527fade682d1
#define SHA_512_H6 0x9b05688c2b3e6c1f
#define SHA_512_H7 0x1f83d9abfb41bd6b
#define SHA_512_H8 0x5be0cd19137e2179

#define SHA_512_224_H1 0x8c3d37c819544da2
#define SHA_512_224_H2 0x73e1996689dcd4d6
#define SHA_512_224_H3 0x1dfab7ae32ff9c82
#define SHA_512_224_H4 0x679dd514582f9fcf
#define SHA_512_224_H5 0x0f6d2b697bd44da8
#define SHA_512_224_H6 0x77e36f7304c48942
#define SHA_512_224_H7 0x3f9d85a86a1d36c8
#define SHA_512_224_H8 0x1112e6ad91d692a1

#define SHA_512_256_H1 0x22312194fc2bf72c
#define SHA_512_256_H2 0x9f555fa3c84c64c2
#define SHA_512_256_H3 0x2393b86b6f53b151
#define SHA_512_256_H4 0x963877195940eabd
#define SHA_512_256_H5 0x96283ee2a88effe3
#define SHA_512_256_H6 0xbe5e1e2553863992
#define SHA_512_256_H7 0x2b0199fc2c85b8aa
#define SHA_512_256_H8 0x0eb72ddc81c52ca2

#define ROTATE_RIGHT_64(x, n) ((x >> n) | (x << (64 - n)))

#define BSIG0_512(x) (ROTATE_RIGHT_64(x, 28) ^ ROTATE_RIGHT_64(x, 34) ^ ROTATE_RIGHT_64(x, 39))
#define BSIG1_512(x) (ROTATE_RIGHT_64(x, 14) ^ ROTATE_RIGHT_64(x, 18) ^ ROTATE_RIGHT_64(x, 41))
#define SSIG0_512(x) (ROTATE_RIGHT_64(x, 1) ^ ROTATE_RIGHT_64(x, 8) ^ (x >> 7))
#define SSIG1_512(x) (ROTATE_RIGHT_64(x, 19) ^ ROTATE_RIGHT_64(x, 61) ^ (x >> 6))

void sha384(void **blocks, size_t num_of_blocks);
void sha512(void **blocks, size_t num_of_blocks);
void sha512_224(void **blocks, size_t num_of_blocks);
void sha512_256(void **blocks, size_t num_of_blocks);










// message_digest.c
void process_hash(const char *input, const char *hash_name);

// utils.c
size_t strlen(const char *s);