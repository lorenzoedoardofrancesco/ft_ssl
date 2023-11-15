#pragma once

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>

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

typedef struct ft_ssl
{
	char *input;
	size_t input_len;
	size_t num_of_blocks;
	uint32_t **blocks;

	uint32_t arg;
} ssl;

typedef enum
{
	HASH_MD5 = 4,
	HASH_SHA256 = 8
} hash_size;

void write_hash(uint32_t **hash, hash_size size);

/*\\\            /\\\\   /\\\\\\\\\\\\      /\\\\\\\\\\\\\\\
\/\\\\\\        /\\\\\\  \/\\\////////\\\   \/\\\///////////
 \/\\\//\\\    /\\\//\\\  \/\\\      \//\\\  \/\\\
  \/\\\\///\\\/\\\/ \/\\\  \/\\\       \/\\\  \/\\\\\\\\\\\\
   \/\\\  \///\\\/   \/\\\  \/\\\       \/\\\  \////////////\\\
	\/\\\    \///     \/\\\  \/\\\       \/\\\             \//\\\
	 \/\\\             \/\\\  \/\\\       /\\\   /\\\        \/\\\
	  \/\\\             \/\\\  \/\\\\\\\\\\\\/   \//\\\\\\\\\\\\\/
	   \///              \///   \////////////      \///////////*/

#define MD5_BLOCK_SIZE 64		//	512 bits | sizeof(uint32_t) * 16 words
#define MD5_WORD_SIZE 4			//	 32 bits | sizeof(uint32_t)
#define MD5_MIN_PADDING_SIZE 1	//	  8 bits | sizeof(uint8_t)
#define MD5_LENGTH_FIELD_SIZE 8 //	 64 bits | sizeof(uint64_t)

#define MD5_WORDS_NUMBER 16 //	 MD5_BLOCK_SIZE / MD5_WORD_SIZE

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

void md5(ssl *ssl);

 /*\\\\\\\\\\    /\\\        /\\\     /\\\\\\\\\
/\\\/////////\\\ \/\\\       \/\\\   /\\\\\\\\\\\\\
\//\\\      \///  \/\\\       \/\\\  /\\\/////////\\\
 \////\\\          \/\\\\\\\\\\\\\\\ \/\\\       \/\\\
	 \////\\\       \/\\\/////////\\\ \/\\\\\\\\\\\\\\\
		 \////\\\    \/\\\       \/\\\ \/\\\/////////\\\
   /\\\      \//\\\   \/\\\       \/\\\ \/\\\       \/\\\
   \///\\\\\\\\\\\/    \/\\\       \/\\\ \/\\\       \/\\\
	  \///////////      \///        \///  \///        \/*/

#define H1 0x6a09e667
#define H2 0xbb67ae85
#define H3 0x3c6ef372
#define H4 0xa54ff53a
#define H5 0x510e527f
#define H6 0x9b05688c
#define H7 0x1f83d9ab
#define H8 0x5be0cd19

#define ROTATE_RIGHT(x, n) ((x >> n) | (x << (32 - n)))

#define CH(x, y, z) ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define BSIG0(x) (ROTATE_RIGHT(x, 2) ^ ROTATE_RIGHT(x, 13) ^ ROTATE_RIGHT(x, 22))
#define BSIG1(x) (ROTATE_RIGHT(x, 6) ^ ROTATE_RIGHT(x, 11) ^ ROTATE_RIGHT(x, 25))
#define SSIG0(x) (ROTATE_RIGHT(x, 7) ^ ROTATE_RIGHT(x, 18) ^ (x >> 3))
#define SSIG1(x) (ROTATE_RIGHT(x, 17) ^ ROTATE_RIGHT(x, 19) ^ (x >> 10))

void sha256(ssl *ssl);