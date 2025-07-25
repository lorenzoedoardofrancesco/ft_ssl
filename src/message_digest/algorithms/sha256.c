#include "ft_ssl.h"

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

#define BSIG0(x) (ROTATE_RIGHT(x, 2)  ^ ROTATE_RIGHT(x, 13) ^ ROTATE_RIGHT(x, 22))
#define BSIG1(x) (ROTATE_RIGHT(x, 6)  ^ ROTATE_RIGHT(x, 11) ^ ROTATE_RIGHT(x, 25))
#define SSIG0(x) (ROTATE_RIGHT(x, 7)  ^ ROTATE_RIGHT(x, 18) ^ (x >> 3))
#define SSIG1(x) (ROTATE_RIGHT(x, 17) ^ ROTATE_RIGHT(x, 19) ^ (x >> 10))

#define CH(x, y, z)  ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^  (x & z) ^ (y & z))

static const uint32_t k[64] =
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void sha256(uint8_t* block_uint8, uint8_t* hash_uint8)
{
    uint32_t* block = (uint32_t*)block_uint8;
    uint32_t* hash  = (uint32_t*)hash_uint8;

    uint32_t  h1 =  hash[0], h2 =  hash[1], h3 =  hash[2], h4 =  hash[3], h5 =  hash[4], h6 =  hash[5], h7 =  hash[6], h8 =  hash[7];
    uint32_t  *a = &hash[0], *b = &hash[1], *c = &hash[2], *d = &hash[3], *e = &hash[4], *f = &hash[5], *g = &hash[6], *h = &hash[7];

    uint32_t w[64];

    for (int i = 0;  i < 16; ++i) w[i] = block[i];
    for (int i = 16; i < 64; ++i) w[i] = SSIG1(w[i - 2]) + w[i - 7] + SSIG0(w[i - 15]) + w[i - 16];

    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = *h + BSIG1(*e) + CH(*e, *f, *g) + k[i] + w[i];
        uint32_t t2 = BSIG0(*a) + MAJ(*a, *b, *c);
        *h = *g, *g = *f, *f = *e, *e = *d + t1, *d = *c, *c = *b, *b = *a, *a = t1 + t2;
    }

    *a += h1, *b += h2, *c += h3, *d += h4, *e += h5, *f += h6, *g += h7, *h += h8;
}

void sha224_seed(uint8_t* hash)
{
    uint32_t* h = (uint32_t*)hash;
    h[0] = SHA_224_H1, h[1] = SHA_224_H2, h[2] = SHA_224_H3, h[3] = SHA_224_H4, h[4] = SHA_224_H5, h[5] = SHA_224_H6, h[6] = SHA_224_H7, h[7] = SHA_224_H8;
}

void sha256_seed(uint8_t* hash)
{
    uint32_t* h = (uint32_t*)hash;
    h[0] = SHA_256_H1, h[1] = SHA_256_H2, h[2] = SHA_256_H3, h[3] = SHA_256_H4, h[4] = SHA_256_H5, h[5] = SHA_256_H6, h[6] = SHA_256_H7, h[7] = SHA_256_H8;
}

uint64_t sha256_append_length(size_t length)
{
    uint64_t length_big_endian = ((uint64_t)((uint32_t)(length & 0xFFFFFFFF)) << 32) | (uint32_t)(length >> 32);
    return length_big_endian;
}