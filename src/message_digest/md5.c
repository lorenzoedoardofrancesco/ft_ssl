#include "ft_ssl.h"

static const uint32_t k[64] =
{
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const uint8_t r[16] =
{
    7, 12, 17, 22,
    5,  9, 14, 20,
    4, 11, 16, 23,
    6, 10, 15, 21
};

void rotate_right(uint32_t** hash)
{
    uint32_t* tmp = hash[3];
    hash[3]       = hash[2];
    hash[2]       = hash[1];
    hash[1]       = hash[0];
    hash[0]       = tmp;
}

void md5(uint8_t* block_uint8, uint8_t* hash_uint8)
{
    uint32_t* block = (uint32_t*)block_uint8;
    uint32_t* hash[4];
    for (int i = 0; i < 4; i++) {
        hash[i] = (uint32_t*)(hash_uint8 + i * sizeof(uint32_t));
    }

    uint32_t a = *hash[0], b = *hash[1], c = *hash[2], d = *hash[3];

    for (int i = 0; i < 16; ++i) {
        FF(*hash[0], *hash[1], *hash[2], *hash[3], block[i], r[i % 4], k[i]);
        rotate_right(hash);
    }
    for (int i = 16; i < 32; ++i) {
        GG(*hash[0], *hash[1], *hash[2], *hash[3], block[(5 * i + 1) % 16], r[i % 4 + 4], k[i]);
        rotate_right(hash);
    }
    for (int i = 32; i < 48; ++i) {
        HH(*hash[0], *hash[1], *hash[2], *hash[3], block[(3 * i + 5) % 16], r[i % 4 + 8], k[i]);
        rotate_right(hash);
    }
    for (int i = 48; i < 64; ++i) {
        II(*hash[0], *hash[1], *hash[2], *hash[3], block[(7 * i) % 16], r[i % 4 + 12], k[i]);
        rotate_right(hash);
    }

    *hash[0] += a, *hash[1] += b, *hash[2] += c, *hash[3] += d;
}

void md5_hash(uint8_t* hash)
{
    uint32_t hash_seed[4] = { A, B, C, D };
    ft_memcpy(hash, hash_seed, sizeof(hash_seed));
}

uint64_t md5_append_length(size_t length) { return length; }