#include "ft_ssl.h"

static const uint64_t k[80] =
{
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

void sha512(uint8_t* block_uint8, uint8_t* hash_uint8)
{
    uint64_t* block = (uint64_t*)block_uint8;
    uint64_t* hash  = (uint64_t*)hash_uint8;

    uint64_t  h1 =  hash[0], h2 =  hash[1], h3 =  hash[2], h4 =  hash[3], h5 =  hash[4], h6 =  hash[5], h7 =  hash[6], h8 =  hash[7];
    uint64_t  *a = &hash[0], *b = &hash[1], *c = &hash[2], *d = &hash[3], *e = &hash[4], *f = &hash[5], *g = &hash[6], *h = &hash[7];

    uint64_t w[80];

    for (int i = 0;  i < 16; ++i) w[i] = block[i];
    for (int i = 16; i < 80; ++i) w[i] = SSIG1_512(w[i - 2]) + w[i - 7] + SSIG0_512(w[i - 15]) + w[i - 16];

    for (int i = 0; i < 80; ++i) {
        uint64_t t1 = *h + BSIG1_512(*e) + CH(*e, *f, *g) + k[i] + w[i];
        uint64_t t2 = BSIG0_512(*a) + MAJ(*a, *b, *c);
        *h = *g, *g = *f, *f = *e, *e = *d + t1, *d = *c, *c = *b, *b = *a, *a = t1 + t2;
    }

    *a += h1, *b += h2, *c += h3, *d += h4, *e += h5, *f += h6, *g += h7, *h += h8;
}

void sha384_hash(uint8_t* hash)
{
    uint64_t hash_seed[8] = { SHA_384_H1, SHA_384_H2, SHA_384_H3, SHA_384_H4, SHA_384_H5, SHA_384_H6, SHA_384_H7, SHA_384_H8 };
    ft_memcpy(hash, hash_seed, sizeof(hash_seed));
}

void sha512_hash(uint8_t* hash)
{
    uint64_t hash_seed[8] = { SHA_512_H1, SHA_512_H2, SHA_512_H3, SHA_512_H4, SHA_512_H5, SHA_512_H6, SHA_512_H7, SHA_512_H8 };
    ft_memcpy(hash, hash_seed, sizeof(hash_seed));
}

void sha512_224_hash(uint8_t* hash)
{
    uint64_t hash_seed[8] = { SHA_512_224_H1, SHA_512_224_H2, SHA_512_224_H3, SHA_512_224_H4, SHA_512_224_H5, SHA_512_224_H6, SHA_512_224_H7, SHA_512_224_H8 };
    ft_memcpy(hash, hash_seed, sizeof(hash_seed));
}

void sha512_256_hash(uint8_t* hash)
{
    uint64_t hash_seed[8] = { SHA_512_256_H1, SHA_512_256_H2, SHA_512_256_H3, SHA_512_256_H4, SHA_512_256_H5, SHA_512_256_H6, SHA_512_256_H7, SHA_512_256_H8 };
    ft_memcpy(hash, hash_seed, sizeof(hash_seed));
}

uint64_t sha512_append_length(size_t length) { return length; }