#pragma once
#include "ft_ssl.h"

typedef void (*hash_fn)(uint8_t* block, uint8_t* hash);
typedef void (*seed_fn)(uint8_t* hash);
typedef uint64_t (*append_len_fn)(size_t length);

typedef enum {
    MD5_HASH_SIZE        = 16,
    SHA224_HASH_SIZE     = 28,
    SHA256_HASH_SIZE     = 32,
    SHA384_HASH_SIZE     = 48,
    SHA512_HASH_SIZE     = 64,
    SHA512_224_HASH_SIZE = 28,
    SHA512_256_HASH_SIZE = 32,
    WHIRLPOOL_HASH_SIZE  = 64
} hash_size;

typedef struct hash_map_s
{
    const char*   name;
    hash_fn       function;
    size_t        word_size;
    size_t        block_size;
    size_t        length_field_size;
    append_len_fn append_length;
    seed_fn       hash_seed;
    uint8_t       hash[64];
    hash_size     hash_size;
    int           hash_mask;
    bool          big_endian;
    int           fd;
    size_t        length;
    size_t        bytes_read;
    size_t        i;
} hash_map;

int  message_digest(char* input, char* argv[]);

// MD5

#define MD5_WORDS_NUMBER 16
#define MD5_WORD_SIZE sizeof(uint32_t)
#define MD5_BLOCK_SIZE (MD5_WORDS_NUMBER * MD5_WORD_SIZE)
#define MD5_LENGTH_FIELD_SIZE sizeof(uint64_t)

void     md5(uint8_t* block, uint8_t* hash);
void     md5_seed(uint8_t* hash);
uint64_t md5_append_length(size_t length);

// SHA-256

#define SHA_256_WORDS_NUMBER 16
#define SHA_256_WORD_SIZE sizeof(uint32_t)
#define SHA_256_BLOCK_SIZE (SHA_256_WORDS_NUMBER * SHA_256_WORD_SIZE)
#define SHA_256_LENGTH_FIELD_SIZE sizeof(uint64_t)

void     sha256(uint8_t* block, uint8_t* hash);
void     sha224_seed(uint8_t* hash);
void     sha256_seed(uint8_t* hash);
uint64_t sha256_append_length(size_t length);

// SHA-512

#define SHA_512_WORDS_NUMBER 16
#define SHA_512_WORD_SIZE sizeof(uint64_t)
#define SHA_512_BLOCK_SIZE (SHA_512_WORDS_NUMBER * SHA_512_WORD_SIZE)
#define SHA_512_LENGTH_FIELD_SIZE sizeof(__uint128_t)

void sha512(uint8_t* block, uint8_t* hash);
void sha384_seed(uint8_t* hash);
void sha512_seed(uint8_t* hash);
void sha512_224_seed(uint8_t* hash);
void sha512_256_seed(uint8_t* hash);
uint64_t sha512_append_length(size_t length);

// Whirlpool

#define WHIRLPOOL_WORDS_NUMBER 8
#define WHIRLPOOL_WORD_SIZE sizeof(uint64_t)
#define WHIRLPOOL_BLOCK_SIZE (WHIRLPOOL_WORDS_NUMBER * WHIRLPOOL_WORD_SIZE)
#define WHIRLPOOL_LENGTH_FIELD_SIZE sizeof(__uint128_t) * 2

void     whirlpool(uint8_t* block, uint8_t* hash);
void     whirlpool_seed(uint8_t* hash);
uint64_t whirlpool_append_length(size_t length);