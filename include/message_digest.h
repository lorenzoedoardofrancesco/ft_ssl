#pragma once
#include "ft_ssl.h"

typedef void (*hash_fn)(uint8_t* block, uint8_t* hash);
typedef void (*seed_fn)(uint8_t* hash);
typedef uint64_t (*append_len_fn)(size_t length);

typedef enum {
    HASH_MD5        = 16,
    HASH_SHA224     = 28,
    HASH_SHA256     = 32,
    HASH_SHA384     = 48,
    HASH_SHA512     = 64,
    HASH_SHA512_224 = 28,
    HASH_SHA512_256 = 32,
    HASH_WHIRLPOOL  = 64
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
void write_hash(uint8_t* hash, hash_size size, int x);

// MD5

#define MD5_WORDS_NUMBER 16
#define MD5_WORD_SIZE sizeof(uint32_t)
#define MD5_LENGTH_FIELD_SIZE sizeof(uint64_t)
#define MD5_BLOCK_SIZE (MD5_WORDS_NUMBER * MD5_WORD_SIZE)

void     md5(uint8_t* block, uint8_t* hash);
void     md5_hash(uint8_t* hash);
uint64_t md5_append_length(size_t length);

// SHA-256

#define SHA_256_WORDS_NUMBER 16
#define SHA_256_WORD_SIZE sizeof(uint32_t)
#define SHA_256_LENGTH_FIELD_SIZE sizeof(uint64_t)
#define SHA_256_BLOCK_SIZE (SHA_256_WORDS_NUMBER * SHA_256_WORD_SIZE)

void     sha256(uint8_t* block, uint8_t* hash);
void     sha224_hash(uint8_t* hash);
void     sha256_hash(uint8_t* hash);
uint64_t sha256_append_length(size_t length);

// SHA-512

#define SHA_512_WORDS_NUMBER 16
#define SHA_512_WORD_SIZE sizeof(uint64_t)
#define SHA_512_LENGTH_FIELD_SIZE sizeof(__uint128_t)
#define SHA_512_BLOCK_SIZE (SHA_512_WORDS_NUMBER * SHA_512_WORD_SIZE)

void sha512(uint8_t* block, uint8_t* hash);

void sha384_hash(uint8_t* hash);
void sha512_hash(uint8_t* hash);
void sha512_224_hash(uint8_t* hash);
void sha512_256_hash(uint8_t* hash);

uint64_t sha512_append_length(size_t length);

// Whirlpool

#define WHIRLPOOL_WORDS_NUMBER 8
#define WHIRLPOOL_WORD_SIZE sizeof(uint64_t)
#define WHIRLPOOL_LENGTH_FIELD_SIZE sizeof(__uint128_t) * 2
#define WHIRLPOOL_BLOCK_SIZE (WHIRLPOOL_WORDS_NUMBER * WHIRLPOOL_WORD_SIZE)

void     whirlpool(uint8_t* block, uint8_t* hash);
void     whirlpool_hash(uint8_t* hash);
uint64_t whirlpool_append_length(size_t length);