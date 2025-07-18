#pragma once
#include "ft_ssl.h"

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

typedef void (*hash_fn)(uint8_t* block, uint8_t* hash);
typedef void (*seed_fn)(uint8_t* hash);
typedef uint64_t (*append_len_fn)(size_t length);

typedef struct hash_map_s
{
    const char*   algorithm_name;      // Name of the hash algorithm (e.g., "SHA-256")

    hash_size     output_size;         // Size of the final hash output (in bytes)
    size_t        word_size_bytes;     // Size of the internal word used by the algorithm (in bytes)
    size_t        block_size_bytes;    // Size of each data block processed (in bytes)
    size_t        length_field_bytes;  // Size of the length field appended during padding (in bytes)
    
    hash_fn       compute_hash_fn;     // Function pointer to the main hash computation function
    seed_fn       init_seed_fn;        // Function pointer to the seed initialization function
    append_len_fn append_length_fn;    // Function pointer to function that appends length during finalization

    int           hash_bitmask;        // Bitmask applied during certain hash operations (e.g., masking hash bits)
    bool          is_big_endian;       // Endianness flag — true if big-endian, false if little-endian

    uint8_t       digest[64];          // Buffer to store the resulting hash (digest)
    int           input_fd;            // File descriptor for the input data source (e.g., open file or stdin)
    size_t        total_length;        // Total length of the input data (in bytes)
    size_t        bytes_processed;     // Number of bytes processed so far
    size_t        buffer_index;        // Current index within the internal buffer for processing
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