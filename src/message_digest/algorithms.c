#include "message_digest.h"

#define HASH_ENTRY(name, u_name, hsize, wsize, bsize, lsize, hash_fn, seed_fn, append_len_fn, mask, be) \
    { name, u_name, hsize, wsize, bsize, lsize, hash_fn, seed_fn, append_len_fn, mask, be, { 0 }, 0, 0, 1, 0 }

static hash_map algorithms[] = {
    HASH_ENTRY("md5",        "MD5",        MD5_HASH_SIZE,        MD5_WORD_SIZE,       MD5_BLOCK_SIZE,       MD5_LENGTH_FIELD_SIZE,       md5,       md5_seed,        md5_append_length,       0,                    false),
    HASH_ENTRY("sha224",     "SHA224",     SHA224_HASH_SIZE,     SHA_256_WORD_SIZE,   SHA_256_BLOCK_SIZE,   SHA_256_LENGTH_FIELD_SIZE,   sha256,    sha224_seed,     sha256_append_length,    sizeof(uint32_t) - 1, true),
    HASH_ENTRY("sha256",     "SHA256",     SHA256_HASH_SIZE,     SHA_256_WORD_SIZE,   SHA_256_BLOCK_SIZE,   SHA_256_LENGTH_FIELD_SIZE,   sha256,    sha256_seed,     sha256_append_length,    sizeof(uint32_t) - 1, true),
    HASH_ENTRY("sha384",     "SHA384",     SHA384_HASH_SIZE,     SHA_512_WORD_SIZE,   SHA_512_BLOCK_SIZE,   SHA_512_LENGTH_FIELD_SIZE,   sha512,    sha384_seed,     sha512_append_length,    sizeof(uint64_t) - 1, true),
    HASH_ENTRY("sha512",     "SHA512",     SHA512_HASH_SIZE,     SHA_512_WORD_SIZE,   SHA_512_BLOCK_SIZE,   SHA_512_LENGTH_FIELD_SIZE,   sha512,    sha512_seed,     sha512_append_length,    sizeof(uint64_t) - 1, true),
    HASH_ENTRY("sha512-224", "SHA512-224", SHA512_224_HASH_SIZE, SHA_512_WORD_SIZE,   SHA_512_BLOCK_SIZE,   SHA_512_LENGTH_FIELD_SIZE,   sha512,    sha512_224_seed, sha512_append_length,    sizeof(uint64_t) - 1, true),
    HASH_ENTRY("sha512-256", "SHA512-256", SHA512_256_HASH_SIZE, SHA_512_WORD_SIZE,   SHA_512_BLOCK_SIZE,   SHA_512_LENGTH_FIELD_SIZE,   sha512,    sha512_256_seed, sha512_append_length,    sizeof(uint64_t) - 1, true),
    HASH_ENTRY("whirlpool",  "WHIRLPOOL",  WHIRLPOOL_HASH_SIZE,  WHIRLPOOL_WORD_SIZE, WHIRLPOOL_BLOCK_SIZE, WHIRLPOOL_LENGTH_FIELD_SIZE, whirlpool, whirlpool_seed,  whirlpool_append_length, 0,                    false),
    { NULL }
};

hash_map find_algorithm(const char* name)
{
    for (hash_map* h = algorithms; h->algorithm_name; ++h) {
        if (strcmp(name, h->algorithm_name) == 0) {
            return *h;
        }
    }
    return (hash_map){ 0 };
}
