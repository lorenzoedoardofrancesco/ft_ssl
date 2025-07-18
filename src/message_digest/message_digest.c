#include "ft_ssl.h"

#define HASH_ENTRY(name, seed, wsize, bsize, lsize, append_len, func, id, mask, big) \
    { name, seed, wsize, bsize, lsize, append_len, func, {0}, id, mask, big, 0, 0, 1, 0 }

static hash_map hash_functions[] = {
    HASH_ENTRY("md5",        md5,       MD5_WORD_SIZE,       MD5_BLOCK_SIZE,       MD5_LENGTH_FIELD_SIZE,       md5_append_length,       md5_seed,        MD5_HASH_SIZE,        0,                    false),
    HASH_ENTRY("sha224",     sha256,    SHA_256_WORD_SIZE,   SHA_256_BLOCK_SIZE,   SHA_256_LENGTH_FIELD_SIZE,   sha256_append_length,    sha224_seed,     SHA224_HASH_SIZE,     sizeof(uint32_t) - 1, true),
    HASH_ENTRY("sha256",     sha256,    SHA_256_WORD_SIZE,   SHA_256_BLOCK_SIZE,   SHA_256_LENGTH_FIELD_SIZE,   sha256_append_length,    sha256_seed,     SHA256_HASH_SIZE,     sizeof(uint32_t) - 1, true),
    HASH_ENTRY("sha384",     sha512,    SHA_512_WORD_SIZE,   SHA_512_BLOCK_SIZE,   SHA_512_LENGTH_FIELD_SIZE,   sha512_append_length,    sha384_seed,     SHA384_HASH_SIZE,     sizeof(uint64_t) - 1, true),
    HASH_ENTRY("sha512",     sha512,    SHA_512_WORD_SIZE,   SHA_512_BLOCK_SIZE,   SHA_512_LENGTH_FIELD_SIZE,   sha512_append_length,    sha512_seed,     SHA512_HASH_SIZE,     sizeof(uint64_t) - 1, true),
    HASH_ENTRY("sha512-224", sha512,    SHA_512_WORD_SIZE,   SHA_512_BLOCK_SIZE,   SHA_512_LENGTH_FIELD_SIZE,   sha512_append_length,    sha512_224_seed, SHA512_224_HASH_SIZE, sizeof(uint64_t) - 1, true),
    HASH_ENTRY("sha512-256", sha512,    SHA_512_WORD_SIZE,   SHA_512_BLOCK_SIZE,   SHA_512_LENGTH_FIELD_SIZE,   sha512_append_length,    sha512_256_seed, SHA512_256_HASH_SIZE, sizeof(uint64_t) - 1, true),
    HASH_ENTRY("whirlpool",  whirlpool, WHIRLPOOL_WORD_SIZE, WHIRLPOOL_BLOCK_SIZE, WHIRLPOOL_LENGTH_FIELD_SIZE, whirlpool_append_length, whirlpool_seed,  WHIRLPOOL_HASH_SIZE,  0,                    false),
    { NULL }
};

static hash_map* find_hash_function(const char* name)
{
    for (int i = 0; hash_functions[i].name != NULL; i++) {
        if (strcmp(name, hash_functions[i].name) == 0) {
            return &hash_functions[i];
        }
    }
    return NULL;
}

static int input_check(char* file_name)
{
    if (file_name == NULL) {
        return STDIN_FILENO; // is this correct?
    }

    int fd = open(file_name, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "Can't open file: %s\n", file_name);
    }
    return fd;
}

static inline size_t map_index(size_t i, size_t w, bool big_endian)
{
    return big_endian ? ((i / w) * w + (w - 1) - (i % w)) : i;
}

static void append_length(uint8_t* block, hash_map* H)
{
    size_t    len_field_start = H->i + H->length_field_size < H->block_size ? H->block_size - sizeof(uint64_t) : H->block_size * 2 - sizeof(uint64_t);
    uint64_t* length_field    = (uint64_t*)(block + len_field_start);

    size_t w = H->word_size;
    while (H->i < len_field_start) {
        size_t index = map_index(H->i, w, H->big_endian);
        if (H->i == H->length % H->block_size) {
            block[index] = 0x80;
        } else {
            block[index] = 0;
        }
        ++H->i;
    }

    *length_field = H->append_length(H->length * 8);
}

static void fill_block(uint8_t* block, hash_map* H, char* input)
{
    size_t w   = H->word_size;
    size_t end = H->i + H->bytes_read;

    while (H->i < end) {
        size_t index = map_index(H->i, w, H->big_endian);

        block[index] = input[H->i];
        ++H->i;
    }
}

static void write_hash(uint8_t* hash, hash_size size, int x)
{
    static const char hex_chars[] = "0123456789abcdef";

    char hex[2];
    for (int i = 0; i < (int)size; ++i) {
        uint8_t byte = hash[i ^ x];
        hex[0] = hex_chars[(byte >> 4) & 0x0F];
        hex[1] = hex_chars[byte & 0x0F];
        print(hex);
    }
    print("\n");
}

int message_digest(char* hash_name, char* argv[])
{
    hash_map* H = find_hash_function(hash_name);
    if (H == NULL) {
        fprintf(stderr, "Unknown hash function: %s\n", hash_name);
        return EXIT_FAILURE;
    }

    H->fd = input_check(argv[0]);
    if (H->fd < 0) {
        return EXIT_FAILURE;
    }

    H->hash_seed(H->hash);
    uint8_t block[H->block_size * 2];
    char    buffer[H->block_size];

    while (H->bytes_read) {
        error(H->bytes_read = read(H->fd, buffer + H->i, H->block_size - H->i));
        H->length += H->bytes_read;

        if (H->bytes_read == 0) append_length(block, H);

        fill_block(block, H, buffer);
        if (H->i == H->block_size || H->bytes_read == 0) {
            H->function(block, H->hash);
            if (H->i > H->block_size) H->function(block + H->block_size, H->hash);
            H->i = 0;
        }
    }

    write_hash(H->hash, H->hash_size, H->hash_mask);
    return EXIT_SUCCESS;
}