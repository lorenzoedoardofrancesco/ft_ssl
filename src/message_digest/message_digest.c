#include "ft_ssl.h"

#define HASH_ENTRY(name, hsize, wsize, bsize, lsize, hash_fn, seed_fn, append_len_fn, mask, be) \
    { name, hsize, wsize, bsize, lsize, hash_fn, seed_fn, append_len_fn, mask, be, { 0 }, 0, 0, 1, 0 }

static hash_map algorithms[] = {
    HASH_ENTRY("md5",        MD5_HASH_SIZE,        MD5_WORD_SIZE,       MD5_BLOCK_SIZE,       MD5_LENGTH_FIELD_SIZE,       md5,       md5_seed,        md5_append_length,       0,                    false),
    HASH_ENTRY("sha224",     SHA224_HASH_SIZE,     SHA_256_WORD_SIZE,   SHA_256_BLOCK_SIZE,   SHA_256_LENGTH_FIELD_SIZE,   sha256,    sha224_seed,     sha256_append_length,    sizeof(uint32_t) - 1, true),
    HASH_ENTRY("sha256",     SHA256_HASH_SIZE,     SHA_256_WORD_SIZE,   SHA_256_BLOCK_SIZE,   SHA_256_LENGTH_FIELD_SIZE,   sha256,    sha256_seed,     sha256_append_length,    sizeof(uint32_t) - 1, true),
    HASH_ENTRY("sha384",     SHA384_HASH_SIZE,     SHA_512_WORD_SIZE,   SHA_512_BLOCK_SIZE,   SHA_512_LENGTH_FIELD_SIZE,   sha512,    sha384_seed,     sha512_append_length,    sizeof(uint64_t) - 1, true),
    HASH_ENTRY("sha512",     SHA512_HASH_SIZE,     SHA_512_WORD_SIZE,   SHA_512_BLOCK_SIZE,   SHA_512_LENGTH_FIELD_SIZE,   sha512,    sha512_seed,     sha512_append_length,    sizeof(uint64_t) - 1, true),
    HASH_ENTRY("sha512-224", SHA512_224_HASH_SIZE, SHA_512_WORD_SIZE,   SHA_512_BLOCK_SIZE,   SHA_512_LENGTH_FIELD_SIZE,   sha512,    sha512_224_seed, sha512_append_length,    sizeof(uint64_t) - 1, true),
    HASH_ENTRY("sha512-256", SHA512_256_HASH_SIZE, SHA_512_WORD_SIZE,   SHA_512_BLOCK_SIZE,   SHA_512_LENGTH_FIELD_SIZE,   sha512,    sha512_256_seed, sha512_append_length,    sizeof(uint64_t) - 1, true),
    HASH_ENTRY("whirlpool",  WHIRLPOOL_HASH_SIZE,  WHIRLPOOL_WORD_SIZE, WHIRLPOOL_BLOCK_SIZE, WHIRLPOOL_LENGTH_FIELD_SIZE, whirlpool, whirlpool_seed,  whirlpool_append_length, 0,                    false),
    { NULL }
};

static hash_map* find_algorithm(const char* name)
{
    for (hash_map* h = algorithms; h->algorithm_name; ++h) {
        if (strcmp(name, h->algorithm_name) == 0) {
            return h;
        }
    }
    return NULL;
}

static int open_input(char* file_name)
{
    if (file_name == NULL) {
        return STDIN_FILENO;
    }

    int fd = open(file_name, O_RDONLY);
    if (fd == -1) {
        print_error("%s: %s\n", file_name, strerror(errno));
    }
    return fd;
}

static inline size_t map_index(size_t i, size_t w, bool is_big_endian) {
    return is_big_endian ? (i ^ (w - 1)) : i;
}

static void append_length(uint8_t* block, hash_map* H)
{
    size_t    len_field_start = H->buffer_index + H->length_field_bytes < H->block_size_bytes ? H->block_size_bytes - sizeof(uint64_t) : H->block_size_bytes * 2 - sizeof(uint64_t);
    uint64_t* length_field    = (uint64_t*)(block + len_field_start);

    size_t w = H->word_size_bytes;
    while (H->buffer_index < len_field_start) {
        size_t index = map_index(H->buffer_index, w, H->is_big_endian);
        if (H->buffer_index == H->total_length % H->block_size_bytes) {
            block[index] = 0x80;
        } else {
            block[index] = 0;
        }
        ++H->buffer_index;
    }

    *length_field = H->append_length_fn(H->total_length * 8);
}

static void fill_block(uint8_t* block, hash_map* H, char* input)
{
    size_t w   = H->word_size_bytes;
    size_t end = H->buffer_index + H->bytes_processed;

    while (H->buffer_index < end) {
        size_t index = map_index(H->buffer_index, w, H->is_big_endian);

        block[index] = input[H->buffer_index];
        ++H->buffer_index;
    }
}

static void print_hash(uint8_t* hash, hash_size size, int x)
{
    static const char hex_chars[] = "0123456789abcdef";

    char hex[3] = {0˛, 0, '\0'};\
    for (int i = 0; i < (int)size; ++i) {
        uint8_t byte = hash[i ^ x];
        hex[0]       = hex_chars[(byte >> 4) & 0x0F];
        hex[1]       = hex_chars[byte & 0x0F];
        print(hex);
    }
    print("\n");
}

int message_digest(char* hash_name, char* argv[])
{
    hash_map* H = find_algorithm(hash_name);

    int  i          = 0;
    bool echo_stdin = false, quiet_mode = false, reverse_output = false;
    while (argv[i] && argv[i][0] == '-') {
        if (strcmp(argv[i], "-p") == 0) {
            echo_stdin = true;
        } else if (strcmp(argv[i], "-q") == 0) {
            quiet_mode = true;
        } else if (strcmp(argv[i], "-r") == 0) {
            reverse_output = true;
        } else if (strcmp(argv[i], "-s") == 0) {
            if (argv[i + 1]) {
                argv[i] = argv[i + 1];
                ++i;
            } else {
                print_error("Option -s needs a value\n");
                return EXIT_FAILURE;
            }
        } else {
            print_error("Unknown option or message digest: %s\n", argv[i]);
            return EXIT_FAILURE;
        }
        ++i;
    }

    H->input_fd = open_input(argv[i]);
    if (H->input_fd < 0) {
        return EXIT_FAILURE;
    }

    H->init_seed_fn(H->digest);

    uint8_t block[H->block_size_bytes * 2];
    char    buffer[H->block_size_bytes];

    while (H->bytes_processed) {
        error(H->bytes_processed = read(H->input_fd, buffer + H->buffer_index, H->block_size_bytes - H->buffer_index));
        H->total_length += H->bytes_processed;

        if (H->bytes_processed == 0) {
            append_length(block, H);
        }

        fill_block(block, H, buffer);

        if (H->buffer_index == H->block_size_bytes || H->bytes_processed == 0) {
            H->compute_hash_fn(block, H->digest);
            if (H->buffer_index > H->block_size_bytes) {
                H->compute_hash_fn(block + H->block_size_bytes, H->digest);
            }
            H->buffer_index = 0;
        }
    }

    print_hash(H->digest, H->output_size, H->hash_bitmask);
    return EXIT_SUCCESS;
}