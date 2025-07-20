#include "message_digest.h"

enum out_mode { QUIET = 1, REVERSE = 2, ECHO = 4 };

static inline int output_mode(const md_options *o, bool echo)
{
    return (o->quiet_mode    ? QUIET   : 0) |
           (o->reverse_output? REVERSE : 0) |
           (echo             ? ECHO    : 0);
}

static const struct
{
    const char* prefix;
    const char* suffix;
} format_tbl[8] = { 
    [0]                  = { "%s(%s)= ", "\n" },
    [REVERSE]            = { "",         " %s\n" },
    [QUIET]              = { "",         "\n" },
    [QUIET|REVERSE]      = { "",         "\n" },
    [ECHO]               = { "\")= ",    "\n" },
    [ECHO|REVERSE]       = { "\")= ",    "\n" },
    [QUIET|ECHO]         = { "",         "\n" },
    [QUIET|REVERSE|ECHO] = { "\n",       "\n" }
};

static void echo_input(const char* buf, ssize_t n, bool quiet_mode)
{
    if (!n) return;
    if (!quiet_mode) print("(\"");
    write(STDOUT_FILENO, buf, --n);
}

static inline size_t get_index(size_t i, size_t word_size, bool big_endian)
{
    return big_endian ? (i ^ (word_size - 1)) : i;
}

static void append_length(uint8_t* block, hash_map* H)
{
    size_t len_pos = (H->buffer_index + H->length_field_bytes < H->block_size_bytes) ?
                      H->block_size_bytes - sizeof(uint64_t) :
                      H->block_size_bytes * 2 - sizeof(uint64_t);

    uint64_t* len_field = (uint64_t*)(block + len_pos);
    size_t    word_size = H->word_size_bytes;

    while (H->buffer_index < len_pos) {
        size_t idx = get_index(H->buffer_index, word_size, H->is_big_endian);
        block[idx] = (H->buffer_index == H->total_length % H->block_size_bytes) ? 0x80 : 0;
        ++H->buffer_index;
    }
    *len_field = H->append_length_fn(H->total_length * 8);
}

static void fill_block(uint8_t* block, hash_map* H, const char* input)
{
    size_t end = H->buffer_index + H->bytes_processed;
    while (H->buffer_index < end) {
        size_t idx = get_index(H->buffer_index, H->word_size_bytes, H->is_big_endian);
        block[idx] = input[H->buffer_index];
        ++H->buffer_index;
    }
}

static void print_hash(const uint8_t* hash, hash_size h_size, int mask)
{
    static const char hex[] = "0123456789abcdef";

    char out[3] = { 0 };
    for (int i = 0; i < (int)h_size; ++i) {
        uint8_t b = hash[i ^ mask];
        out[0]    = hex[b >> 4];
        out[1]    = hex[b & 0xF];
        print("%s", out);
    }
}

static void print_result(const md_options* opt, const char* label, hash_map* H, bool echo)
{
    int m = output_mode(opt, echo);
    if (*format_tbl[m].prefix) print(format_tbl[m].prefix, H->upper_algorithm_name, label);
    print_hash(H->digest, H->output_size, H->hash_bitmask);
    if (*format_tbl[m].suffix) print(format_tbl[m].suffix, label);
}

int digest_and_print(const md_options* opt, const char* label, int fd, bool echo)
{
    hash_map H = find_algorithm(opt->hash_name);
    H.input_fd = fd;
    H.init_seed_fn(H.digest);

    uint8_t block[H.block_size_bytes * 2];
    char    buf[H.block_size_bytes];

    while (H.bytes_processed > 0) {
        H.bytes_processed = read(fd, buf + H.buffer_index, H.block_size_bytes - H.buffer_index);
        if (H.bytes_processed < 0) return EXIT_FAILURE;

        if (echo) {
            echo_input(buf + H.buffer_index, H.bytes_processed, opt->quiet_mode);
        }

        H.total_length += H.bytes_processed;
        if (H.bytes_processed == 0) append_length(block, &H);

        fill_block(block, &H, buf);

        if (H.buffer_index == H.block_size_bytes || H.bytes_processed == 0) {
            H.compute_hash_fn(block, H.digest);
            if (H.buffer_index > H.block_size_bytes) {
                H.compute_hash_fn(block + H.block_size_bytes, H.digest);
            }
            H.buffer_index = 0;
        }
    }

    print_result(opt, label, &H, echo);
    return EXIT_SUCCESS;
}

int digest_string_pipe(const md_options* opt, const char* s)
{
    size_t L = strlen(s);
    char   quoted[L + 3];
    quoted[0] = '"';
    for (size_t i = 0; i < L; ++i) quoted[i + 1] = s[i];
    quoted[L + 1] = '"';
    quoted[L + 2] = '\0';

    int pfd[2];
    if (pipe(pfd) != 0) return EXIT_FAILURE;

    write(pfd[1], s, L);
    close(pfd[1]);
    int err = digest_and_print(opt, quoted, pfd[0], false);
    close(pfd[0]);
    return err;
}