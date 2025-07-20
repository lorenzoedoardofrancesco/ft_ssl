#include "ft_ssl.h"

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

static hash_map find_algorithm(const char* name)
{
    for (hash_map* h = algorithms; h->algorithm_name; ++h) {
        if (strcmp(name, h->algorithm_name) == 0) {
            return *h;
        }
    }
    return (hash_map){0};
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

    char hex[3] = { 0 };
    for (int i = 0; i < (int)size; ++i) {
        uint8_t byte = hash[i ^ x];
        hex[0]       = hex_chars[(byte >> 4) & 0x0F];
        hex[1]       = hex_chars[byte & 0x0F];
        print(hex);
    }
}








typedef struct
{
    char   *hash_name;         /* argv[0]                    */
    bool    echo_stdin;        /* -p                         */
    bool    quiet_mode;        /* -q                         */
    bool    reverse_output;    /* -r                         */
    int     first_path_index;  /* index of first filename    */

    /* NEW ------------------------------------------------------------ */
    const char **s_arg;        /* dynamic array of -s strings */
    size_t       s_count;
} md_options;

static int parse_md_options(char* argv[], md_options* opt)
{
    *opt                  = (md_options){ 0 };
    opt->hash_name        = argv[0];
    opt->first_path_index = 1;

    for (int i = 1; argv[i] && argv[i][0] == '-' && argv[i][2] == '\0'; ++i) {
        switch (argv[i][1]) {
            case 'p': opt->echo_stdin = true;     break;
            case 'q': opt->quiet_mode = true;     break;
            case 'r': opt->reverse_output = true; break;
            case 's':
                if (!argv[i + 1]) {
                    print_error("%s: Option -s needs a value\n", opt->hash_name);
                    return EXIT_FAILURE;
                }

                opt->s_arg = realloc(opt->s_arg, (opt->s_count + 1) * sizeof(char*));
                if (!opt->s_arg) {
                    print_error("%s: out of memory\n", opt->hash_name);
                    return EXIT_FAILURE;
                }
                opt->s_arg[opt->s_count++] = argv[i + 1];
                ++i;
                break;
            default:
                print_error("%s: Unknown option or message digest: %s\n", opt->hash_name, argv[i] + 1);
                return EXIT_FAILURE;
        }
        opt->first_path_index = i + 1;
    }

    if (argv[opt->first_path_index] && argv[opt->first_path_index][0] == '-') {
        print_error("%s: Unknown option or message digest: %s\n", opt->hash_name, argv[opt->first_path_index] + 1);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static void print_result(const md_options *opt,
                         const char       *label,
                         hash_map         *H,
                         bool              is_echo)
{
    /* 0) QUIET always wins ----------------------------------------- */
    if (opt->quiet_mode) {
        print_hash(H->digest, H->output_size, H->hash_bitmask);
        print("\n");
        return;
    }

    /* 1) Echoing STDIN with -p  ------------------------------------ */
    if (is_echo) {
        /* we opened   ("   in digest_and_print(); finish it here    */
        print("\")= ");
        print_hash(H->digest, H->output_size, H->hash_bitmask);
        /*   NO '\n' here – the pending newline held back in
             digest_and_print() will follow, exactly like openssl   */
        return;
    }

    /* 2) Plain stdin (no -p)  -------------------------------------- */
    if (strcmp(label, "stdin") == 0) {
        print("(%s)= ", label);               /* (stdin)= <hash>      */
        print_hash(H->digest, H->output_size, H->hash_bitmask);
        print("\n");
        return;
    }

    /* 3) Normal files / “-s” strings ------------------------------- */
    if (opt->reverse_output) {                /*     -r               */
        print_hash(H->digest, H->output_size, H->hash_bitmask);
        print(" %s\n", label);
    } else {                                  /*   default direction  */
        print("%s (%s) = ", H->upper_algorithm_name, label);
        print_hash(H->digest, H->output_size, H->hash_bitmask);
        print("\n");
    }
}

static int digest_and_print(const md_options *opt,
                            const char       *label,
                            int               fd,
                            bool              echo)
{
    hash_map H = find_algorithm(opt->hash_name);
    H.input_fd = fd;
    H.init_seed_fn(H.digest);

    /* keep the final ‘\n’ back so we can place it AFTER the digest */
    bool   hold_newline   = false;
    size_t newline_offset = 0;

    uint8_t block[H.block_size_bytes * 2];
    char    buffer[H.block_size_bytes];

    for (;;) {
        H.bytes_processed = read(fd,
                                 buffer + H.buffer_index,
                                 H.block_size_bytes - H.buffer_index);
        if (H.bytes_processed < 0)
            return EXIT_FAILURE;

        /* ---- ECHO (-p) ------------------------------------------ */
        if (H.bytes_processed > 0 && echo) {
            static bool first = true;
            if (first) {
                first = false;
                if (!opt->quiet_mode)            /* no “(” in quiet   */
                    print("(\"");
            }

            /* write everything we just read …                       */
            size_t n = H.bytes_processed;

            /* … but keep ONE final '\n' back, exactly like openssl  */
            if (!opt->quiet_mode &&
                buffer[H.buffer_index + n - 1] == '\n')
            {
                n--;                        /* don’t write it yet   */
                hold_newline   = true;
                newline_offset = H.buffer_index + H.bytes_processed - 1;
            }

            if (n)
                write(STDOUT_FILENO, buffer + H.buffer_index, n);
        }

        /* ---- hashing mechanics (unchanged) ---------------------- */
        H.total_length += H.bytes_processed;
        if (H.bytes_processed == 0)
            append_length(block, &H);

        fill_block(block, &H, buffer);

        if (H.buffer_index == H.block_size_bytes || H.bytes_processed == 0) {
            H.compute_hash_fn(block, H.digest);
            if (H.buffer_index > H.block_size_bytes)
                H.compute_hash_fn(block + H.block_size_bytes, H.digest);
            H.buffer_index = 0;
        }

        if (H.bytes_processed == 0)
            break;
    }

    /* ---- finish -------------------------------------------------- */
    print_result(opt, label, &H, echo);

    /* now place the postponed newline (only for the “-p” flavour)   */
    if (echo && hold_newline && !opt->quiet_mode)
        print("\n");

    return EXIT_SUCCESS;
}

static int digest_string_and_print(const md_options *opt, const char *str)
{
    int pipefd[2];
    if (pipe(pipefd) == -1)
        return EXIT_FAILURE;

    write(pipefd[1], str, strlen(str));
    close(pipefd[1]);

    char quoted[500]; // was PATH_MAX, but that is not portable
    snprintf(quoted, sizeof quoted, "\"%s\"", str);

    int ret = digest_and_print(opt, quoted, pipefd[0], false);
    close(pipefd[0]);
    return ret;
}

int message_digest(int argc, char* argv[])
{
    md_options opt;
    if (parse_md_options(argv, &opt) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    /* 1.  -p  -------------------------------------------------------- */
    if (opt.echo_stdin) {
        if (digest_and_print(&opt, "stdin", STDIN_FILENO, true) != EXIT_SUCCESS) {
            return EXIT_FAILURE;
        }
    }

    /* 2.  every  -s <string>  encountered in the option block -------- */
    for (size_t i = 0; i < opt.s_count; ++i) {
        if (digest_string_and_print(&opt, opt.s_arg[i]) != EXIT_SUCCESS) {
            return EXIT_FAILURE;
        }
    }

    /* 3.  remaining arguments = file names --------------------------- */
    for (int i = opt.first_path_index; i < argc; ++i) {
        int fd = open_input(argv[i]);
        if (fd < 0) continue;
        if (digest_and_print(&opt, argv[i], fd, false) != EXIT_SUCCESS) return EXIT_FAILURE;
    }

    /* 4.  no args & no -p  ⇒  treat STDIN like md5sum ---------------- */
    if (!opt.echo_stdin && opt.first_path_index == argc && opt.s_count == 0) {
        if (digest_and_print(&opt, "stdin", STDIN_FILENO, false) != EXIT_SUCCESS) return EXIT_FAILURE;
    }

    free(opt.s_arg);
    return EXIT_SUCCESS;
}