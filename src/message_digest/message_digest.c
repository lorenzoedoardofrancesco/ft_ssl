#include "message_digest.h"

#define RETURN_FAIL do { free(opt.s_arg); return EXIT_FAILURE; } while(0)

static int open_input(char* file_name)
{
    if (file_name == NULL) return STDIN_FILENO;

    int fd = open(file_name, O_RDONLY);
    if (fd == -1) {
        print_error("%s: %s\n", file_name, strerror(errno));
    }
    return fd;
}

static int parse_md_options(char* argv[], md_options* opt)
{
    *opt                  = (md_options){ 0 };
    opt->hash_name        = argv[0];
    opt->first_path_index = 1;

    for (int i = 1; argv[i] && argv[i][0] == '-' && argv[i][2] == '\0'; ++i) {
        switch (argv[i][1]) {
            case 'p':
                opt->echo_stdin = true;
                break;
            case 'q':
                opt->quiet_mode = true;
                break;
            case 'r':
                opt->reverse_output = true;
                break;
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

int message_digest(int argc, char* argv[])
{
    md_options opt;
    if (parse_md_options(argv, &opt)) return EXIT_FAILURE;

    if (opt.echo_stdin) {
        if (digest_and_print(&opt, "stdin", STDIN_FILENO, true)) {
            RETURN_FAIL;
        }
    }

    for (size_t i = 0; i < opt.s_count; ++i) {
        if (digest_string_pipe(&opt, opt.s_arg[i])) {
            RETURN_FAIL;
        }
    }

    for (int i = opt.first_path_index; i < argc; ++i) {
        int fd = open_input(argv[i]);
        if (fd < 0) continue;

        if (digest_and_print(&opt, argv[i], fd, false)) {
            close(fd);
            RETURN_FAIL;
        }
        close(fd);
    }

    if (!opt.echo_stdin && opt.s_count == 0 && opt.first_path_index == argc) {
        if (digest_and_print(&opt, "stdin", STDIN_FILENO, false)) {
            RETURN_FAIL;
        }
    }

    free(opt.s_arg);
    return EXIT_SUCCESS;
}