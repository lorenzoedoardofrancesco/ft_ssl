#include "ft_ssl.h"

command_map commands[] = {
    { "md5",        message_digest },
    { "sha224",     message_digest },
    { "sha256",     message_digest },
    { "sha384",     message_digest },
    { "sha512",     message_digest },
    { "sha512-224", message_digest },
    { "sha512-256", message_digest },
    { "whirlpool",  message_digest },
    { NULL,         NULL           }
};

int main(int argc, char* argv[])
{
    if (argc < 2) {
        print(HELP_MESSAGE);
        return EXIT_SUCCESS;
    }

    for (int i = 0; commands[i].command != NULL; i++) {
        if (strcmp(argv[1], commands[i].command) == 0) {
            return commands[i].function(argv[1], argv + 2);
        }
    }

    fprintf(stderr, "ft_ssl: Invalid command '%s'; type \"help\" for a list.\n", argv[1]);
    return EXIT_FAILURE;
}