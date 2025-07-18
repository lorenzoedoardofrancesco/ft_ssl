#include "ft_ssl.h"

void print(const char* message) { write(STDOUT_FILENO, message, strlen(message)); }

void print_error(const char* message) { write(STDERR_FILENO, message, strlen(message)); }

void error(int ret)
{
    if (ret == -1) {
        print_error(strerror(errno));
        exit(EXIT_FAILURE);
    }
}