#include "ft_ssl.h"

#include <stdarg.h>

void print(const char* message) { write(STDOUT_FILENO, message, strlen(message)); }

void print_error(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    while (*fmt) {
        if (*fmt == '%' && *(fmt + 1) == 's') {
            fmt += 2;
            const char* s = va_arg(args, const char*);
            write(STDERR_FILENO, s, strlen(s));
        } else {
            write(STDERR_FILENO, fmt, 1);
            fmt++;
        }
    }
    va_end(args);
}

void error(int ret)
{
    if (ret == -1) {
        print_error("Error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}