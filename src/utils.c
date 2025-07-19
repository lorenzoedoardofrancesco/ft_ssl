#include "ft_ssl.h"

#include <stdarg.h>

static void print_fd(int fd, const char* fmt, va_list args)
{
    while (*fmt) {
        if (*fmt == '%' && *(fmt + 1) == 's') {
            fmt += 2;
            const char* s = va_arg(args, const char*);
            write(fd, s, strlen(s));
        } else {
            write(fd, fmt, 1);
            fmt++;
        }
    }
}

void print(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    print_fd(STDOUT_FILENO, fmt, args);
    va_end(args);
}

void print_error(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    print_fd(STDERR_FILENO, fmt, args);
    va_end(args);
}

void error(int ret)
{
    if (ret == -1) {
        print_error("Error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}