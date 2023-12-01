#include "ft_ssl.h"

size_t strlen(const char *s)
{
	size_t len = 0;
	while (s[len])
		++len;
	return len;
}

void *ft_memcpy(void *dest, const void *src, size_t n)
{
	for (size_t i = 0; i < n; ++i)
		((uint8_t *)dest)[i] = ((uint8_t *)src)[i];
	return dest;
}

void ft_memset(void *dest, int c, size_t len)
{
	for (size_t i = 0; i < len; ++i)
		((uint8_t *)dest)[i] = c;
}

void put_error(char *str)
{
	write(STDERR_FILENO, str, strlen(str));
}

void error(int ret)
{
	if (ret == -1)
	{
		put_error(strerror(errno));
		exit(EXIT_FAILURE);
	}
}