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