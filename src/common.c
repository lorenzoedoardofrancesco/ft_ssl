#include "ft_ssl.h"

void write_hex_byte(uint8_t byte)
{
	char hex[2];

	hex[0] = HEX_CHARS[(byte >> 4) & 0x0F];
	hex[1] = HEX_CHARS[byte & 0x0F];
	write(1, hex, 2);
}

void write_hash(uint32_t **hash, hash_size size)
{
	for (int i = 0; i < (int)size; ++i)
		for (int j = 0; j < 4; j++)
		{
			int shift = (size == HASH_MD5) ? (8 * j) : (24 - 8 * j);  // MD5 is little endian, SHA256 is big endian
			write_hex_byte((*hash[i] >> shift) & 0xFF);
		}
	write(1, "  - \n", 5);
}