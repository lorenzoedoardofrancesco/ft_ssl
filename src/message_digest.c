#include "ft_ssl.h"

int little_endian = 0; // a mettre dans la structure hash_map ??

hash_map hash_functions[] =
	{
		{"md5", md5, MD5_WORDS_NUMBER, MD5_WORD_SIZE, MD5_LENGTH_FIELD_SIZE, MD5_PADDING_BYTE},
		{"sha224", sha224, SHA_256_WORDS_NUMBER, SHA_256_WORD_SIZE, SHA_256_LENGTH_FIELD_SIZE, SHA_256_PADDING_BYTE},
		{"sha256", sha256, SHA_256_WORDS_NUMBER, SHA_256_WORD_SIZE, SHA_256_LENGTH_FIELD_SIZE, SHA_256_PADDING_BYTE},
		{"sha384", sha384, SHA_512_WORDS_NUMBER, SHA_512_WORD_SIZE, SHA_512_LENGTH_FIELD_SIZE, SHA_512_PADDING_BYTE},
		{"sha512", sha512, SHA_512_WORDS_NUMBER, SHA_512_WORD_SIZE, SHA_512_LENGTH_FIELD_SIZE, SHA_512_PADDING_BYTE},
		{"sha512-224", sha512_224, SHA_512_WORDS_NUMBER, SHA_512_WORD_SIZE, SHA_512_LENGTH_FIELD_SIZE, SHA_512_PADDING_BYTE},
		{"sha512-256", sha512_256, SHA_512_WORDS_NUMBER, SHA_512_WORD_SIZE, SHA_512_LENGTH_FIELD_SIZE, SHA_512_PADDING_BYTE},
		{NULL, NULL, 0, 0, 0, 0}};

hash_map *find_hash_function(const char *name)
{
	for (int i = 0; hash_functions[i].name != NULL; i++)
		if (strcmp(name, hash_functions[i].name) == 0)
			return &hash_functions[i];
	return NULL;
}

void append_length_32(uint32_t *block, uint64_t length)
{
	block[MD5_WORDS_NUMBER - 1 - little_endian] = (uint32_t)(length & 0xFFFFFFFF);
	block[MD5_WORDS_NUMBER - 2 + little_endian] = (uint32_t)(length >> 32);
}

void copy_input_to_block_32(uint32_t *block, const char *input, size_t byte_index, size_t input_len)
{
	*block = 0;
	for (size_t k = 0; k < 4; ++k)
	{
		if (byte_index + k < input_len)
			*block |= (uint32_t)((unsigned char)input[byte_index + k]) << (little_endian ? 8 * k : 8 * (3 - k));
		else if (byte_index + k == input_len)
			*block |= 0x80 << (little_endian ? 8 * k : 8 * (3 - k));
	}
}

void **fill_blocks_32(uint32_t **blocks, size_t num_of_blocks, size_t words_per_block, size_t block_size, const char *input, size_t input_len, uint32_t padding)
{
	for (size_t i = 0; i < num_of_blocks; ++i)
	{
		for (size_t j = 0; j < words_per_block; ++j)
		{
			size_t byte_index = i * block_size + j * 4;

			if (byte_index < input_len)
				copy_input_to_block_32(&blocks[i][j], input, byte_index, input_len);
			else if (byte_index == input_len)
				blocks[i][j] = padding;
			else
				blocks[i][j] = 0;
		}
	}

	append_length_32(blocks[num_of_blocks - 1], input_len * 8);
	return (void **)blocks;
}

void append_length_64(uint64_t *block, size_t words_per_block, uint64_t length)
{
	block[words_per_block - 1] = length;
}

void copy_input_to_block_64(uint64_t *block, const char *input, size_t byte_index, size_t input_len)
{
	*block = 0;
	for (size_t k = 0; k < 8; ++k)
	{
		if (byte_index + k < input_len)
			*block |= (uint64_t)((unsigned char)input[byte_index + k]) << (8 * (7 - k));
		else if (byte_index + k == input_len)
			*block |= (uint64_t)0x80 << (8 * (7 - k));
	}
}

void **fill_blocks_64(uint64_t **blocks, size_t num_of_blocks, size_t words_per_block, size_t block_size, const char *input, size_t input_len, uint64_t padding)
{
	for (size_t i = 0; i < num_of_blocks; ++i)
	{
		for (size_t j = 0; j < words_per_block; ++j)
		{
			size_t byte_index = i * block_size + j * 8;

			if (byte_index < input_len)
				copy_input_to_block_64(&blocks[i][j], input, byte_index, input_len);
			else if (byte_index == input_len)
				blocks[i][j] = padding;
			else
				blocks[i][j] = 0;
		}
	}

	append_length_64(blocks[num_of_blocks - 1], words_per_block, input_len * 8);
	return (void **)blocks;
}

void **initialize_blocks(size_t num_of_blocks, size_t words_per_block, size_t word_size, const char *input, size_t input_len, uint64_t padding)
{
	size_t block_size = words_per_block * word_size;

	void **blocks = malloc(sizeof(void *) * num_of_blocks);
	if (!blocks)
		return NULL;

	for (size_t i = 0; i < num_of_blocks; ++i)
	{
		blocks[i] = malloc(block_size);
		if (!blocks[i])
		{
			for (size_t j = 0; j < i; ++j)
				free(blocks[j]);
			free(blocks);
			return NULL;
		}
	}

	if (word_size == sizeof(uint32_t))
		return fill_blocks_32((uint32_t **)blocks, num_of_blocks, words_per_block, block_size, input, input_len, padding);
	else
		return fill_blocks_64((uint64_t **)blocks, num_of_blocks, words_per_block, block_size, input, input_len, padding);
}

void free_blocks(void **blocks, size_t num_of_blocks)
{
	for (size_t i = 0; i < num_of_blocks; ++i)
		free(blocks[i]);
	free(blocks);
}

void process_hash(const char *hash_name, const char *input)
{
	hash_map *hash_map = find_hash_function(hash_name);
	if (hash_map == NULL)
	{
		fprintf(stderr, "Unknown hash function: %s\n", hash_name);
		return;
	}

	size_t input_len = strlen(input);
	size_t num_of_blocks = (input_len + hash_map->length_field_size) / (hash_map->word_size * hash_map->words_number) + 1;

	void **blocks = initialize_blocks(num_of_blocks, hash_map->words_number, hash_map->word_size, input, input_len, hash_map->padding_byte);
	hash_map->function(blocks, num_of_blocks);
	free_blocks(blocks, num_of_blocks);
}

///
///
///
///

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
			int shift = (size == HASH_MD5) ? (8 * j) : (24 - 8 * j); // MD5 is little endian, SHA256 is big endian
			write_hex_byte((*hash[i] >> shift) & 0xFF);
		}
	write(1, "  - \n", 5);
}

void write_hash_64(uint64_t **hash, hash_size size)
{
	for (int i = 0; i < (int)size; ++i)
		for (int j = 0; j < 8; j++)
		{
			int shift = 56 - 8 * j; // Big endian
			write_hex_byte((*hash[i] >> shift) & 0xFF);
		}
	write(1, "  - \n", 5);
}