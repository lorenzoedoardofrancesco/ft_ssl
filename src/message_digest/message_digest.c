#include "ft_ssl.h"
 // FAIRE LE TESTEUR QUI TEST AUSSI LE TEMPS D'EXECUTION. VOIR C'EST QUOI LES FUNCTIONS QUI RENDENT LE PROGRAMME LENT
hash_map hash_functions[] =
{
	{"md5", md5, MD5_WORDS_NUMBER, MD5_WORD_SIZE, MD5_LENGTH_FIELD_SIZE, false},
	{"sha224", sha224, SHA_256_WORDS_NUMBER, SHA_256_WORD_SIZE, SHA_256_LENGTH_FIELD_SIZE, true},
	{"sha256", sha256, SHA_256_WORDS_NUMBER, SHA_256_WORD_SIZE, SHA_256_LENGTH_FIELD_SIZE, true},
	{"sha384", sha384, SHA_512_WORDS_NUMBER, SHA_512_WORD_SIZE, SHA_512_LENGTH_FIELD_SIZE, true},
	{"sha512", sha512, SHA_512_WORDS_NUMBER, SHA_512_WORD_SIZE, SHA_512_LENGTH_FIELD_SIZE, true},
	{"sha512-224", sha512_224, SHA_512_WORDS_NUMBER, SHA_512_WORD_SIZE, SHA_512_LENGTH_FIELD_SIZE, true},
	{"sha512-256", sha512_256, SHA_512_WORDS_NUMBER, SHA_512_WORD_SIZE, SHA_512_LENGTH_FIELD_SIZE, true},
	{"whirlpool", whirlpool, WHIRLPOOL_WORDS_NUMBER, WHIRLPOOL_WORD_SIZE, WHIRLPOOL_LENGTH_FIELD_SIZE, false},
	{NULL, NULL, 0, 0, 0, false}
};

hash_map *find_hash_function(const char *name)
{
	for (int i = 0; hash_functions[i].name != NULL; i++)
		if (strcmp(name, hash_functions[i].name) == 0)
			return &hash_functions[i];
	return NULL;
}

void append_length(uint64_t *block, uint64_t length, size_t length_field_size, bool big_endian)
{
	if (length_field_size == sizeof(uint64_t))
	{
		uint64_t length_big_endian = ((uint64_t)((uint32_t)(length & 0xFFFFFFFF)) << 32) | (uint32_t)(length >> 32);
		*block = big_endian ? length_big_endian : length;
	}
	else if (length_field_size == sizeof(__uint128_t))
		*(block + 1) = length;
	else if (length_field_size == sizeof(__uint128_t) * 2)
		*(block + 3) = SWAP64(length);
}

void **fill_blocks(void **blocks_ptr, size_t num_of_blocks, size_t word_size, size_t block_size, const char *input, size_t input_len, size_t length_field_size, bool big_endian)
{
	uint8_t **blocks = (uint8_t **)blocks_ptr;
	size_t w = word_size;

	for (size_t i = 0; i < num_of_blocks; ++i)
	{
		for (size_t j = 0; j < block_size; ++j)
		{
			size_t byte_index = i * block_size + j;
			size_t index = (big_endian) ? ((j / w) * w + (w - 1) - j % w) : j;

			if (byte_index < input_len)
				blocks[i][index] = input[byte_index];
			else if (byte_index == input_len)
				blocks[i][index] = 0x80;
			else
				blocks[i][index] = 0;
		}
	}

	uint8_t *last_block_end = blocks[num_of_blocks - 1] + block_size;
	uint64_t *len_field_start = (uint64_t *)(last_block_end - length_field_size);
	append_length(len_field_start, input_len * 8, length_field_size, big_endian);

	return blocks_ptr;
}

void free_blocks(void **blocks, size_t num_of_blocks)
{
	for (size_t i = 0; i < num_of_blocks; ++i)
		free(blocks[i]);
	free(blocks);
}

void **initialize_blocks(size_t num_of_blocks, size_t words_per_block, size_t word_size, const char *input, size_t input_len, size_t length_field_size, bool big_endian)
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
			free_blocks(blocks, i);
			return NULL;
		}
	}

	return fill_blocks(blocks, num_of_blocks, word_size, block_size, input, input_len, length_field_size, big_endian);
}

void message_digest(const char *hash_name, const char *input)
{
	hash_map *hash_map = find_hash_function(hash_name);
	if (hash_map == NULL)
	{
		fprintf(stderr, "Unknown hash function: %s\n", hash_name); // changer
		return;
	}

	size_t input_len = strlen(input);
	size_t num_of_blocks = (input_len + hash_map->length_field_size) / (hash_map->word_size * hash_map->words_number) + 1;

	void **blocks = initialize_blocks(num_of_blocks, hash_map->words_number, hash_map->word_size, input, input_len, hash_map->length_field_size, hash_map->big_endian);
	if (!blocks)
	{
		fprintf(stderr, "Memory allocation error\n"); // changer  -> faire une function error
		return;
	}

	hash_map->function(blocks, num_of_blocks);
	free_blocks(blocks, num_of_blocks);
}

void write_hex_byte(uint8_t byte)
{
	char hex[2];

	hex[0] = HEX_CHARS[(byte >> 4) & 0x0F];
	hex[1] = HEX_CHARS[byte & 0x0F];
	write(1, hex, 2);
}

void write_hash(uint8_t *hash, hash_size size, int x)
{
	for (int i = 0; i < (int)size; ++i)
		write_hex_byte(hash[i ^ x]);
	write(1, "\n", 1);
	// write(1, "  - \n", 5);
}