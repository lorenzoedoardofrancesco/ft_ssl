#include "ft_ssl.h"

int little_endian = 1; // a mettre dans la structure ssl

uint32_t **initialize_blocks(size_t num_of_blocks)
{
	uint32_t **blocks = malloc(sizeof(uint32_t *) * num_of_blocks);
	if (!blocks)
		return NULL;

	for (size_t i = 0; i < num_of_blocks; ++i)
	{
		blocks[i] = malloc(sizeof(uint32_t) * MD5_WORDS_NUMBER);
		if (!blocks[i])
		{
			for (size_t j = 0; j < i; ++j)
				free(blocks[j]);
			free(blocks);
			return NULL;
		}
	}

	return blocks;
}

void free_blocks(uint32_t **blocks, size_t num_of_blocks)
{
	for (size_t i = 0; i < num_of_blocks; ++i)
		free(blocks[i]);
	free(blocks);
}

void append_length(uint32_t *block, uint64_t length)
{
	block[MD5_WORDS_NUMBER - 1 - little_endian] = (uint32_t)(length & 0xFFFFFFFF);
	block[MD5_WORDS_NUMBER - 2 + little_endian] = (uint32_t)(length >> 32);
}

void copy_input_to_block(uint32_t *block, const char *input, size_t byte_index, size_t input_len)
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

void fill_blocks(ssl *ssl)
{
	for (size_t i = 0; i < ssl->num_of_blocks; ++i)
	{
		for (int j = 0; j < MD5_WORDS_NUMBER; ++j)
		{
			size_t byte_index = i * MD5_BLOCK_SIZE + j * 4;

			if (byte_index < ssl->input_len)
				copy_input_to_block(&ssl->blocks[i][j], ssl->input, byte_index, ssl->input_len);
			else if (byte_index == ssl->input_len)
				ssl->blocks[i][j] = little_endian ? 0x80 : 0x80000000;
			else
				ssl->blocks[i][j] = 0;
		}
	}

	append_length(ssl->blocks[ssl->num_of_blocks - 1], ssl->input_len * 8);
}

size_t strlen(const char *s)
{
	size_t len = 0;
	while (s[len])
		++len;
	return len;
}

int main(int argc, char *argv[])
{
	(void)argc;
	ssl ssl = {
		.input = argv[1],
		.input_len = strlen(ssl.input),
		.num_of_blocks = (ssl.input_len + MD5_MIN_PADDING_SIZE + MD5_LENGTH_FIELD_SIZE - 1) / MD5_BLOCK_SIZE + 1,
	};

	little_endian = 1; // md5 = 1 ; sha256 = 0
	ssl.blocks = initialize_blocks(ssl.num_of_blocks);
	if (!ssl.blocks)
		return EXIT_FAILURE; // a faire

	fill_blocks(&ssl);

	md5(&ssl);
	// sha256(&ssl);

	free_blocks(ssl.blocks, ssl.num_of_blocks);
	return EXIT_SUCCESS;
}

// print_blocks(ssl.blocks, ssl.num_of_blocks);

/*void print_blocks(uint32_t **blocks, size_t num_of_blocks)
{
	for (size_t i = 0; i < num_of_blocks; ++i)
	{
		for (size_t j = 0; j < MD5_WORDS_NUMBER; ++j)
			printf("%08x ", blocks[i][j]);
		printf("\n");
	}
}*/