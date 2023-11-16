#include "ft_ssl.h"

int main(int argc, char *argv[])
{
	if (argc < 3)
	{
		printf("usage: ft_ssl command [command opts] [command args]\n");
		return EXIT_FAILURE;
	}

	process_hash(argv[1], argv[2]);

	return EXIT_SUCCESS;
}