#include "ft_ssl.h"

int error(const char *message)
{
	write(STDERR_FILENO, message, strlen(message));
	return EXIT_FAILURE;
}

int main(int argc, char *argv[])
{
	if (argc < 2)
		return error(HELP_MESSAGE);

	message_digest(argv[1], argv[2]);

	return EXIT_SUCCESS;
}