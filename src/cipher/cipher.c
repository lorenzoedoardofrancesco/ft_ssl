#include "cipher.h"
#include <errno.h>

#define MISSING_ARGUMENT(option) "base64: Option " option " needs a value\n"

enum Mode
{
	ENCODE = 0,
	DECODE = 1
};

int set_file_option(char ***argv, char **file_option)
{
	if (*++(*argv))
		*file_option = **argv;
	else
		return 1;
	return 0;
}


void base64_encode(int fd_in, int fd_out) {
    unsigned char in[3];
    unsigned char out[4];
    int len;

    while ((len = read(fd_in, in, 3)) > 0) {
        out[0] = BASE64_CHARS[in[0] >> 2];
        out[1] = BASE64_CHARS[((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)];
        out[2] = (len > 1 ? BASE64_CHARS[((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6)] : '=');
        out[3] = (len > 2 ? BASE64_CHARS[in[2] & 0x3f] : '=');

        write(fd_out, out, 4);
    }
}
int base64(char *input, char *argv[])
{
	(void) input;
	int mode = ENCODE;
	char *input_file = NULL;
	char *output_file = NULL;

	while (*++argv)
	{
		if (strcmp(*argv, "-i") == 0 && set_file_option(&argv, &input_file))
			return print_error(MISSING_ARGUMENT("-i"));
		else if (strcmp(*argv, "-o") == 0 && set_file_option(&argv, &output_file))
			return print_error(MISSING_ARGUMENT("-o"));
		else if (strcmp(*argv, "-d") == 0)
			mode = DECODE;
		else if (strcmp(*argv, "-e") == 0)
			mode = ENCODE;
		else
			fprintf(stderr, "base64: Invalid option '%s'\n", *argv);
	}

	
	int fd_in = STDIN_FILENO;
	if (input_file != NULL)
	{
		fd_in = open(input_file, O_RDONLY);
		if (fd_in == -1)
			fprintf(stderr, "base64: %s: Cannot open file\n", input_file);
	}

	int fd_out = STDOUT_FILENO;
	if (output_file != NULL)
	{
		int fd_out = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd_out == -1)
			fprintf(stderr, "base64: %s: Cannot open file\n", output_file);
	}

	if (mode == ENCODE)
		base64_encode(fd_in, fd_out);
	//else
		//base64_decode(fd_in, fd_out);

	if (input_file != NULL && close(fd_in))
		fprintf(stderr, "base64: %s: Cannot close file: %s\n", input_file, strerror(errno));
	if (output_file != NULL)
		fprintf(stderr, "base64: %s: Cannot close file: %s\n", output_file, strerror(errno));

	return EXIT_SUCCESS;
}