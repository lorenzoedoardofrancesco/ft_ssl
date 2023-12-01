///////
// A DELETE
#include <stdio.h>
#include <string.h>
////

#pragma once

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

#include "message_digest.h"
#include "cipher.h"

/*
 /\\\\\\\\\\\       /\\\\\\\\\\\    /\\\
/\\\/////////\\\   /\\\/////////\\\ \/\\\
\//\\\      \///   \//\\\      \///  \/\\\
  \////\\\           \////\\\         \/\\\
      \////\\\           \////\\\      \/\\\
          \////\\\           \////\\\   \/\\\
    /\\\      \//\\\   /\\\      \//\\\  \/\\\
    \///\\\\\\\\\\\/   \///\\\\\\\\\\\/   \/\\\\\\\\\\\\\\\
       \///////////       \///////////     \/////////////*/

#define HEX_CHARS "0123456789abcdef"
// #define HELP_MESSAGE "help:\n\nMessage Digest commands (see the `dgst' command for more details)\nmd5               sha224            sha256            sha384\nsha512            sha512-224        sha512-256        whirlpool\n"
#define HELP_MESSAGE "help:\n\nMessage Digest commands (see the `dgst' command for more details)\nmd5               sha224            sha256            sha384\nsha512            sha512-224        sha512-256        whirlpool\n"
//#define INVALID_COMMAND(command) "Invalid command '" command "'; type \"help\" for a list.\n"

typedef struct
{
	char *command;
	int (*function)(char *, char **);
} command_map;



int print_error(const char *message);


// utils.c
size_t strlen(const char *s);
void *ft_memcpy(void *dest, const void *src, size_t n);
void ft_memset(void *dest, int c, size_t len);
void error(int ret);