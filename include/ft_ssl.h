#pragma once

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "message_digest.h"

#define HELP_MESSAGE                                                      \
    "help:\n\n"                                                           \
    "Message Digest commands (see the `dgst` command for more details)\n" \
    "md5               sha224            sha256            sha384\n"      \
    "sha512            sha512-224        sha512-256        whirlpool\n"

typedef struct
{
    char* command;
    int (*function)(char*, char**);
} command_map;


// utils.c
void print(const char* message);
void error(int ret);