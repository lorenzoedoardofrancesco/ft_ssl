NAME        = ft_ssl

CC          = gcc
CFLAGS      = -O3 -march=native -Wall -Wextra -Werror -Iinclude
RM          = rm -f
MKDIR       = mkdir -p
VALGRIND    = valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes -q

SRCDIR      = src
OBJDIR      = obj
INCDIR      = include
LIBDIR      = lib

SRC         = $(SRCDIR)/ft_ssl.c \
              $(SRCDIR)/utils.c \
              $(SRCDIR)/message_digest/message_digest.c \
              $(SRCDIR)/message_digest/message_digest_utils.c \
              $(SRCDIR)/message_digest/algorithms.c \
              $(SRCDIR)/message_digest/algorithms/md5.c \
              $(SRCDIR)/message_digest/algorithms/sha256.c \
              $(SRCDIR)/message_digest/algorithms/sha512.c \
              $(SRCDIR)/message_digest/algorithms/whirlpool.c

OBJ         = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRC))
DEP         = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.d,$(SRC))

all: $(NAME)

-include $(DEP)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(MKDIR) $(OBJDIR) $(OBJDIR)/message_digest $(OBJDIR)/message_digest/algorithms $(OBJDIR)/cipher
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

$(NAME): $(OBJ)
	$(CC) $(OBJ) -o $@

clean:
	@echo "Removing object files..."
	@$(RM) -r $(OBJDIR)

fclean: clean
	@echo "Removing executable..."
	@$(RM) $(NAME)

re: fclean all

.PHONY: all clean fclean re
