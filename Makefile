NAME		= ft_ssl

CC			= gcc
CFLAGS		= -Wall -Wextra -Werror -Iinclude
RM			= rm -f
MKDIR		= mkdir -p
VALGRIND	= valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes -q

SRCDIR		= src
OBJDIR		= obj
INCDIR		= include
LIBDIR		= lib

SRC			= $(SRCDIR)/ft_ssl.c \
			  $(SRCDIR)/utils.c \
			  $(SRCDIR)/message_digest/message_digest.c \
			  $(SRCDIR)/message_digest/md5.c \
			  $(SRCDIR)/message_digest/sha256.c \
			  $(SRCDIR)/message_digest/sha512.c \
			  $(SRCDIR)/message_digest/whirlpool.c \
			  $(SRCDIR)/cipher/cipher.c 
OBJ			= $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRC))
DEP			= $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.d,$(SRC))

all: $(NAME)

-include $(DEP)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@$(MKDIR) $(OBJDIR) $(OBJDIR)/message_digest $(OBJDIR)/cipher
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

$(NAME): $(OBJ)
	$(CC) $(OBJ) -o $@ -lm

clean:
	@echo "Removing object files..."
	@$(RM) -r $(OBJDIR)

fclean: clean
	@echo "Removing executable..."
	@$(RM) $(NAME)

re: fclean all

.PHONY: all clean fclean re