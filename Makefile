CC=gcc
CFLAGS=-Werror -Wextra -Wall

NAME=ft_malcolm

SRC=$(addprefix src/, main.c)
OBJ=$(SRC:.c=.o)

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
