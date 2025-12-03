NAME		= chunknet
CC			= cc
CFLAGS		= -Wall -Wextra -Werror -std=c99
SRC_DIR		= src
OBJ_DIR		= obj
SRCS		= $(shell find $(SRC_DIR) -name '*.c')
OBJS		= $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

GREEN		= \033[0;32m
RESET		= \033[0m

all: $(NAME)

$(NAME): $(OBJS)
	@$(CC) $(CFLAGS) $(OBJS) -o $(NAME) -I${SRC_DIR}
	@echo "$(GREEN)$(NAME) built successfully$(RESET)"

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "Compiled $<"

clean:
	@rm -rf $(OBJ_DIR)
	@echo "Object files cleaned"

fclean: clean
	@rm -f $(NAME)
	@echo "$(NAME) removed"

re: fclean all

# Tests
TEST_DIR	= test
TEST_SRCS	= $(shell find $(TEST_DIR) -name '*.c')
CLI_SRC		= $(SRC_DIR)/cli/parse.c
COMMON_SRC	= $(SRC_DIR)/common/dbgprintf.c

test: test_parse_receive
	@./test_parse_receive
	@rm -f test_parse_receive

test_parse_receive: $(TEST_DIR)/test_parse_receive.c $(CLI_SRC) $(COMMON_SRC)
	@$(CC) $(CFLAGS) -I$(SRC_DIR) $^ -o $@
	@echo "$(GREEN)Running parse_receive tests...$(RESET)"

.PHONY: all clean fclean re test
