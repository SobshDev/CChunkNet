NAME		= chunknet
CC			= cc
CFLAGS		= -Wall -Wextra -Werror -std=c99
SRC_DIR		= src
OBJ_DIR		= obj
SRCS		= $(shell find $(SRC_DIR) -name '*.c')
OBJS		= $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

GREEN		= \033[0;32m
RESET		= \033[0m

# Detect libsodium: try pkg-config first, then common paths
SODIUM_CFLAGS := $(shell pkg-config --cflags libsodium 2>/dev/null)
SODIUM_LIBS := $(shell pkg-config --libs libsodium 2>/dev/null)
ifeq ($(SODIUM_LIBS),)
    ifneq ($(wildcard /opt/homebrew/lib/libsodium.*),)
        SODIUM_CFLAGS := -I/opt/homebrew/include
        SODIUM_LIBS := -L/opt/homebrew/lib -lsodium
    else ifneq ($(wildcard /usr/local/lib/libsodium.*),)
        SODIUM_CFLAGS := -I/usr/local/include
        SODIUM_LIBS := -L/usr/local/lib -lsodium
    else
        SODIUM_LIBS := -lsodium
    endif
endif

all: $(NAME)

$(NAME): $(OBJS)
	@$(CC) $(CFLAGS) $(OBJS) -o $(NAME) -I${SRC_DIR} $(SODIUM_LIBS)
	@echo "$(GREEN)$(NAME) built successfully$(RESET)"

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) $(SODIUM_CFLAGS) -c $< -o $@
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

PROTOCOL_SRC = $(SRC_DIR)/protocol/message.c
NETWORK_SRC = $(SRC_DIR)/network/socket.c
CRYPTO_SRC = $(SRC_DIR)/crypto/crypto.c

test: test_parse_receive test_parse_send test_message test_socket test_crypto

test_parse_receive: $(TEST_DIR)/test_parse_receive.c $(CLI_SRC) $(COMMON_SRC)
	@$(CC) $(CFLAGS) -I$(SRC_DIR) $^ -o $@
	@echo "$(GREEN)Running parse_receive tests...$(RESET)"
	@./test_parse_receive
	@rm -f test_parse_receive

test_parse_send: $(TEST_DIR)/test_parse_send.c $(CLI_SRC) $(COMMON_SRC)
	@$(CC) $(CFLAGS) -I$(SRC_DIR) $^ -o $@
	@echo "$(GREEN)Running parse_send tests...$(RESET)"
	@./test_parse_send
	@rm -f test_parse_send

test_message: $(TEST_DIR)/test_message.c $(PROTOCOL_SRC)
	@$(CC) $(CFLAGS) -I$(SRC_DIR) $^ -o $@
	@echo "$(GREEN)Running message tests...$(RESET)"
	@./test_message
	@rm -f test_message

test_socket: $(TEST_DIR)/test_socket.c $(NETWORK_SRC)
	@$(CC) $(CFLAGS) -I$(SRC_DIR) $^ -o $@
	@echo "$(GREEN)Running socket tests...$(RESET)"
	@./test_socket
	@rm -f test_socket

test_crypto: $(TEST_DIR)/test_crypto.c $(CRYPTO_SRC)
	@$(CC) $(CFLAGS) -I$(SRC_DIR) $(SODIUM_CFLAGS) $^ -o $@ $(SODIUM_LIBS)
	@echo "$(GREEN)Running crypto tests...$(RESET)"
	@./test_crypto
	@rm -f test_crypto

.PHONY: all clean fclean re test test_parse_receive test_parse_send test_message test_socket test_crypto
