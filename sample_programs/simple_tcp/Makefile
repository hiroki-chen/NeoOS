include ../common.mk

SERVER_SOURCE := ./server.c
CLIENT_SOURCE := ./client.c
SERVER_OUTPUT := $(OUTPUT_PATH)/server
CLIENT_OUTPUT := $(OUTPUT_PATH)/client

.phony: all clean

all: $(SERVER_OUTPUT) $(CLIENT_OUTPUT)

$(CLIENT_OUTPUT): $(CLIENT_SOURCE)
	@$(CC) -o $@ $^ $(C_FLAGS) $(LINK) $(INCLUDE)

$(SERVER_OUTPUT): $(SERVER_SOURCE)
	@$(CC) -o $@ $^ $(C_FLAGS) $(LINK) $(INCLUDE)

clean:
	@rm -rf $(SERVER_OUTPUT) $(CLIENT_OUTPUT)
