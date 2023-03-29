include ../common.mk

SOURCE 	:= main.c
OUTPUT 	:= $(OUTPUT_PATH)/sample_c

.phony: all clean

all: $(OUTPUT)

$(OUTPUT): $(SOURCE)
	@$(CC) -o $@ $^ $(C_FLAGS) $(LINK) $(INCLUDE)

clean:
	@rm -rf $(OUTPUT) $(OBJDUMP)
