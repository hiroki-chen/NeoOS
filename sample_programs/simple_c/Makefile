include ../common.mk

SOURCE 	:= main.c
OUTPUT 	:= $(OUTPUT_PATH)/sample_c
OBJDUMP	:= out.S

.phony: all clean

all: $(OUTPUT) $(OBJDUMP)

$(OUTPUT): $(SOURCE)
	@$(CC) -o $@ $^ $(C_FLAGS) $(LINK) $(INCLUDE)
	@objdump -D $(OUTPUT) -M intel > $(OBJDUMP)

clean:
	@rm -rf $(OUTPUT) $(OBJDUMP)
