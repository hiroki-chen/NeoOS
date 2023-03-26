SOURCE 	:= main.c
OUTPUT 	:= test
OBJDUMP	:= out.S

MUSL_LIB_PATH 	?= /usr/lib/x86_64-linux-musl
MUSL_INC_PATH	?= /usr/include/x86_64-linux-musl
INCLUDE		?= -I$(MUSL_INC_PATH)
LINK		?= -L$(MUSL_LIB_PATH) \
			$(MUSL_LIB_PATH)/crt1.o \
			$(MUSL_LIB_PATH)/crti.o \
			$(MUSL_LIB_PATH)/crtn.o \
			-lc

CC 		?= musl-gcc
C_FLAGS 	?= -static -nostdinc -nostdlib -m64

# bug: __fwritex @ 0x4018e5: jmp rax --> rax = 0 --> Instruction fetch!!
.phony: all clean

all: $(OUTPUT) $(OBJDUMP)

$(OUTPUT): $(SOURCE)
	@$(CC) -o $@ $^ $(C_FLAGS) $(LINK) $(INCLUDE)
	@objdump -D $(OUTPUT) -M intel > $(OBJDUMP)

clean:
	@rm -rf $(OUTPUT) $(OBJDUMP)
