SOURCE 	:= main.c
OUTPUT 	:= test
OBJDUMP	:= out.S

MUSL_LIB_PATH 	?= /home/chb/.local/musl/lib
MUSL_INC_PATH	?= /home/chb/.local/musl/include
INCLUDE		?= -I$(MUSL_INC_PATH)
LINK		?= -L$(MUSL_LIB_PATH) \
			$(MUSL_LIB_PATH)/crt1.o \
			$(MUSL_LIB_PATH)/crti.o \
			$(MUSL_LIB_PATH)/crtn.o \
			-lc

CC 		?= $(HOME)/.local/musl/bin/musl-gcc
C_FLAGS 	?= -static -nostdinc -nostdlib -m64

# bug: __fwritex @ 0x4018e5: jmp rax --> rax = 0 --> Instruction fetch!!
.phony: all clean

all: $(OUTPUT) $(OBJDUMP)

$(OUTPUT): $(SOURCE)
	@$(CC) -o $@ $^ $(C_FLAGS) $(LINK) $(INCLUDE)
	@objdump -D $(OUTPUT) -M intel > $(OBJDUMP)

clean:
	@rm $(OUTPUT) $(OBJDUMP)
