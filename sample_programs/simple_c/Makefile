SOURCE 	:= main.c
OUTPUT 	:= test

CC 	?= musl-gcc
C_FLAGS ?= -nostdlib -fno-pic -no-pie

.phony: all clean

all: $(OUTPUT)

$(OUTPUT): $(SOURCE)
	@$(CC) -o $@ $^ $(C_FLAGS)

clean:
	@rm $(OUTPUT)
