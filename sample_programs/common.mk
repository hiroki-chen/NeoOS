MUSL_LIB_PATH 	?= /usr/local/lib/x86_64-linux-musl
MUSL_INC_PATH	?= /usr/local/include/x86_64-linux-musl
OUTPUT_PATH	?= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))../test/bin
INCLUDE		?= -I$(MUSL_INC_PATH)
LINK		?= -L$(MUSL_LIB_PATH) \
			$(MUSL_LIB_PATH)/crt1.o \
			$(MUSL_LIB_PATH)/crti.o \
			$(MUSL_LIB_PATH)/crtn.o \
			-lc

# On MacOS, clang will override this to `cc`, so we use `:=`.
CC 		:= musl-gcc
C_FLAGS 	?= -static -nostdinc -nostdlib -m64
