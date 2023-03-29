MUSL_LIB_PATH 	?= /usr/lib/x86_64-linux-musl
MUSL_INC_PATH	?= /usr/include/x86_64-linux-musl
OUTPUT_PATH	?= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))../test/bin
INCLUDE		?= -I$(MUSL_INC_PATH)
LINK		?= -L$(MUSL_LIB_PATH) \
			$(MUSL_LIB_PATH)/crt1.o \
			$(MUSL_LIB_PATH)/crti.o \
			$(MUSL_LIB_PATH)/crtn.o \
			-lc

CC 		?= musl-gcc
C_FLAGS 	?= -static -nostdinc -nostdlib -m64
