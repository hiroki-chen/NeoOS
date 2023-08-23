UNAME		:= $(shell uname)

ifeq ($(UNAME), Darwin)
	MUSL_LIB_PATH 	:= /usr/local/lib/x86_64-linux-musl
	MUSL_INC_PATH	:= /usr/local/include/x86_64-linux-musl
else
	MUSL_LIB_PATH 	:= /usr/lib/x86_64-linux-musl
	MUSL_INC_PATH	:= /usr/include/x86_64-linux-musl
endif

OUTPUT_PATH	?= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))../test/bin
INCLUDE		?= -I$(MUSL_INC_PATH)
LINK		?= -L$(MUSL_LIB_PATH) \
			$(MUSL_LIB_PATH)/crt1.o \
			$(MUSL_LIB_PATH)/crti.o \
			$(MUSL_LIB_PATH)/crtn.o \
			-lc

# On MacOS, clang will override this to `cc`, so we use `:=`.
CC 		:= musl-gcc
C_COMMON_FLAGS	?= -nostdinc -nostdlib -m64
C_FLAGS 	?= $(C_COMMON_FLAGS) -static
C_SHARED_FLAGS	?= $(C_COMMON_FLAGS) -shared
