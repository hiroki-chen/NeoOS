include ../common.mk

# Add more test suites if needed.
FS_TEST			?= fs.c
MALLOC_TEST		?= malloc.c
DYLIB_TEST		?= dylib.c
DYLIB_DEPDENDEE		?= dylib_dependee.c
FS_OBJ			?= $(OUTPUT_PATH)/fs
MALLOC_OBJ		?= $(OUTPUT_PATH)/malloc
DYLIB_OBJ		?= $(OUTPUT_PATH)/../lib/libtest.so
DYLIB_DEPDENDEE_OBJ	?= $(OUTPUT_PATH)/dylib_dependee

.phony: all clean

all: $(FS_OBJ) $(MALLOC_OBJ) $(DYLIB_OBJ) $(DYLIB_DEPDENDEE_OBJ)

$(FS_OBJ): $(FS_TEST)
	@$(CC) -o $@ $^ $(C_FLAGS) $(LINK) $(INCLUDE)

$(MALLOC_OBJ): $(MALLOC_TEST)
	@$(CC) -o $@ $^ $(C_FLAGS) $(LINK) $(INCLUDE)

$(DYLIB_OBJ): $(DYLIB_TEST)
	$(CC) -o $@ $^ $(C_SHARED_FLAGS) -fPIC $(INCLUDE)

$(DYLIB_DEPDENDEE_OBJ): $(DYLIB_OBJ) $(DYLIB_DEPDENDEE)
	@$(CC) -o $@ $(DYLIB_DEPDENDEE) $(C_COMMON_FLAGS) -no-pie -L$(OUTPUT_PATH)/../lib -ltest $(LINK)

clean:
	@echo "Nothing to do"
